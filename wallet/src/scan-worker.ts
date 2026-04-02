/**
 * Web Worker for parallel note scanning.
 *
 * This worker handles trial decryption of encrypted outputs to find notes
 * belonging to a wallet. By running multiple workers in parallel, we can
 * significantly speed up the scanning process.
 */

import { blake2s } from '@noble/hashes/blake2.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { buildPoseidon, type Poseidon } from 'circomlibjs';

// Poseidon instance for this worker
let poseidon: Poseidon | null = null;

// Domain constants (must match Rust)
const DOMAIN_NULLIFIER = 3n;

// Message types
interface InitMessage {
  type: 'init';
}

interface ScanMessage {
  type: 'scan';
  outputs: ScanOutput[];
  pkHash: string;       // hex
  nullifierKey: string; // hex
}

interface ScanOutput {
  ciphertext: string;      // hex
  ephemeral_pk: string;    // hex
  note_commitment: string; // hex
  position: number;
  block_height: number;
}

interface DecryptedNote {
  value: string;  // bigint as string
  recipientPkHash: string;
  randomness: string;
  commitment: string;
  position: string;  // bigint as string
  blockHeight: number;
  nullifier: string;
}

type WorkerMessage = InitMessage | ScanMessage;

// Utility functions
function hexToBytes(hex: string): Uint8Array {
  if (hex.startsWith('0x')) hex = hex.slice(2);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function bigintToBytes32(n: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let temp = n;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  return bytes;
}

function bytes32ToBigint(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < 32; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/**
 * Derive shared secret using ECDH-like construction.
 */
function deriveSharedSecret(ephemeralPk: Uint8Array, pkHash: Uint8Array): Uint8Array {
  // Hash ephemeral public key with pk_hash to derive shared secret
  const input = new Uint8Array([
    ...new TextEncoder().encode('TSN_NoteKey'),
    ...ephemeralPk,
    ...pkHash,
  ]);
  return blake2s(input, { dkLen: 32 });
}

/**
 * Try to decrypt note data.
 */
function tryDecrypt(
  ciphertextHex: string,
  ephemeralPkHex: string,
  pkHash: Uint8Array
): { value: bigint; recipientPkHash: Uint8Array; randomness: Uint8Array } | null {
  try {
    const ciphertext = hexToBytes(ciphertextHex);
    const ephemeralPk = hexToBytes(ephemeralPkHex);

    // Derive shared secret
    const sharedSecret = deriveSharedSecret(ephemeralPk, pkHash);

    // ChaCha20-Poly1305 with zero nonce
    const nonce = new Uint8Array(12);
    const cipher = chacha20poly1305(sharedSecret, nonce);

    let plaintext: Uint8Array;
    try {
      plaintext = cipher.decrypt(ciphertext);
    } catch {
      return null; // Decryption failed (not for us)
    }

    // Parse note: 8 bytes value + 32 bytes pk_hash + 32 bytes randomness = 72 bytes
    if (plaintext.length !== 72) {
      return null;
    }

    // Extract value (little-endian u64)
    let value = 0n;
    for (let i = 7; i >= 0; i--) {
      value = (value << 8n) | BigInt(plaintext[i]);
    }

    // Extract pk_hash (32 bytes)
    const recipientPkHash = plaintext.slice(8, 40);

    // Extract randomness (32 bytes)
    const randomness = plaintext.slice(40, 72);

    return { value, recipientPkHash, randomness };
  } catch {
    return null;
  }
}

/**
 * Derive nullifier using Poseidon hash.
 */
function deriveNullifier(
  nullifierKey: Uint8Array,
  commitment: Uint8Array,
  position: bigint
): Uint8Array {
  if (!poseidon) throw new Error('Poseidon not initialized');

  const nkBigint = bytes32ToBigint(nullifierKey);
  const commitBigint = bytes32ToBigint(commitment);

  // Poseidon(domain, nk, commitment, position)
  const hash = poseidon([DOMAIN_NULLIFIER, nkBigint, commitBigint, position]);
  const hashBigint = poseidon.F.toObject(hash) as bigint;

  return bigintToBytes32(hashBigint);
}

/**
 * Process a batch of outputs and return decrypted notes.
 */
function scanOutputs(
  outputs: ScanOutput[],
  pkHashHex: string,
  nullifierKeyHex: string
): DecryptedNote[] {
  const pkHash = hexToBytes(pkHashHex);
  const nullifierKey = hexToBytes(nullifierKeyHex);
  const results: DecryptedNote[] = [];

  for (const output of outputs) {
    // Skip V2-only outputs
    if (!output.note_commitment || output.note_commitment.length === 0) {
      continue;
    }

    const decrypted = tryDecrypt(output.ciphertext, output.ephemeral_pk, pkHash);
    if (!decrypted) continue;

    // Verify recipient
    const recipientHex = bytesToHex(decrypted.recipientPkHash);
    if (recipientHex !== pkHashHex) continue;

    // Derive nullifier
    const commitmentBytes = hexToBytes(output.note_commitment);
    const nullifier = deriveNullifier(nullifierKey, commitmentBytes, BigInt(output.position));

    results.push({
      value: decrypted.value.toString(),
      recipientPkHash: recipientHex,
      randomness: bytesToHex(decrypted.randomness),
      commitment: output.note_commitment,
      position: output.position.toString(),
      blockHeight: output.block_height,
      nullifier: bytesToHex(nullifier),
    });
  }

  return results;
}

// Worker message handler
self.onmessage = async (event: MessageEvent<WorkerMessage>) => {
  const msg = event.data;

  if (msg.type === 'init') {
    try {
      poseidon = await buildPoseidon();
      self.postMessage({ type: 'ready' });
    } catch (error) {
      self.postMessage({ type: 'error', error: String(error) });
    }
  } else if (msg.type === 'scan') {
    try {
      const notes = scanOutputs(msg.outputs, msg.pkHash, msg.nullifierKey);
      self.postMessage({ type: 'result', notes });
    } catch (error) {
      self.postMessage({ type: 'error', error: String(error) });
    }
  }
};
