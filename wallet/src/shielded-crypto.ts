/**
 * Shielded cryptographic operations for note encryption/decryption.
 *
 * These functions match the Rust implementation exactly, using the same
 * domain separators and algorithms:
 * - Poseidon hash for note commitments and nullifiers (ZK-SNARK friendly)
 * - BLAKE2s-256 for key derivation
 * - ChaCha20-Poly1305 for note encryption
 */

import { blake2s } from '@noble/hashes/blake2.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hexToBytes } from './crypto';
import {
  noteCommitment as poseidonNoteCommitment,
  deriveNullifier as poseidonDeriveNullifier,
  bigintToBytes32,
  bytes32ToBigint,
} from './poseidon';

// Note structure: 8 bytes value + 32 bytes pk_hash + 32 bytes randomness = 72 bytes
// Ciphertext: 72 + 16 (poly1305 tag) = 88 bytes

/**
 * Derive a viewing key from the wallet's secret key material.
 * ViewingKey = BLAKE2s("TSN_ViewingKey" || secretBytes)
 */
export function deriveViewingKey(secretBytes: Uint8Array): Uint8Array {
  const input = new Uint8Array([
    ...new TextEncoder().encode('TSN_ViewingKey'),
    ...secretBytes,
  ]);
  return blake2s(input, { dkLen: 32 });
}

/**
 * Derive a nullifier key from the wallet's secret key material.
 * NullifierKey = BLAKE2s("TSN_NullifierKey" || secretBytes)
 *
 * Note: The Rust implementation converts this to a field element (Fr),
 * but for nullifier derivation we use the raw 32 bytes.
 */
export function deriveNullifierKey(secretBytes: Uint8Array): Uint8Array {
  const input = new Uint8Array([
    ...new TextEncoder().encode('TSN_NullifierKey'),
    ...secretBytes,
  ]);
  return blake2s(input, { dkLen: 32 });
}

/**
 * Compute the public key hash for receiving notes.
 * PkHash = BLAKE2s("TSN_PkHash" || publicKey)
 */
export function computePkHash(publicKey: Uint8Array): Uint8Array {
  const input = new Uint8Array([
    ...new TextEncoder().encode('TSN_PkHash'),
    ...publicKey,
  ]);
  return blake2s(input, { dkLen: 32 });
}

/**
 * Derive the encryption key for note decryption/encryption.
 * EncKey = BLAKE2s("TSN_NoteEncryption" || viewingSecret || ephemeralPk)
 */
export function deriveEncryptionKey(viewingSecret: Uint8Array, ephemeralPk: Uint8Array): Uint8Array {
  const input = new Uint8Array([
    ...new TextEncoder().encode('TSN_NoteEncryption'),
    ...viewingSecret,
    ...ephemeralPk,
  ]);
  return blake2s(input, { dkLen: 32 });
}

/**
 * Compute a note commitment using Poseidon hash (ZK-SNARK friendly).
 * cm = Poseidon(DOMAIN_NOTE_COMMITMENT, value, pkHash, randomness)
 *
 * This must match the Rust and Circom implementations exactly.
 */
export function computeNoteCommitment(value: bigint, pkHash: Uint8Array, randomness: Uint8Array): Uint8Array {
  // Convert inputs to field elements
  const pkHashFe = bytes32ToBigint(pkHash);
  const randomnessFe = bytes32ToBigint(randomness);

  // Compute Poseidon hash
  const commitmentFe = poseidonNoteCommitment(value, pkHashFe, randomnessFe);

  // Convert back to bytes
  return bigintToBytes32(commitmentFe);
}

/**
 * Derive a nullifier for a note using Poseidon hash (ZK-SNARK friendly).
 * nf = Poseidon(DOMAIN_NULLIFIER, nullifierKey, commitment, position)
 *
 * This must match the Rust and Circom implementations exactly.
 */
export function deriveNullifier(nullifierKey: Uint8Array, commitment: Uint8Array, position: bigint): Uint8Array {
  // Convert inputs to field elements
  const nullifierKeyFe = bytes32ToBigint(nullifierKey);
  const commitmentFe = bytes32ToBigint(commitment);

  // Compute Poseidon hash
  const nullifierFe = poseidonDeriveNullifier(nullifierKeyFe, commitmentFe, position);

  // Convert back to bytes
  return bigintToBytes32(nullifierFe);
}

/**
 * Derive an ephemeral "public key" from random bytes.
 * Used for note encryption.
 * EphemeralPk = BLAKE2s("TSN_EphemeralPK" || ephemeralSecret)
 */
export function deriveEphemeralPk(ephemeralSecret: Uint8Array): Uint8Array {
  const input = new Uint8Array([
    ...new TextEncoder().encode('TSN_EphemeralPK'),
    ...ephemeralSecret,
  ]);
  return blake2s(input, { dkLen: 32 });
}

/**
 * Serialized note structure.
 */
export interface SerializedNote {
  value: bigint;
  recipientPkHash: Uint8Array;
  randomness: Uint8Array;
}

/**
 * Serialize a note to bytes.
 * Format: value (8 bytes LE) || pk_hash (32 bytes) || randomness (32 bytes)
 */
export function serializeNote(value: bigint, pkHash: Uint8Array, randomness: Uint8Array): Uint8Array {
  const bytes = new Uint8Array(72);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(0, value, true);
  bytes.set(pkHash, 8);
  bytes.set(randomness, 40);
  return bytes;
}

/**
 * Deserialize a note from bytes.
 */
export function deserializeNote(bytes: Uint8Array): SerializedNote {
  if (bytes.length < 72) {
    throw new Error('Note bytes too short');
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const value = view.getBigUint64(0, true);
  const recipientPkHash = bytes.slice(8, 40);
  const randomness = bytes.slice(40, 72);
  return { value, recipientPkHash, randomness };
}

/**
 * Encrypted note structure.
 */
export interface EncryptedNote {
  ciphertext: Uint8Array;
  ephemeralPk: Uint8Array;
}

/**
 * Encrypt a note so only the recipient can decrypt it.
 * Uses ChaCha20-Poly1305 with:
 * - Key: derived from recipient's pk_hash and ephemeral public key
 * - Nonce: first 12 bytes of ephemeral public key
 *
 * The recipient can decrypt because they know their own pk_hash
 * (derived from their public key).
 */
export function encryptNote(
  value: bigint,
  pkHash: Uint8Array,
  randomness: Uint8Array,
  _viewingKey: Uint8Array // deprecated - use pkHash for encryption
): EncryptedNote {
  // Generate ephemeral randomness
  const ephemeralSecret = new Uint8Array(32);
  crypto.getRandomValues(ephemeralSecret);

  // Derive ephemeral public key
  const ephemeralPk = deriveEphemeralPk(ephemeralSecret);

  // Derive encryption key using RECIPIENT'S pk_hash (not sender's viewing key)
  // This allows the recipient to decrypt using their own pk_hash
  const encryptionKey = deriveEncryptionKey(pkHash, ephemeralPk);

  // Use first 12 bytes of ephemeral_pk as nonce
  const nonce = ephemeralPk.slice(0, 12);

  // Serialize the note
  const plaintext = serializeNote(value, pkHash, randomness);

  // Encrypt using ChaCha20-Poly1305
  const cipher = chacha20poly1305(encryptionKey, nonce);
  const ciphertext = cipher.encrypt(plaintext);

  return { ciphertext, ephemeralPk };
}

/**
 * Decrypt an encrypted note.
 * Returns null if decryption fails (note wasn't for us).
 */
export function decryptNote(
  encrypted: EncryptedNote,
  viewingKey: Uint8Array
): SerializedNote | null {
  try {
    // Derive encryption key
    const encryptionKey = deriveEncryptionKey(viewingKey, encrypted.ephemeralPk);

    // Use first 12 bytes of ephemeral_pk as nonce
    if (encrypted.ephemeralPk.length < 12) {
      return null;
    }
    const nonce = encrypted.ephemeralPk.slice(0, 12);

    // Decrypt using ChaCha20-Poly1305
    const cipher = chacha20poly1305(encryptionKey, nonce);
    const plaintext = cipher.decrypt(encrypted.ciphertext);

    // Deserialize the note
    return deserializeNote(plaintext);
  } catch {
    // Decryption failed - note wasn't for us
    return null;
  }
}

/**
 * Try to decrypt an encrypted note from hex-encoded data.
 */
export function tryDecryptNoteFromHex(
  ciphertextHex: string,
  ephemeralPkHex: string,
  viewingKey: Uint8Array
): SerializedNote | null {
  const encrypted: EncryptedNote = {
    ciphertext: hexToBytes(ciphertextHex),
    ephemeralPk: hexToBytes(ephemeralPkHex),
  };
  return decryptNote(encrypted, viewingKey);
}

/**
 * Generate random 32 bytes for note randomness.
 */
export function generateRandomness(): Uint8Array {
  const randomness = new Uint8Array(32);
  crypto.getRandomValues(randomness);
  return randomness;
}

/**
 * Check if we can decrypt a note (i.e., it's for our viewing key).
 */
export function canDecryptNote(encrypted: EncryptedNote, viewingKey: Uint8Array): boolean {
  return decryptNote(encrypted, viewingKey) !== null;
}

/**
 * Initialize cryptographic primitives.
 * Must be called before using computeNoteCommitment or deriveNullifier.
 */
export { initPoseidon } from './poseidon';

// ============================================================================
// Post-Quantum Exports (V2)
// ============================================================================

// Re-export PQ commitment functions
export {
  commitToValuePQ,
  commitToNotePQ,
  deriveNullifierPQ,
  verifyValueCommitmentPQ,
  verifyNoteCommitmentPQ,
  generateRandomnessPQ,
} from './commitment-pq';

// Re-export PQ Poseidon functions
export {
  poseidonPQHash,
  bytesToGoldilocks,
  goldilocksToBytes,
  noteCommitmentPQ,
  valueCommitmentPQ,
  deriveNullifierPQ as deriveNullifierPQPoseidon,
  merkleHashPQ,
  emptyLeafHashPQ,
  computeMerkleRootPQ,
  GOLDILOCKS_PRIME,
  DOMAIN_NOTE_COMMIT_PQ,
  DOMAIN_VALUE_COMMIT_PQ,
  DOMAIN_NULLIFIER_PQ,
  DOMAIN_MERKLE_EMPTY_PQ,
  DOMAIN_MERKLE_NODE_PQ,
} from './poseidon-pq';

// Re-export PQ prover functions
export {
  generateTransactionProofPQ,
  verifyProofPQ,
  serializeProof,
  deserializeProof,
  getProofSize,
  type SpendWitnessPQ,
  type OutputWitnessPQ,
  type TransactionPublicInputs,
  type Plonky2Proof,
  ProofError,
} from './prover-pq';

// Re-export migration functions
export {
  migrateNotesToPQ,
  isV1Note,
  isV2Note,
  estimateMigrationFee,
  getMigrationStats,
  type V1Note,
  type V2Note,
  type MigrationParams,
  type MigrationResult,
  type MigrationTransaction,
} from './migration';
