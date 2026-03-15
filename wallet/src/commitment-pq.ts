/**
 * Hash-based commitments for post-quantum security.
 *
 * This module provides quantum-resistant commitment schemes using
 * Poseidon hash over the Goldilocks field, replacing the BN254-based
 * Pedersen commitments used in V1.
 *
 * ## IMPORTANT: WASM Integration
 *
 * This module uses Plonky2's native Poseidon implementation via WASM
 * to ensure commitments and nullifiers match exactly what the circuit computes.
 * You MUST call `initPQCrypto()` before using these functions.
 *
 * ## Security Model
 *
 * Hash-based commitments provide:
 * - **Hiding**: Cannot determine committed value from commitment (randomness)
 * - **Binding**: Cannot find two values with same commitment (collision resistance)
 *
 * Unlike Pedersen commitments, these are NOT homomorphic.
 * Balance verification happens inside the STARK proof instead.
 *
 * ## Hash Format
 *
 * To match Plonky2's circuit, all hashes are 4 Goldilocks field elements (256 bits).
 * This is stored as 32 bytes in serialized form.
 */

import { hexToBytes, bytesToHex } from './crypto';
import { valueCommitmentPQ as valueCommitmentPQFallback } from './poseidon-pq';

// WASM module functions - loaded dynamically
let wasmInitialized = false;
let wasmComputeNullifier: ((nk: string, cm: string, pos: string) => string) | null = null;
let wasmComputeNoteCommitment: ((value: string, pk: string, rand: string) => string) | null = null;
let wasmComputeMerkleRoot: ((leaf: string, pathJson: string, indicesJson: string) => string) | null = null;

/**
 * Initialize the PQ crypto module.
 * This loads the Plonky2 WASM module and prepares the Poseidon functions.
 * MUST be called before using any other functions in this module.
 */
export async function initPQCrypto(): Promise<void> {
  if (wasmInitialized) {
    return;
  }

  try {
    // Dynamically import the WASM module
    const wasmModule = await import('tsn-plonky2-wasm');

    // Initialize the WASM module
    await wasmModule.default();

    // Store references to the WASM functions
    wasmComputeNullifier = wasmModule.compute_nullifier_wasm;
    wasmComputeNoteCommitment = wasmModule.compute_note_commitment_wasm;
    wasmComputeMerkleRoot = wasmModule.compute_merkle_root_wasm ?? null;

    // Check WASM version to verify correct module is loaded
    const version = wasmModule.wasm_version?.() ?? 'unknown';
    console.log(`PQ crypto WASM version: ${version}`);
    console.log(`WASM Merkle root function: ${wasmComputeMerkleRoot !== null ? 'available' : 'not available'}`);

    wasmInitialized = true;
    console.log('PQ crypto initialized with WASM Poseidon');
  } catch (e) {
    console.error('Failed to initialize PQ crypto:', e);
    throw new Error('PQ crypto initialization failed - WASM module not available');
  }
}

/**
 * Check if PQ crypto is initialized.
 */
export function isPQCryptoInitialized(): boolean {
  return wasmInitialized;
}

/**
 * A hash-based value commitment (post-quantum secure).
 */
export interface ValueCommitmentPQ {
  commitment: Uint8Array;
}

/**
 * A hash-based note commitment (post-quantum secure).
 */
export interface NoteCommitmentPQ {
  commitment: Uint8Array;
}

/**
 * Compute a note commitment using Plonky2's native Poseidon.
 *
 * @param value - The note value
 * @param pkHash - Recipient public key hash (32 bytes)
 * @param randomness - Note randomness (32 bytes)
 * @returns The commitment (32 bytes)
 */
export function commitToNotePQ(
  value: bigint,
  pkHash: Uint8Array,
  randomness: Uint8Array
): Uint8Array {
  if (!wasmInitialized || !wasmComputeNoteCommitment) {
    throw new Error('PQ crypto not initialized - call initPQCrypto() first');
  }
  if (pkHash.length !== 32) {
    throw new Error('pkHash must be 32 bytes');
  }
  if (randomness.length !== 32) {
    throw new Error('Randomness must be 32 bytes');
  }

  const commitmentHex = wasmComputeNoteCommitment(
    value.toString(),
    bytesToHex(pkHash),
    bytesToHex(randomness)
  );
  return hexToBytes(commitmentHex);
}

/**
 * Derive a nullifier for a note (PQ version) using Plonky2's native Poseidon.
 *
 * @param nullifierKey - The nullifier key (32 bytes)
 * @param commitment - The note commitment (32 bytes)
 * @param position - Position in the commitment tree
 * @returns The nullifier (32 bytes)
 */
export function deriveNullifierPQ(
  nullifierKey: Uint8Array,
  commitment: Uint8Array,
  position: bigint
): Uint8Array {
  if (!wasmInitialized || !wasmComputeNullifier) {
    throw new Error('PQ crypto not initialized - call initPQCrypto() first');
  }
  if (nullifierKey.length !== 32) {
    throw new Error('nullifierKey must be 32 bytes');
  }
  if (commitment.length !== 32) {
    throw new Error('commitment must be 32 bytes');
  }

  const nullifierHex = wasmComputeNullifier(
    bytesToHex(nullifierKey),
    bytesToHex(commitment),
    position.toString()
  );
  return hexToBytes(nullifierHex);
}

/**
 * Compute a value commitment using Poseidon hash.
 * NOTE: Value commitments are not currently used in V2 transactions,
 * but this is provided for completeness.
 *
 * @param value - The value to commit to
 * @param randomness - 32 bytes of randomness
 * @returns The commitment (32 bytes)
 */
export function commitToValuePQ(value: bigint, randomness: Uint8Array): Uint8Array {
  // Value commitments use the same structure as note commitments
  // but without the pk_hash. For now, we use the TypeScript implementation
  // since value commitments are not used in V2 proofs.
  return valueCommitmentPQFallback(value, randomness);
}

/**
 * Verify a value commitment.
 *
 * @param commitment - The commitment to verify
 * @param value - The claimed value
 * @param randomness - The claimed randomness
 * @returns True if the commitment is valid
 */
export function verifyValueCommitmentPQ(
  commitment: Uint8Array,
  value: bigint,
  randomness: Uint8Array
): boolean {
  const expected = commitToValuePQ(value, randomness);
  return arraysEqual(commitment, expected);
}

/**
 * Verify a note commitment.
 *
 * @param commitment - The commitment to verify
 * @param value - The claimed value
 * @param pkHash - The claimed recipient pk hash
 * @param randomness - The claimed randomness
 * @returns True if the commitment is valid
 */
export function verifyNoteCommitmentPQ(
  commitment: Uint8Array,
  value: bigint,
  pkHash: Uint8Array,
  randomness: Uint8Array
): boolean {
  const expected = commitToNotePQ(value, pkHash, randomness);
  return arraysEqual(commitment, expected);
}

/**
 * Generate random 32 bytes for commitment randomness.
 */
export function generateRandomnessPQ(): Uint8Array {
  const randomness = new Uint8Array(32);
  crypto.getRandomValues(randomness);
  return randomness;
}

/**
 * Convenience function: commit to value and return hex string.
 */
export function commitToValuePQHex(value: bigint, randomnessHex: string): string {
  const randomness = hexToBytes(randomnessHex);
  const commitment = commitToValuePQ(value, randomness);
  return bytesToHex(commitment);
}

/**
 * Convenience function: commit to note and return hex string.
 */
export function commitToNotePQHex(
  value: bigint,
  pkHashHex: string,
  randomnessHex: string
): string {
  const pkHash = hexToBytes(pkHashHex);
  const randomness = hexToBytes(randomnessHex);
  const commitment = commitToNotePQ(value, pkHash, randomness);
  return bytesToHex(commitment);
}

/**
 * Convenience function: derive nullifier and return hex string.
 */
export function deriveNullifierPQHex(
  nullifierKeyHex: string,
  commitmentHex: string,
  position: bigint
): string {
  const nullifierKey = hexToBytes(nullifierKeyHex);
  const commitment = hexToBytes(commitmentHex);
  const nullifier = deriveNullifierPQ(nullifierKey, commitment, position);
  return bytesToHex(nullifier);
}

/**
 * Compute Merkle root from commitment and path using WASM.
 * This is useful for debugging Merkle path issues.
 *
 * @param commitment - The commitment (leaf) as hex string
 * @param path - Array of sibling hashes as hex strings
 * @param indices - Array of path indices (0 = left, 1 = right)
 * @returns The computed Merkle root as hex string
 */
export function computeMerkleRootPQHex(
  commitmentHex: string,
  path: string[],
  indices: number[]
): string {
  if (!wasmInitialized || !wasmComputeMerkleRoot) {
    throw new Error('PQ crypto not initialized or Merkle root function not available');
  }

  const pathJson = JSON.stringify(path);
  const indicesJson = JSON.stringify(indices);

  return wasmComputeMerkleRoot(commitmentHex, pathJson, indicesJson);
}

/**
 * Debug function: Compare Merkle root computation between WASM and server.
 * Logs detailed information about any differences.
 */
export async function debugCompareMerkleRoot(
  commitmentHex: string,
  path: string[],
  indices: number[],
  serverUrl: string = ''
): Promise<{wasmRoot: string, serverRoot?: string, match: boolean}> {
  if (!wasmInitialized || !wasmComputeMerkleRoot) {
    throw new Error('PQ crypto not initialized');
  }

  // Compute using WASM
  const wasmRoot = computeMerkleRootPQHex(commitmentHex, path, indices);
  console.log('[Debug] WASM computed root:', wasmRoot);

  // Try to compute using server debug endpoint
  let serverRoot: string | undefined;
  try {
    const response = await fetch(`${serverUrl}/debug/verify-path`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        commitment: commitmentHex,
        path,
        indices,
      }),
    });

    if (response.ok) {
      const data = await response.json();
      serverRoot = data.computed_root;
      console.log('[Debug] Server computed root:', serverRoot);
      console.log('[Debug] Server debug info:', JSON.stringify(data.debug, null, 2));
    } else {
      console.log('[Debug] Server verify-path failed:', response.status);
    }
  } catch (e) {
    console.log('[Debug] Could not reach server for comparison');
  }

  const match = serverRoot === wasmRoot;
  if (!match && serverRoot) {
    console.error('[Debug] MISMATCH! WASM and server computed different roots');
  } else if (match) {
    console.log('[Debug] MATCH! WASM and server roots are identical');
  }

  return { wasmRoot, serverRoot, match };
}

/**
 * Helper function to compare two Uint8Arrays.
 */
function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
