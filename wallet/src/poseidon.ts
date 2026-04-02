/**
 * Poseidon hash implementation for browser.
 *
 * This implementation MUST produce identical results to the Rust implementation.
 * It uses circomlibjs which provides Poseidon for the BN128 and BLS12-381 curves.
 *
 * Domain separation constants match Rust:
 * - DOMAIN_NOTE_COMMITMENT = 1
 * - DOMAIN_NULLIFIER = 3
 * - DOMAIN_MERKLE_NODE = 5
 */

import { buildPoseidon, type Poseidon } from 'circomlibjs';

// Domain separation constants (must match Rust)
export const DOMAIN_NOTE_COMMITMENT = 1n;
export const DOMAIN_VALUE_COMMITMENT_HASH = 2n;
export const DOMAIN_NULLIFIER = 3n;
export const DOMAIN_MERKLE_EMPTY = 4n;
export const DOMAIN_MERKLE_NODE = 5n;

// Singleton Poseidon instance
let poseidonInstance: Poseidon | null = null;

/**
 * Initialize the Poseidon hash function.
 * Must be called before using any hash functions.
 */
export async function initPoseidon(): Promise<void> {
  if (poseidonInstance === null) {
    poseidonInstance = await buildPoseidon();
  }
}

/**
 * Get the Poseidon instance, throwing if not initialized.
 */
function getPoseidon(): Poseidon {
  if (poseidonInstance === null) {
    throw new Error('Poseidon not initialized. Call initPoseidon() first.');
  }
  return poseidonInstance;
}

/**
 * Convert a bigint to a 32-byte Uint8Array (little-endian).
 */
export function bigintToBytes32(n: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let temp = n;
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(temp & 0xFFn);
    temp >>= 8n;
  }
  return bytes;
}

/**
 * Convert a 32-byte Uint8Array to a bigint (little-endian).
 */
export function bytes32ToBigint(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/**
 * Hash multiple field elements using Poseidon with domain separation.
 *
 * @param domain - Domain separation constant
 * @param inputs - Field elements to hash
 * @returns Single field element as bigint
 */
export function poseidonHash(domain: bigint, inputs: bigint[]): bigint {
  const poseidon = getPoseidon();

  // Prepend domain to inputs
  const allInputs = [domain, ...inputs];

  // Hash and return as bigint
  const result = poseidon(allInputs);
  return poseidon.F.toObject(result);
}

/**
 * Hash two field elements (common for Merkle tree nodes).
 */
export function poseidonHash2(domain: bigint, left: bigint, right: bigint): bigint {
  return poseidonHash(domain, [left, right]);
}

/**
 * Compute a note commitment.
 * cm = Poseidon(DOMAIN_NOTE_COMMITMENT, value, pkHash, randomness)
 *
 * @param value - Note value
 * @param pkHash - Recipient public key hash as field element
 * @param randomness - Note randomness as field element
 */
export function noteCommitment(value: bigint, pkHash: bigint, randomness: bigint): bigint {
  return poseidonHash(DOMAIN_NOTE_COMMITMENT, [value, pkHash, randomness]);
}

/**
 * Derive a nullifier for a note.
 * nf = Poseidon(DOMAIN_NULLIFIER, nk, cm, position)
 *
 * @param nullifierKey - Nullifier key as field element
 * @param commitment - Note commitment as field element
 * @param position - Position in the tree
 */
export function deriveNullifier(nullifierKey: bigint, commitment: bigint, position: bigint): bigint {
  return poseidonHash(DOMAIN_NULLIFIER, [nullifierKey, commitment, position]);
}

/**
 * Compute a Merkle tree node hash.
 * hash = Poseidon(DOMAIN_MERKLE_NODE, left, right)
 */
export function merkleHash(left: bigint, right: bigint): bigint {
  return poseidonHash2(DOMAIN_MERKLE_NODE, left, right);
}

/**
 * Compute the empty leaf hash.
 * hash = Poseidon(DOMAIN_MERKLE_EMPTY, 0)
 */
export function emptyLeafHash(): bigint {
  return poseidonHash(DOMAIN_MERKLE_EMPTY, [0n]);
}

/**
 * Compute Merkle root from a leaf and its authentication path.
 *
 * @param leaf - Leaf value (commitment)
 * @param pathElements - Sibling hashes from leaf to root
 * @param pathIndices - Path directions (0 = left, 1 = right)
 * @returns Computed Merkle root
 */
export function computeMerkleRoot(
  leaf: bigint,
  pathElements: bigint[],
  pathIndices: number[]
): bigint {
  let current = leaf;

  for (let i = 0; i < pathElements.length; i++) {
    const sibling = pathElements[i];
    const isRight = pathIndices[i] === 1;

    if (isRight) {
      // Current is right child, sibling is left
      current = merkleHash(sibling, current);
    } else {
      // Current is left child, sibling is right
      current = merkleHash(current, sibling);
    }
  }

  return current;
}

/**
 * Convert a hex string to a field element (bigint).
 */
export function hexToFieldElement(hex: string): bigint {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
  return bytes32ToBigint(bytes);
}

/**
 * Convert a field element (bigint) to a hex string.
 */
export function fieldElementToHex(fe: bigint): string {
  const bytes = bigintToBytes32(fe);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
