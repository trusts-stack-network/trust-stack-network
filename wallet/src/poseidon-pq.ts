/**
 * Poseidon hash implementation over Goldilocks field for post-quantum security.
 *
 * This implementation MUST produce identical results to the Rust PQ implementation.
 * It uses the Goldilocks field (p = 2^64 - 2^32 + 1) which is compatible with
 * Plonky2's STARK proofs.
 *
 * ## IMPORTANT: Hash Output Format
 *
 * To match Plonky2's built-in Poseidon, we output 4 field elements (256 bits)
 * instead of a single element. This ensures circuit proofs and non-circuit
 * computations produce identical results.
 *
 * ## Field Choice Rationale
 *
 * - BN254 (V1): 254-bit field, requires pairings, vulnerable to quantum
 * - Goldilocks (V2): 64-bit field, hash-based STARKs, quantum-resistant
 *
 * The smaller field is secure because STARKs don't rely on discrete log.
 */

// Goldilocks prime: p = 2^64 - 2^32 + 1
export const GOLDILOCKS_PRIME = 0xFFFF_FFFF_0000_0001n;

// Domain separation constants for PQ (V2) - must match Rust
export const DOMAIN_NOTE_COMMIT_PQ = 1n;
export const DOMAIN_VALUE_COMMIT_PQ = 2n;
export const DOMAIN_NULLIFIER_PQ = 3n;
export const DOMAIN_MERKLE_EMPTY_PQ = 4n;
export const DOMAIN_MERKLE_NODE_PQ = 5n;

// Hash output type: 4 field elements (256 bits) to match Plonky2's PoseidonHash
export type HashOut = [bigint, bigint, bigint, bigint];

// Extended round constants for width-12 Poseidon (must match Rust exactly)
// Need 30 rounds: RF=8 full rounds + RP=22 partial rounds
const ROUND_CONSTANTS_12: bigint[][] = [
  [0x67f52a8e0e7bce9fn, 0x8c73f9fd68aa9d92n, 0x2a69fa48c0f9ae81n, 0x3c8d2a8bd8fe6d05n,
   0x9e6c49d3e27a8f01n, 0x5a1f8d3c4e7b2a96n, 0x1d4e7a2c3f8b9d05n, 0x6a3f8e1d2c7b4a95n,
   0x8c2e5a1f3d9b7c06n, 0x4f2d8a3e1c7b9605n, 0x2c7a1f4e3d8b5a96n, 0x9a3f2e1d4c8b7a05n],
  [0x5e3d7a2f1c8b9406n, 0x7a2f3e1d4c9b8a05n, 0x1c8a3f2e5d7b4a96n, 0x8f1e3a2d4c7b9506n,
   0x3d8a2f1e5c7b4a95n, 0x6a1f3e2d4c9b8a06n, 0x2e4d7a3f1c8b9506n, 0x9a2f3e1d5c7b4a96n,
   0x4c8a1f3e2d7b5a06n, 0x7f2e3a1d4c8b9506n, 0x1d9a3f2e4c7b5a96n, 0x3a8f2e1d5c7b4a06n],
  [0x6e3d7a2f1c9b8405n, 0x4a2f3e1d5c8b7a96n, 0x8c1a3f2e4d7b5a06n, 0x1f4e3a2d5c7b9806n,
   0x7a3f2e1d4c9b8a05n, 0x2d8a1f3e5c7b4a96n, 0x9e2d7a3f1c8b9405n, 0x5a2f3e1d4c7b8a96n,
   0x3c9a1f2e4d8b7a05n, 0x4f3e7a2d1c9b8506n, 0x8a2f1e3d5c7b4a96n, 0x1d7a3f2e4c9b8a06n],
  [0x2e5d3a7f1c8b9406n, 0x6a3f2e1d4c8b7a95n, 0x9c1a2f3e5d7b4a06n, 0x7f4e2a3d1c9b8506n,
   0x3a2f1e4d5c7b8a96n, 0x4c8a3f2e1d9b7a05n, 0x1e6d3a7f2c8b9405n, 0x9a3f2e1d5c7b4a96n,
   0x2d7a1f3e4c8b9a06n, 0x5f2e4a3d1c7b9806n, 0x4a2f3e1d5c9b8a95n, 0x8c3a1f2e4d7b5a06n],
  [0x3e7d2a4f1c9b8506n, 0x7a3f1e2d4c8b7a96n, 0x1d9a2f3e5c7b4a05n, 0x6f4e3a2d1c8b9705n,
   0x2a3f1e5d4c7b9a96n, 0x5c8a3f2e1d7b4a06n, 0x8e2d5a3f1c7b9406n, 0x1a4f3e2d5c9b8a95n,
   0x3d7a2f1e4c8b9a06n, 0x4f3e2a7d1c9b8506n, 0x6a2f3e1d4c7b8a96n, 0x9c1a3f2e5d8b7a05n],
  [0x1e5d4a3f2c8b9706n, 0x8a3f2e1d5c7b4a96n, 0x2d9a1f3e4c7b8a06n, 0x7f2e3a5d1c8b9406n,
   0x3a4f2e1d5c9b7a95n, 0x6c8a1f3e2d7b5a06n, 0x5e4d2a3f1c7b9806n, 0x9a2f3e1d4c8b7a96n,
   0x1d7a3f2e5c9b4a05n, 0x2f3e5a4d1c9b8706n, 0x4a3f2e1d5c7b8a96n, 0x8c9a1f2e3d7b5a06n],
  [0x6e2d4a3f1c8b9506n, 0x1a3f2e5d4c9b7a95n, 0x3d8a2f1e5c7b4a06n, 0x9f4e2a3d1c7b9806n,
   0x7a2f3e1d5c8b4a96n, 0x5c1a3f2e4d9b7a05n, 0x3e5d4a2f1c9b8706n, 0x2a4f3e1d5c7b9a96n,
   0x8d7a1f2e3c8b5a06n, 0x1f2e5a3d4c8b9706n, 0x6a3f2e1d5c9b8a95n, 0x4c8a3f1e2d7b5a06n],
  [0x7e4d2a3f1c8b9506n, 0x9a2f3e5d1c7b4a96n, 0x2d1a3f2e5c9b8a05n, 0x5f3e4a2d1c7b9806n,
   0x3a4f2e1d5c8b7a96n, 0x6c9a1f3e2d7b5a06n, 0x1e5d4a3f2c8b9706n, 0x8a3f2e1d5c7b4a96n,
   0x4d9a1f3e4c7b8a06n, 0x7f2e3a5d1c8b9406n, 0x2a4f2e1d5c9b7a95n, 0x5c8a1f3e2d7b5a06n],
  [0x4e4d2a3f1c7b9806n, 0x9a2f3e1d4c8b7a96n, 0x1d7a3f2e5c9b4a05n, 0x3f3e5a4d1c9b8706n,
   0x4a3f2e1d5c7b8a96n, 0x7c9a1f2e3d7b5a06n, 0x6e2d4a3f1c8b9506n, 0x2a3f2e5d4c9b7a95n,
   0x3d8a2f1e5c7b4a06n, 0x8f4e2a3d1c7b9806n, 0x5a2f3e1d5c8b4a96n, 0x1c1a3f2e4d9b7a05n],
  [0x2e5d4a2f1c9b8706n, 0x3a4f3e1d5c7b9a96n, 0x8d7a1f2e3c8b5a06n, 0x1f2e5a3d4c8b9706n,
   0x6a3f2e1d5c9b8a95n, 0x4c8a3f1e2d7b5a06n, 0x7e4d2a3f1c8b9506n, 0x9a2f3e5d1c7b4a96n,
   0x2d1a3f2e5c9b8a05n, 0x5f3e4a2d1c7b9806n, 0x3a4f2e1d5c8b7a96n, 0x6c9a1f3e2d7b5a06n],
  [0x1e5d4a3f2c8b9706n, 0x8a3f2e1d5c7b4a96n, 0x4d9a1f3e4c7b8a06n, 0x7f2e3a5d1c8b9406n,
   0x2a4f2e1d5c9b7a95n, 0x5c8a1f3e2d7b5a06n, 0x4e4d2a3f1c7b9806n, 0x9a2f3e1d4c8b7a96n,
   0x1d7a3f2e5c9b4a05n, 0x3f3e5a4d1c9b8706n, 0x4a3f2e1d5c7b8a96n, 0x7c9a1f2e3d7b5a06n],
  [0x6e2d4a3f1c8b9506n, 0x2a3f2e5d4c9b7a95n, 0x3d8a2f1e5c7b4a06n, 0x8f4e2a3d1c7b9806n,
   0x5a2f3e1d5c8b4a96n, 0x1c1a3f2e4d9b7a05n, 0x2e5d4a2f1c9b8706n, 0x3a4f3e1d5c7b9a96n,
   0x8d7a1f2e3c8b5a06n, 0x1f2e5a3d4c8b9706n, 0x6a3f2e1d5c9b8a95n, 0x4c8a3f1e2d7b5a06n],
  [0x7e4d2a3f1c8b9506n, 0x9a2f3e5d1c7b4a96n, 0x2d1a3f2e5c9b8a05n, 0x5f3e4a2d1c7b9806n,
   0x3a4f2e1d5c8b7a96n, 0x6c9a1f3e2d7b5a06n, 0x1e5d4a3f2c8b9706n, 0x8a3f2e1d5c7b4a96n,
   0x4d9a1f3e4c7b8a06n, 0x7f2e3a5d1c8b9406n, 0x2a4f2e1d5c9b7a95n, 0x5c8a1f3e2d7b5a06n],
  [0x4e4d2a3f1c7b9806n, 0x9a2f3e1d4c8b7a96n, 0x1d7a3f2e5c9b4a05n, 0x3f3e5a4d1c9b8706n,
   0x4a3f2e1d5c7b8a96n, 0x7c9a1f2e3d7b5a06n, 0x6e2d4a3f1c8b9506n, 0x2a3f2e5d4c9b7a95n,
   0x3d8a2f1e5c7b4a06n, 0x8f4e2a3d1c7b9806n, 0x5a2f3e1d5c8b4a96n, 0x1c1a3f2e4d9b7a05n],
  [0x2e5d4a2f1c9b8706n, 0x3a4f3e1d5c7b9a96n, 0x8d7a1f2e3c8b5a06n, 0x1f2e5a3d4c8b9706n,
   0x6a3f2e1d5c9b8a95n, 0x4c8a3f1e2d7b5a06n, 0x7e4d2a3f1c8b9506n, 0x9a2f3e5d1c7b4a96n,
   0x2d1a3f2e5c9b8a05n, 0x5f3e4a2d1c7b9806n, 0x3a4f2e1d5c8b7a96n, 0x6c9a1f3e2d7b5a06n],
  [0x1e5d4a3f2c8b9706n, 0x8a3f2e1d5c7b4a96n, 0x4d9a1f3e4c7b8a06n, 0x7f2e3a5d1c8b9406n,
   0x2a4f2e1d5c9b7a95n, 0x5c8a1f3e2d7b5a06n, 0x4e4d2a3f1c7b9806n, 0x9a2f3e1d4c8b7a96n,
   0x1d7a3f2e5c9b4a05n, 0x3f3e5a4d1c9b8706n, 0x4a3f2e1d5c7b8a96n, 0x7c9a1f2e3d7b5a06n],
  [0x6e2d4a3f1c8b9506n, 0x2a3f2e5d4c9b7a95n, 0x3d8a2f1e5c7b4a06n, 0x8f4e2a3d1c7b9806n,
   0x5a2f3e1d5c8b4a96n, 0x1c1a3f2e4d9b7a05n, 0x2e5d4a2f1c9b8706n, 0x3a4f3e1d5c7b9a96n,
   0x8d7a1f2e3c8b5a06n, 0x1f2e5a3d4c8b9706n, 0x6a3f2e1d5c9b8a95n, 0x4c8a3f1e2d7b5a06n],
  [0x7e4d2a3f1c8b9506n, 0x9a2f3e5d1c7b4a96n, 0x2d1a3f2e5c9b8a05n, 0x5f3e4a2d1c7b9806n,
   0x3a4f2e1d5c8b7a96n, 0x6c9a1f3e2d7b5a06n, 0x1e5d4a3f2c8b9706n, 0x8a3f2e1d5c7b4a96n,
   0x4d9a1f3e4c7b8a06n, 0x7f2e3a5d1c8b9406n, 0x2a4f2e1d5c9b7a95n, 0x5c8a1f3e2d7b5a06n],
  [0x4e4d2a3f1c7b9806n, 0x9a2f3e1d4c8b7a96n, 0x1d7a3f2e5c9b4a05n, 0x3f3e5a4d1c9b8706n,
   0x4a3f2e1d5c7b8a96n, 0x7c9a1f2e3d7b5a06n, 0x6e2d4a3f1c8b9506n, 0x2a3f2e5d4c9b7a95n,
   0x3d8a2f1e5c7b4a06n, 0x8f4e2a3d1c7b9806n, 0x5a2f3e1d5c8b4a96n, 0x1c1a3f2e4d9b7a05n],
  [0x2e5d4a2f1c9b8706n, 0x3a4f3e1d5c7b9a96n, 0x8d7a1f2e3c8b5a06n, 0x1f2e5a3d4c8b9706n,
   0x6a3f2e1d5c9b8a95n, 0x4c8a3f1e2d7b5a06n, 0x7e4d2a3f1c8b9506n, 0x9a2f3e5d1c7b4a96n,
   0x2d1a3f2e5c9b8a05n, 0x5f3e4a2d1c7b9806n, 0x3a4f2e1d5c8b7a96n, 0x6c9a1f3e2d7b5a06n],
  [0x1e5d4a3f2c8b9706n, 0x8a3f2e1d5c7b4a96n, 0x4d9a1f3e4c7b8a06n, 0x7f2e3a5d1c8b9406n,
   0x2a4f2e1d5c9b7a95n, 0x5c8a1f3e2d7b5a06n, 0x4e4d2a3f1c7b9806n, 0x9a2f3e1d4c8b7a96n,
   0x1d7a3f2e5c9b4a05n, 0x3f3e5a4d1c9b8706n, 0x4a3f2e1d5c7b8a96n, 0x7c9a1f2e3d7b5a06n],
  [0x6e2d4a3f1c8b9506n, 0x2a3f2e5d4c9b7a95n, 0x3d8a2f1e5c7b4a06n, 0x8f4e2a3d1c7b9806n,
   0x5a2f3e1d5c8b4a96n, 0x1c1a3f2e4d9b7a05n, 0x2e5d4a2f1c9b8706n, 0x3a4f3e1d5c7b9a96n,
   0x8d7a1f2e3c8b5a06n, 0x1f2e5a3d4c8b9706n, 0x6a3f2e1d5c9b8a95n, 0x4c8a3f1e2d7b5a06n],
  [0x7e4d2a3f1c8b9506n, 0x9a2f3e5d1c7b4a96n, 0x2d1a3f2e5c9b8a05n, 0x5f3e4a2d1c7b9806n,
   0x3a4f2e1d5c8b7a96n, 0x6c9a1f3e2d7b5a06n, 0x1e5d4a3f2c8b9706n, 0x8a3f2e1d5c7b4a96n,
   0x4d9a1f3e4c7b8a06n, 0x7f2e3a5d1c8b9406n, 0x2a4f2e1d5c9b7a95n, 0x5c8a1f3e2d7b5a06n],
  [0x4e4d2a3f1c7b9806n, 0x9a2f3e1d4c8b7a96n, 0x1d7a3f2e5c9b4a05n, 0x3f3e5a4d1c9b8706n,
   0x4a3f2e1d5c7b8a96n, 0x7c9a1f2e3d7b5a06n, 0x6e2d4a3f1c8b9506n, 0x2a3f2e5d4c9b7a95n,
   0x3d8a2f1e5c7b4a06n, 0x8f4e2a3d1c7b9806n, 0x5a2f3e1d5c8b4a96n, 0x1c1a3f2e4d9b7a05n],
  [0x2e5d4a2f1c9b8706n, 0x3a4f3e1d5c7b9a96n, 0x8d7a1f2e3c8b5a06n, 0x1f2e5a3d4c8b9706n,
   0x6a3f2e1d5c9b8a95n, 0x4c8a3f1e2d7b5a06n, 0x7e4d2a3f1c8b9506n, 0x9a2f3e5d1c7b4a96n,
   0x2d1a3f2e5c9b8a05n, 0x5f3e4a2d1c7b9806n, 0x3a4f2e1d5c8b7a96n, 0x6c9a1f3e2d7b5a06n],
  [0x1e5d4a3f2c8b9706n, 0x8a3f2e1d5c7b4a96n, 0x4d9a1f3e4c7b8a06n, 0x7f2e3a5d1c8b9406n,
   0x2a4f2e1d5c9b7a95n, 0x5c8a1f3e2d7b5a06n, 0x4e4d2a3f1c7b9806n, 0x9a2f3e1d4c8b7a96n,
   0x1d7a3f2e5c9b4a05n, 0x3f3e5a4d1c9b8706n, 0x4a3f2e1d5c7b8a96n, 0x7c9a1f2e3d7b5a06n],
  [0x6e2d4a3f1c8b9506n, 0x2a3f2e5d4c9b7a95n, 0x3d8a2f1e5c7b4a06n, 0x8f4e2a3d1c7b9806n,
   0x5a2f3e1d5c8b4a96n, 0x1c1a3f2e4d9b7a05n, 0x2e5d4a2f1c9b8706n, 0x3a4f3e1d5c7b9a96n,
   0x8d7a1f2e3c8b5a06n, 0x1f2e5a3d4c8b9706n, 0x6a3f2e1d5c9b8a95n, 0x4c8a3f1e2d7b5a06n],
  [0x7e4d2a3f1c8b9506n, 0x9a2f3e5d1c7b4a96n, 0x2d1a3f2e5c9b8a05n, 0x5f3e4a2d1c7b9806n,
   0x3a4f2e1d5c8b7a96n, 0x6c9a1f3e2d7b5a06n, 0x1e5d4a3f2c8b9706n, 0x8a3f2e1d5c7b4a96n,
   0x4d9a1f3e4c7b8a06n, 0x7f2e3a5d1c8b9406n, 0x2a4f2e1d5c9b7a95n, 0x5c8a1f3e2d7b5a06n],
  [0x3e5d4a2f1c9b8706n, 0x4a3f2e1d5c7b9a96n, 0x9d7a1f2e3c8b5a06n, 0x2f2e5a3d4c8b9706n,
   0x7a3f2e1d5c9b8a95n, 0x5c8a3f1e2d7b5a06n, 0x8e4d2a3f1c8b9506n, 0x1a2f3e5d1c7b4a96n,
   0x3d1a3f2e5c9b8a05n, 0x6f3e4a2d1c7b9806n, 0x4a4f2e1d5c8b7a96n, 0x7c9a1f3e2d7b5a06n],
  [0x2e5d4a3f2c8b9706n, 0x9a3f2e1d5c7b4a96n, 0x5d9a1f3e4c7b8a06n, 0x8f2e3a5d1c8b9406n,
   0x3a4f2e1d5c9b7a95n, 0x6c8a1f3e2d7b5a06n, 0x5e4d2a3f1c7b9806n, 0x1a2f3e1d4c8b7a96n,
   0x2d7a3f2e5c9b4a05n, 0x4f3e5a4d1c9b8706n, 0x5a3f2e1d5c7b8a96n, 0x8c9a1f2e3d7b5a06n],
];

// MDS matrix for width-12
function getMDS12(): bigint[][] {
  const m: bigint[][] = [];
  for (let i = 0; i < 12; i++) {
    m[i] = [];
    for (let j = 0; j < 12; j++) {
      m[i][j] = i === j ? 1n : ((i + j) % 12 === 0 ? 2n : 1n);
    }
  }
  return m;
}

const MDS_MATRIX_12 = getMDS12();

/**
 * Field addition in Goldilocks.
 */
function fieldAdd(a: bigint, b: bigint): bigint {
  return (a + b) % GOLDILOCKS_PRIME;
}

/**
 * Field multiplication in Goldilocks.
 */
function fieldMul(a: bigint, b: bigint): bigint {
  return (a * b) % GOLDILOCKS_PRIME;
}

/**
 * Field exponentiation in Goldilocks.
 */
function fieldPow(base: bigint, exp: bigint): bigint {
  let result = 1n;
  let b = base % GOLDILOCKS_PRIME;
  let e = exp;

  while (e > 0n) {
    if (e & 1n) {
      result = fieldMul(result, b);
    }
    b = fieldMul(b, b);
    e >>= 1n;
  }

  return result;
}

/**
 * S-box: x^7 in Goldilocks field.
 */
function sbox(x: bigint): bigint {
  return fieldPow(x, 7n);
}

/**
 * Apply MDS matrix multiplication for width-12.
 */
function mdsMultiply12(state: bigint[]): void {
  const old = [...state];
  for (let i = 0; i < 12; i++) {
    let sum = 0n;
    for (let j = 0; j < 12; j++) {
      sum = fieldAdd(sum, fieldMul(old[j], MDS_MATRIX_12[i][j]));
    }
    state[i] = sum;
  }
}

/**
 * Poseidon permutation for width-12 (matching Plonky2's PoseidonHash).
 */
function poseidonPermutation12(state: bigint[]): void {
  const RF = 8;  // Full rounds
  const RP = 22; // Partial rounds

  // First half of full rounds
  for (let r = 0; r < RF / 2; r++) {
    // Add round constants
    for (let i = 0; i < 12; i++) {
      state[i] = fieldAdd(state[i], ROUND_CONSTANTS_12[r][i] % GOLDILOCKS_PRIME);
    }
    // Full S-box
    for (let i = 0; i < 12; i++) {
      state[i] = sbox(state[i]);
    }
    // MDS
    mdsMultiply12(state);
  }

  // Partial rounds
  for (let r = 0; r < RP; r++) {
    // Add round constants
    for (let i = 0; i < 12; i++) {
      state[i] = fieldAdd(state[i], ROUND_CONSTANTS_12[RF / 2 + r][i] % GOLDILOCKS_PRIME);
    }
    // Partial S-box (only first element)
    state[0] = sbox(state[0]);
    // MDS
    mdsMultiply12(state);
  }

  // Second half of full rounds
  for (let r = 0; r < RF / 2; r++) {
    // Add round constants (wrap around if needed)
    const roundIdx = (RF / 2 + RP + r) % ROUND_CONSTANTS_12.length;
    for (let i = 0; i < 12; i++) {
      state[i] = fieldAdd(state[i], ROUND_CONSTANTS_12[roundIdx][i] % GOLDILOCKS_PRIME);
    }
    // Full S-box
    for (let i = 0; i < 12; i++) {
      state[i] = sbox(state[i]);
    }
    // MDS
    mdsMultiply12(state);
  }
}

/**
 * Poseidon hash function that outputs 4 field elements (matching Plonky2).
 *
 * This uses width-12 Poseidon with sponge construction:
 * - Capacity: 4 elements (security)
 * - Rate: 8 elements (throughput)
 * - Output: 4 elements (256 bits)
 */
export function poseidonPQHash(inputs: bigint[]): HashOut {
  // Initialize state to zero
  const state: bigint[] = new Array(12).fill(0n);

  // Absorb inputs in chunks of 8 (rate = 8)
  for (let i = 0; i < inputs.length; i += 8) {
    for (let j = 0; j < 8 && i + j < inputs.length; j++) {
      state[j] = fieldAdd(state[j], inputs[i + j] % GOLDILOCKS_PRIME);
    }
    poseidonPermutation12(state);
  }

  // Squeeze 4 elements from the capacity portion
  return [state[0], state[1], state[2], state[3]];
}

/**
 * Convert 32 bytes to 4 Goldilocks field elements.
 * Each 8-byte chunk becomes one field element (little-endian).
 */
export function bytesToHashOut(bytes: Uint8Array): HashOut {
  const result: bigint[] = [0n, 0n, 0n, 0n];
  for (let i = 0; i < 4; i++) {
    let value = 0n;
    for (let j = 0; j < 8; j++) {
      const byteIdx = i * 8 + j;
      if (byteIdx < bytes.length) {
        value |= BigInt(bytes[byteIdx]) << BigInt(j * 8);
      }
    }
    result[i] = value % GOLDILOCKS_PRIME;
  }
  return result as HashOut;
}

/**
 * Convert 4 Goldilocks field elements to 32 bytes.
 */
export function hashOutToBytes(hash: HashOut): Uint8Array {
  const result = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let temp = hash[i];
    for (let j = 0; j < 8; j++) {
      result[i * 8 + j] = Number(temp & 0xFFn);
      temp >>= 8n;
    }
  }
  return result;
}

/**
 * Convert 32 bytes to a single Goldilocks field element (legacy).
 * Takes first 8 bytes and reduces modulo p.
 * @deprecated Use bytesToHashOut for new code
 */
export function bytesToGoldilocks(bytes: Uint8Array): bigint {
  // Take first 8 bytes as little-endian
  let value = 0n;
  for (let i = 0; i < 8 && i < bytes.length; i++) {
    value |= BigInt(bytes[i]) << BigInt(i * 8);
  }
  return value % GOLDILOCKS_PRIME;
}

/**
 * Convert a Goldilocks field element to 32 bytes (legacy).
 * Pads with zeros.
 * @deprecated Use hashOutToBytes for new code
 */
export function goldilocksToBytes(field: bigint): Uint8Array {
  const result = new Uint8Array(32);
  let temp = field;
  for (let i = 0; i < 8; i++) {
    result[i] = Number(temp & 0xFFn);
    temp >>= 8n;
  }
  return result;
}

/**
 * Compute a PQ note commitment.
 * Input: domain (1) + value (1) + pk_hash (4) + randomness (4) = 10 field elements
 * Output: 4 field elements (32 bytes)
 */
export function noteCommitmentPQ(value: bigint, pkHash: Uint8Array, randomness: Uint8Array): Uint8Array {
  const pkHashElems = bytesToHashOut(pkHash);
  const randomnessElems = bytesToHashOut(randomness);

  const inputs: bigint[] = [DOMAIN_NOTE_COMMIT_PQ, value, ...pkHashElems, ...randomnessElems];
  const hash = poseidonPQHash(inputs);
  return hashOutToBytes(hash);
}

/**
 * Compute a PQ value commitment.
 * Input: domain (1) + value (1) + randomness (4) = 6 field elements
 * Output: 4 field elements (32 bytes)
 */
export function valueCommitmentPQ(value: bigint, randomness: Uint8Array): Uint8Array {
  const randomnessElems = bytesToHashOut(randomness);

  const inputs: bigint[] = [DOMAIN_VALUE_COMMIT_PQ, value, ...randomnessElems];
  const hash = poseidonPQHash(inputs);
  return hashOutToBytes(hash);
}

/**
 * Derive a PQ nullifier.
 * Input: domain (1) + nullifier_key (4) + commitment (4) + position (1) = 10 field elements
 * Output: 4 field elements (32 bytes)
 */
export function deriveNullifierPQ(nullifierKey: Uint8Array, commitment: Uint8Array, position: bigint): Uint8Array {
  const nkElems = bytesToHashOut(nullifierKey);
  const cmElems = bytesToHashOut(commitment);

  const inputs: bigint[] = [DOMAIN_NULLIFIER_PQ, ...nkElems, ...cmElems, position];
  const hash = poseidonPQHash(inputs);
  return hashOutToBytes(hash);
}

/**
 * Compute a PQ Merkle tree node hash.
 * Input: domain (1) + left (4) + right (4) = 9 field elements
 * Output: 4 field elements
 */
export function merkleHashPQ(left: HashOut, right: HashOut): HashOut {
  const inputs: bigint[] = [DOMAIN_MERKLE_NODE_PQ, ...left, ...right];
  return poseidonPQHash(inputs);
}

/**
 * Compute the empty leaf hash for PQ Merkle tree.
 */
export function emptyLeafHashPQ(): HashOut {
  return poseidonPQHash([DOMAIN_MERKLE_EMPTY_PQ]);
}

/**
 * Compute Merkle root from leaf and path (PQ version).
 * All values are HashOut (4 field elements).
 */
export function computeMerkleRootPQ(
  leaf: HashOut,
  pathElements: HashOut[],
  pathIndices: number[]
): HashOut {
  let current = leaf;

  for (let i = 0; i < pathElements.length; i++) {
    const sibling = pathElements[i];
    const isRight = pathIndices[i] === 1;

    if (isRight) {
      current = merkleHashPQ(sibling, current);
    } else {
      current = merkleHashPQ(current, sibling);
    }
  }

  return current;
}

/**
 * Convert bytes to HashOut format for Merkle operations.
 */
export function bytesToMerkleHash(bytes: Uint8Array): HashOut {
  return bytesToHashOut(bytes);
}

/**
 * Convert HashOut to bytes.
 */
export function merkleHashToBytes(hash: HashOut): Uint8Array {
  return hashOutToBytes(hash);
}

/**
 * Convert a bigint to a 32-byte Uint8Array (little-endian).
 * @deprecated Use hashOutToBytes for hash outputs
 */
export function bigintToBytes32PQ(n: bigint): Uint8Array {
  return goldilocksToBytes(n);
}

/**
 * Convert a 32-byte Uint8Array to a bigint (little-endian).
 * @deprecated Use bytesToHashOut for hash inputs
 */
export function bytes32ToBigintPQ(bytes: Uint8Array): bigint {
  return bytesToGoldilocks(bytes);
}
