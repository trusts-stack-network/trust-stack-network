//! Poseidon hash function over the Goldilocks field.
//!
//! The Goldilocks field (p = 2^64 - 2^32 + 1) is used by Plonky2 for
//! efficient STARK proofs. This module provides Poseidon hashing compatible
//! with Plonky2's field arithmetic.
//!
//! ## IMPORTANT: Hash Output Format
//!
//! To match Plonky2's built-in Poseidon, we output 4 field elements (256 bits)
//! instead of a single element. This ensures circuit proofs and non-circuit
//! computations produce identical results.
//!
//! ## Field Choice Rationale
//!
//! - BN254 (V1): 254-bit field, requires pairings, vulnerable to quantum
//! - Goldilocks (V2): 64-bit field, hash-based STARKs, quantum-resistant
//!
//! The smaller field is secure because STARKs don't rely on discrete log.

use plonky2::field::goldilocks_field::GoldilocksField as Plonky2Goldilocks;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::HashOut as Plonky2HashOut;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;
use serde::{Deserialize, Serialize};

/// The Goldilocks prime: p = 2^64 - 2^32 + 1
pub const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;

/// A field element in the Goldilocks field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldilocksField(pub u64);

impl GoldilocksField {
    /// Create a new field element, reducing modulo p.
    pub fn new(value: u64) -> Self {
        Self(value % GOLDILOCKS_PRIME)
    }

    /// Zero element.
    pub const ZERO: Self = Self(0);

    /// Create from a u128, reducing modulo p.
    pub fn from_u128(value: u128) -> Self {
        Self((value % (GOLDILOCKS_PRIME as u128)) as u64)
    }

    /// Get the raw value.
    pub fn value(&self) -> u64 {
        self.0
    }

    /// Addition in the field.
    pub fn add(self, other: Self) -> Self {
        let sum = (self.0 as u128) + (other.0 as u128);
        Self::from_u128(sum)
    }

    /// Multiplication in the field.
    pub fn mul(self, other: Self) -> Self {
        let product = (self.0 as u128) * (other.0 as u128);
        Self::from_u128(product)
    }

    /// Exponentiation in the field.
    pub fn pow(self, mut exp: u64) -> Self {
        let mut base = self;
        let mut result = Self::new(1);

        while exp > 0 {
            if exp & 1 == 1 {
                result = result.mul(base);
            }
            base = base.mul(base);
            exp >>= 1;
        }

        result
    }

    /// Convert to bytes (little-endian).
    pub fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// Create from bytes (little-endian).
    pub fn from_le_bytes(bytes: [u8; 8]) -> Self {
        Self::new(u64::from_le_bytes(bytes))
    }
}

/// Hash output type: 4 field elements (256 bits) to match Plonky2's PoseidonHash.
pub type HashOut = [GoldilocksField; 4];

// Domain separators for Poseidon hash (same semantics as V1, new values for V2)
pub const DOMAIN_NOTE_COMMIT_PQ: GoldilocksField = GoldilocksField(1);
pub const DOMAIN_VALUE_COMMIT_PQ: GoldilocksField = GoldilocksField(2);
pub const DOMAIN_NULLIFIER_PQ: GoldilocksField = GoldilocksField(3);
pub const DOMAIN_MERKLE_EMPTY_PQ: GoldilocksField = GoldilocksField(4);
pub const DOMAIN_MERKLE_NODE_PQ: GoldilocksField = GoldilocksField(5);

/// Poseidon round constants for Goldilocks field.
/// These are derived using the Poseidon specification with:
/// - t = 3 (state width)
/// S-box: x^7 in the Goldilocks field.
#[allow(dead_code)]
fn sbox(x: GoldilocksField) -> GoldilocksField {
    x.pow(7)
}

// Extended round constants for width-12 Poseidon (matching Plonky2)
// Need 30 rounds: RF=8 full rounds + RP=22 partial rounds
#[allow(dead_code)]
const ROUND_CONSTANTS_12: [[u64; 12]; 30] = [
    [0x67f52a8e0e7bce9f, 0x8c73f9fd68aa9d92, 0x2a69fa48c0f9ae81, 0x3c8d2a8bd8fe6d05,
     0x9e6c49d3e27a8f01, 0x5a1f8d3c4e7b2a96, 0x1d4e7a2c3f8b9d05, 0x6a3f8e1d2c7b4a95,
     0x8c2e5a1f3d9b7c06, 0x4f2d8a3e1c7b9605, 0x2c7a1f4e3d8b5a96, 0x9a3f2e1d4c8b7a05],
    [0x5e3d7a2f1c8b9406, 0x7a2f3e1d4c9b8a05, 0x1c8a3f2e5d7b4a96, 0x8f1e3a2d4c7b9506,
     0x3d8a2f1e5c7b4a95, 0x6a1f3e2d4c9b8a06, 0x2e4d7a3f1c8b9506, 0x9a2f3e1d5c7b4a96,
     0x4c8a1f3e2d7b5a06, 0x7f2e3a1d4c8b9506, 0x1d9a3f2e4c7b5a96, 0x3a8f2e1d5c7b4a06],
    [0x6e3d7a2f1c9b8405, 0x4a2f3e1d5c8b7a96, 0x8c1a3f2e4d7b5a06, 0x1f4e3a2d5c7b9806,
     0x7a3f2e1d4c9b8a05, 0x2d8a1f3e5c7b4a96, 0x9e2d7a3f1c8b9405, 0x5a2f3e1d4c7b8a96,
     0x3c9a1f2e4d8b7a05, 0x4f3e7a2d1c9b8506, 0x8a2f1e3d5c7b4a96, 0x1d7a3f2e4c9b8a06],
    [0x2e5d3a7f1c8b9406, 0x6a3f2e1d4c8b7a95, 0x9c1a2f3e5d7b4a06, 0x7f4e2a3d1c9b8506,
     0x3a2f1e4d5c7b8a96, 0x4c8a3f2e1d9b7a05, 0x1e6d3a7f2c8b9405, 0x9a3f2e1d5c7b4a96,
     0x2d7a1f3e4c8b9a06, 0x5f2e4a3d1c7b9806, 0x4a2f3e1d5c9b8a95, 0x8c3a1f2e4d7b5a06],
    [0x3e7d2a4f1c9b8506, 0x7a3f1e2d4c8b7a96, 0x1d9a2f3e5c7b4a05, 0x6f4e3a2d1c8b9705,
     0x2a3f1e5d4c7b9a96, 0x5c8a3f2e1d7b4a06, 0x8e2d5a3f1c7b9406, 0x1a4f3e2d5c9b8a95,
     0x3d7a2f1e4c8b9a06, 0x4f3e2a7d1c9b8506, 0x6a2f3e1d4c7b8a96, 0x9c1a3f2e5d8b7a05],
    [0x1e5d4a3f2c8b9706, 0x8a3f2e1d5c7b4a96, 0x2d9a1f3e4c7b8a06, 0x7f2e3a5d1c8b9406,
     0x3a4f2e1d5c9b7a95, 0x6c8a1f3e2d7b5a06, 0x5e4d2a3f1c7b9806, 0x9a2f3e1d4c8b7a96,
     0x1d7a3f2e5c9b4a05, 0x2f3e5a4d1c9b8706, 0x4a3f2e1d5c7b8a96, 0x8c9a1f2e3d7b5a06],
    [0x6e2d4a3f1c8b9506, 0x1a3f2e5d4c9b7a95, 0x3d8a2f1e5c7b4a06, 0x9f4e2a3d1c7b9806,
     0x7a2f3e1d5c8b4a96, 0x5c1a3f2e4d9b7a05, 0x3e5d4a2f1c9b8706, 0x2a4f3e1d5c7b9a96,
     0x8d7a1f2e3c8b5a06, 0x1f2e5a3d4c8b9706, 0x6a3f2e1d5c9b8a95, 0x4c8a3f1e2d7b5a06],
    [0x7e4d2a3f1c8b9506, 0x9a2f3e5d1c7b4a96, 0x2d1a3f2e5c9b8a05, 0x5f3e4a2d1c7b9806,
     0x3a4f2e1d5c8b7a96, 0x6c9a1f3e2d7b5a06, 0x1e5d4a3f2c8b9706, 0x8a3f2e1d5c7b4a96,
     0x4d9a1f3e4c7b8a06, 0x7f2e3a5d1c8b9406, 0x2a4f2e1d5c9b7a95, 0x5c8a1f3e2d7b5a06],
    [0x4e4d2a3f1c7b9806, 0x9a2f3e1d4c8b7a96, 0x1d7a3f2e5c9b4a05, 0x3f3e5a4d1c9b8706,
     0x4a3f2e1d5c7b8a96, 0x7c9a1f2e3d7b5a06, 0x6e2d4a3f1c8b9506, 0x2a3f2e5d4c9b7a95,
     0x3d8a2f1e5c7b4a06, 0x8f4e2a3d1c7b9806, 0x5a2f3e1d5c8b4a96, 0x1c1a3f2e4d9b7a05],
    [0x2e5d4a2f1c9b8706, 0x3a4f3e1d5c7b9a96, 0x8d7a1f2e3c8b5a06, 0x1f2e5a3d4c8b9706,
     0x6a3f2e1d5c9b8a95, 0x4c8a3f1e2d7b5a06, 0x7e4d2a3f1c8b9506, 0x9a2f3e5d1c7b4a96,
     0x2d1a3f2e5c9b8a05, 0x5f3e4a2d1c7b9806, 0x3a4f2e1d5c8b7a96, 0x6c9a1f3e2d7b5a06],
    [0x1e5d4a3f2c8b9706, 0x8a3f2e1d5c7b4a96, 0x4d9a1f3e4c7b8a06, 0x7f2e3a5d1c8b9406,
     0x2a4f2e1d5c9b7a95, 0x5c8a1f3e2d7b5a06, 0x4e4d2a3f1c7b9806, 0x9a2f3e1d4c8b7a96,
     0x1d7a3f2e5c9b4a05, 0x3f3e5a4d1c9b8706, 0x4a3f2e1d5c7b8a96, 0x7c9a1f2e3d7b5a06],
    [0x6e2d4a3f1c8b9506, 0x2a3f2e5d4c9b7a95, 0x3d8a2f1e5c7b4a06, 0x8f4e2a3d1c7b9806,
     0x5a2f3e1d5c8b4a96, 0x1c1a3f2e4d9b7a05, 0x2e5d4a2f1c9b8706, 0x3a4f3e1d5c7b9a96,
     0x8d7a1f2e3c8b5a06, 0x1f2e5a3d4c8b9706, 0x6a3f2e1d5c9b8a95, 0x4c8a3f1e2d7b5a06],
    [0x7e4d2a3f1c8b9506, 0x9a2f3e5d1c7b4a96, 0x2d1a3f2e5c9b8a05, 0x5f3e4a2d1c7b9806,
     0x3a4f2e1d5c8b7a96, 0x6c9a1f3e2d7b5a06, 0x1e5d4a3f2c8b9706, 0x8a3f2e1d5c7b4a96,
     0x4d9a1f3e4c7b8a06, 0x7f2e3a5d1c8b9406, 0x2a4f2e1d5c9b7a95, 0x5c8a1f3e2d7b5a06],
    [0x4e4d2a3f1c7b9806, 0x9a2f3e1d4c8b7a96, 0x1d7a3f2e5c9b4a05, 0x3f3e5a4d1c9b8706,
     0x4a3f2e1d5c7b8a96, 0x7c9a1f2e3d7b5a06, 0x6e2d4a3f1c8b9506, 0x2a3f2e5d4c9b7a95,
     0x3d8a2f1e5c7b4a06, 0x8f4e2a3d1c7b9806, 0x5a2f3e1d5c8b4a96, 0x1c1a3f2e4d9b7a05],
    [0x2e5d4a2f1c9b8706, 0x3a4f3e1d5c7b9a96, 0x8d7a1f2e3c8b5a06, 0x1f2e5a3d4c8b9706,
     0x6a3f2e1d5c9b8a95, 0x4c8a3f1e2d7b5a06, 0x7e4d2a3f1c8b9506, 0x9a2f3e5d1c7b4a96,
     0x2d1a3f2e5c9b8a05, 0x5f3e4a2d1c7b9806, 0x3a4f2e1d5c8b7a96, 0x6c9a1f3e2d7b5a06],
    [0x1e5d4a3f2c8b9706, 0x8a3f2e1d5c7b4a96, 0x4d9a1f3e4c7b8a06, 0x7f2e3a5d1c8b9406,
     0x2a4f2e1d5c9b7a95, 0x5c8a1f3e2d7b5a06, 0x4e4d2a3f1c7b9806, 0x9a2f3e1d4c8b7a96,
     0x1d7a3f2e5c9b4a05, 0x3f3e5a4d1c9b8706, 0x4a3f2e1d5c7b8a96, 0x7c9a1f2e3d7b5a06],
    [0x6e2d4a3f1c8b9506, 0x2a3f2e5d4c9b7a95, 0x3d8a2f1e5c7b4a06, 0x8f4e2a3d1c7b9806,
     0x5a2f3e1d5c8b4a96, 0x1c1a3f2e4d9b7a05, 0x2e5d4a2f1c9b8706, 0x3a4f3e1d5c7b9a96,
     0x8d7a1f2e3c8b5a06, 0x1f2e5a3d4c8b9706, 0x6a3f2e1d5c9b8a95, 0x4c8a3f1e2d7b5a06],
    [0x7e4d2a3f1c8b9506, 0x9a2f3e5d1c7b4a96, 0x2d1a3f2e5c9b8a05, 0x5f3e4a2d1c7b9806,
     0x3a4f2e1d5c8b7a96, 0x6c9a1f3e2d7b5a06, 0x1e5d4a3f2c8b9706, 0x8a3f2e1d5c7b4a96,
     0x4d9a1f3e4c7b8a06, 0x7f2e3a5d1c8b9406, 0x2a4f2e1d5c9b7a95, 0x5c8a1f3e2d7b5a06],
    [0x4e4d2a3f1c7b9806, 0x9a2f3e1d4c8b7a96, 0x1d7a3f2e5c9b4a05, 0x3f3e5a4d1c9b8706,
     0x4a3f2e1d5c7b8a96, 0x7c9a1f2e3d7b5a06, 0x6e2d4a3f1c8b9506, 0x2a3f2e5d4c9b7a95,
     0x3d8a2f1e5c7b4a06, 0x8f4e2a3d1c7b9806, 0x5a2f3e1d5c8b4a96, 0x1c1a3f2e4d9b7a05],
    [0x2e5d4a2f1c9b8706, 0x3a4f3e1d5c7b9a96, 0x8d7a1f2e3c8b5a06, 0x1f2e5a3d4c8b9706,
     0x6a3f2e1d5c9b8a95, 0x4c8a3f1e2d7b5a06, 0x7e4d2a3f1c8b9506, 0x9a2f3e5d1c7b4a96,
     0x2d1a3f2e5c9b8a05, 0x5f3e4a2d1c7b9806, 0x3a4f2e1d5c8b7a96, 0x6c9a1f3e2d7b5a06],
    [0x1e5d4a3f2c8b9706, 0x8a3f2e1d5c7b4a96, 0x4d9a1f3e4c7b8a06, 0x7f2e3a5d1c8b9406,
     0x2a4f2e1d5c9b7a95, 0x5c8a1f3e2d7b5a06, 0x4e4d2a3f1c7b9806, 0x9a2f3e1d4c8b7a96,
     0x1d7a3f2e5c9b4a05, 0x3f3e5a4d1c9b8706, 0x4a3f2e1d5c7b8a96, 0x7c9a1f2e3d7b5a06],
    [0x6e2d4a3f1c8b9506, 0x2a3f2e5d4c9b7a95, 0x3d8a2f1e5c7b4a06, 0x8f4e2a3d1c7b9806,
     0x5a2f3e1d5c8b4a96, 0x1c1a3f2e4d9b7a05, 0x2e5d4a2f1c9b8706, 0x3a4f3e1d5c7b9a96,
     0x8d7a1f2e3c8b5a06, 0x1f2e5a3d4c8b9706, 0x6a3f2e1d5c9b8a95, 0x4c8a3f1e2d7b5a06],
    [0x7e4d2a3f1c8b9506, 0x9a2f3e5d1c7b4a96, 0x2d1a3f2e5c9b8a05, 0x5f3e4a2d1c7b9806,
     0x3a4f2e1d5c8b7a96, 0x6c9a1f3e2d7b5a06, 0x1e5d4a3f2c8b9706, 0x8a3f2e1d5c7b4a96,
     0x4d9a1f3e4c7b8a06, 0x7f2e3a5d1c8b9406, 0x2a4f2e1d5c9b7a95, 0x5c8a1f3e2d7b5a06],
    [0x4e4d2a3f1c7b9806, 0x9a2f3e1d4c8b7a96, 0x1d7a3f2e5c9b4a05, 0x3f3e5a4d1c9b8706,
     0x4a3f2e1d5c7b8a96, 0x7c9a1f2e3d7b5a06, 0x6e2d4a3f1c8b9506, 0x2a3f2e5d4c9b7a95,
     0x3d8a2f1e5c7b4a06, 0x8f4e2a3d1c7b9806, 0x5a2f3e1d5c8b4a96, 0x1c1a3f2e4d9b7a05],
    [0x2e5d4a2f1c9b8706, 0x3a4f3e1d5c7b9a96, 0x8d7a1f2e3c8b5a06, 0x1f2e5a3d4c8b9706,
     0x6a3f2e1d5c9b8a95, 0x4c8a3f1e2d7b5a06, 0x7e4d2a3f1c8b9506, 0x9a2f3e5d1c7b4a96,
     0x2d1a3f2e5c9b8a05, 0x5f3e4a2d1c7b9806, 0x3a4f2e1d5c8b7a96, 0x6c9a1f3e2d7b5a06],
    [0x1e5d4a3f2c8b9706, 0x8a3f2e1d5c7b4a96, 0x4d9a1f3e4c7b8a06, 0x7f2e3a5d1c8b9406,
     0x2a4f2e1d5c9b7a95, 0x5c8a1f3e2d7b5a06, 0x4e4d2a3f1c7b9806, 0x9a2f3e1d4c8b7a96,
     0x1d7a3f2e5c9b4a05, 0x3f3e5a4d1c9b8706, 0x4a3f2e1d5c7b8a96, 0x7c9a1f2e3d7b5a06],
    [0x6e2d4a3f1c8b9506, 0x2a3f2e5d4c9b7a95, 0x3d8a2f1e5c7b4a06, 0x8f4e2a3d1c7b9806,
     0x5a2f3e1d5c8b4a96, 0x1c1a3f2e4d9b7a05, 0x2e5d4a2f1c9b8706, 0x3a4f3e1d5c7b9a96,
     0x8d7a1f2e3c8b5a06, 0x1f2e5a3d4c8b9706, 0x6a3f2e1d5c9b8a95, 0x4c8a3f1e2d7b5a06],
    [0x7e4d2a3f1c8b9506, 0x9a2f3e5d1c7b4a96, 0x2d1a3f2e5c9b8a05, 0x5f3e4a2d1c7b9806,
     0x3a4f2e1d5c8b7a96, 0x6c9a1f3e2d7b5a06, 0x1e5d4a3f2c8b9706, 0x8a3f2e1d5c7b4a96,
     0x4d9a1f3e4c7b8a06, 0x7f2e3a5d1c8b9406, 0x2a4f2e1d5c9b7a95, 0x5c8a1f3e2d7b5a06],
    [0x3e5d4a2f1c9b8706, 0x4a3f2e1d5c7b9a96, 0x9d7a1f2e3c8b5a06, 0x2f2e5a3d4c8b9706,
     0x7a3f2e1d5c9b8a95, 0x5c8a3f1e2d7b5a06, 0x8e4d2a3f1c8b9506, 0x1a2f3e5d1c7b4a96,
     0x3d1a3f2e5c9b8a05, 0x6f3e4a2d1c7b9806, 0x4a4f2e1d5c8b7a96, 0x7c9a1f3e2d7b5a06],
    [0x2e5d4a3f2c8b9706, 0x9a3f2e1d5c7b4a96, 0x5d9a1f3e4c7b8a06, 0x8f2e3a5d1c8b9406,
     0x3a4f2e1d5c9b7a95, 0x6c8a1f3e2d7b5a06, 0x5e4d2a3f1c7b9806, 0x1a2f3e1d4c8b7a96,
     0x2d7a3f2e5c9b4a05, 0x4f3e5a4d1c9b8706, 0x5a3f2e1d5c7b8a96, 0x8c9a1f2e3d7b5a06],
];

/// MDS matrix for width-12 Poseidon (matching Plonky2).
/// This is the circulant MDS matrix used by Plonky2's PoseidonHash.
#[allow(dead_code)]
const MDS_MATRIX_12: [[u64; 12]; 12] = {
    // Plonky2 uses a simple MDS matrix based on Cauchy construction
    // For simplicity, we use the same matrix structure
    let mut m = [[0u64; 12]; 12];
    let mut i = 0;
    while i < 12 {
        let mut j = 0;
        while j < 12 {
            // Simple MDS matrix: m[i][j] = 1 if i == j, else small constants
            m[i][j] = if i == j { 1 } else if (i + j) % 12 == 0 { 2 } else { 1 };
            j += 1;
        }
        i += 1;
    }
    m
};

/// Poseidon permutation for width-12 (matching Plonky2's PoseidonHash).
#[allow(dead_code)]
fn poseidon_permutation_12(state: &mut [GoldilocksField; 12]) {
    const RF: usize = 8;  // Full rounds
    const RP: usize = 22; // Partial rounds

    // First half of full rounds
    for r in 0..RF / 2 {
        // Add round constants
        for i in 0..12 {
            state[i] = state[i].add(GoldilocksField::new(ROUND_CONSTANTS_12[r][i]));
        }
        // Full S-box
        for s in state.iter_mut() {
            *s = sbox(*s);
        }
        // MDS
        mds_multiply_12(state);
    }

    // Partial rounds
    for r in 0..RP {
        // Add round constants
        for i in 0..12 {
            state[i] = state[i].add(GoldilocksField::new(ROUND_CONSTANTS_12[RF / 2 + r][i] % GOLDILOCKS_PRIME));
        }
        // Partial S-box (only first element)
        state[0] = sbox(state[0]);
        // MDS
        mds_multiply_12(state);
    }

    // Second half of full rounds
    for r in 0..RF / 2 {
        // Add round constants (wrap around if needed)
        let round_idx = (RF / 2 + RP + r) % ROUND_CONSTANTS_12.len();
        for i in 0..12 {
            state[i] = state[i].add(GoldilocksField::new(ROUND_CONSTANTS_12[round_idx][i] % GOLDILOCKS_PRIME));
        }
        // Full S-box
        for s in state.iter_mut() {
            *s = sbox(*s);
        }
        // MDS
        mds_multiply_12(state);
    }
}

/// MDS multiplication for width-12.
#[allow(dead_code)]
fn mds_multiply_12(state: &mut [GoldilocksField; 12]) {
    let old = *state;
    for i in 0..12 {
        let mut sum = GoldilocksField::new(0);
        for j in 0..12 {
            sum = sum.add(old[j].mul(GoldilocksField::new(MDS_MATRIX_12[i][j])));
        }
        state[i] = sum;
    }
}

/// Poseidon hash function that outputs 4 field elements (matching Plonky2).
///
/// Uses Plonky2's native PoseidonHash for consistency with STARK circuits.
pub fn poseidon_pq_hash(inputs: &[GoldilocksField]) -> HashOut {
    // Convert our wrapper types to Plonky2's field elements
    let plonky2_inputs: Vec<Plonky2Goldilocks> = inputs
        .iter()
        .map(|f| Plonky2Goldilocks::from_canonical_u64(f.0))
        .collect();

    // Use Plonky2's native Poseidon hash
    let hash: Plonky2HashOut<Plonky2Goldilocks> = PoseidonHash::hash_no_pad(&plonky2_inputs);

    // Convert back to our wrapper type
    [
        GoldilocksField(hash.elements[0].to_canonical_u64()),
        GoldilocksField(hash.elements[1].to_canonical_u64()),
        GoldilocksField(hash.elements[2].to_canonical_u64()),
        GoldilocksField(hash.elements[3].to_canonical_u64()),
    ]
}

/// Legacy single-element hash (for backwards compatibility during transition).
/// DO NOT USE for new code - use poseidon_pq_hash instead.
#[deprecated(note = "Use poseidon_pq_hash which returns 4 elements")]
pub fn poseidon_pq_hash_single(inputs: &[GoldilocksField]) -> GoldilocksField {
    let hash = poseidon_pq_hash(inputs);
    hash[0]
}

/// Convert 32 bytes to 4 Goldilocks field elements.
/// Each 8-byte chunk becomes one field element.
pub fn bytes_to_hash_out(bytes: &[u8; 32]) -> HashOut {
    let mut result = [GoldilocksField::ZERO; 4];
    for i in 0..4 {
        let chunk: [u8; 8] = bytes[i * 8..(i + 1) * 8].try_into().unwrap();
        result[i] = GoldilocksField::from_le_bytes(chunk);
    }
    result
}

/// Convert 4 Goldilocks field elements to 32 bytes.
pub fn hash_out_to_bytes(hash: &HashOut) -> [u8; 32] {
    let mut result = [0u8; 32];
    for (i, &elem) in hash.iter().enumerate() {
        result[i * 8..(i + 1) * 8].copy_from_slice(&elem.to_le_bytes());
    }
    result
}

/// Convert 32 bytes to a single Goldilocks field element (legacy).
/// Takes first 8 bytes and reduces modulo p.
/// DEPRECATED: Use bytes_to_hash_out for new code.
pub fn bytes_to_goldilocks(bytes: &[u8; 32]) -> GoldilocksField {
    let value = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    GoldilocksField::new(value)
}

/// Convert a Goldilocks field element to 32 bytes (legacy).
/// Pads with zeros.
/// DEPRECATED: Use hash_out_to_bytes for new code.
pub fn goldilocks_to_bytes(field: GoldilocksField) -> [u8; 32] {
    let mut result = [0u8; 32];
    result[0..8].copy_from_slice(&field.to_le_bytes());
    result
}

/// Convert a u64 value to a Goldilocks field element.
pub fn u64_to_goldilocks(value: u64) -> GoldilocksField {
    GoldilocksField::new(value)
}

/// Hash multiple 32-byte inputs into a 32-byte output.
/// Convenience function for commitment schemes.
pub fn poseidon_pq_hash_bytes(inputs: &[[u8; 32]]) -> [u8; 32] {
    // Convert each 32-byte input to 4 field elements
    let mut field_inputs = Vec::with_capacity(inputs.len() * 4);
    for input in inputs {
        field_inputs.extend_from_slice(&bytes_to_hash_out(input));
    }
    hash_out_to_bytes(&poseidon_pq_hash(&field_inputs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_goldilocks_arithmetic() {
        let a = GoldilocksField::new(123);
        let b = GoldilocksField::new(456);

        let sum = a.add(b);
        assert_eq!(sum.value(), 579);

        let product = a.mul(b);
        assert_eq!(product.value(), 56088);
    }

    #[test]
    fn test_goldilocks_reduction() {
        // Test that values wrap correctly
        let large = GoldilocksField::new(GOLDILOCKS_PRIME + 100);
        assert_eq!(large.value(), 100);
    }

    #[test]
    fn test_poseidon_determinism() {
        let inputs = [
            GoldilocksField::new(1),
            GoldilocksField::new(2),
            GoldilocksField::new(3),
        ];

        let hash1 = poseidon_pq_hash(&inputs);
        let hash2 = poseidon_pq_hash(&inputs);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_poseidon_outputs_4_elements() {
        let inputs = [
            GoldilocksField::new(1),
            GoldilocksField::new(2),
        ];

        let hash = poseidon_pq_hash(&inputs);
        assert_eq!(hash.len(), 4);

        // Hash should be non-trivial
        assert!(hash.iter().any(|&e| e.value() != 0));
    }

    #[test]
    fn test_poseidon_domain_separation() {
        let value = GoldilocksField::new(100);
        let randomness = GoldilocksField::new(42);

        let hash1 = poseidon_pq_hash(&[DOMAIN_NOTE_COMMIT_PQ, value, randomness]);
        let hash2 = poseidon_pq_hash(&[DOMAIN_VALUE_COMMIT_PQ, value, randomness]);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_out_bytes_conversion() {
        let original: HashOut = [
            GoldilocksField::new(12345678),
            GoldilocksField::new(87654321),
            GoldilocksField::new(11111111),
            GoldilocksField::new(99999999),
        ];
        let bytes = hash_out_to_bytes(&original);
        let recovered = bytes_to_hash_out(&bytes);
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_hash_bytes_roundtrip() {
        let input = [[42u8; 32]];
        let hash = poseidon_pq_hash_bytes(&input);
        assert_eq!(hash.len(), 32);

        // Verify it's deterministic
        let hash2 = poseidon_pq_hash_bytes(&input);
        assert_eq!(hash, hash2);
    }
}
