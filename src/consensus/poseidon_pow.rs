//! Poseidon-based Proof-of-Work hash function.
//!
//! Uses Poseidon over the Goldilocks field (p = 2^64 - 2^32 + 1) via plonky2
//! for ZK-friendly block header hashing. Legacy BN254 support is retained for
//! backward compatibility with blocks mined before the activation height.
//!
//! The header bytes are packed into Goldilocks field elements (7 bytes each),
//! then hashed via Poseidon sponge. The output (4 field elements = 32 bytes)
//! is used for numeric difficulty check (hash_prefix < u64::MAX / difficulty).
//!
//! Advantages over BN254 Poseidon:
//! - Native compatibility with plonky2 STARK proving (no field conversion)
//! - Faster: 64-bit field arithmetic vs 256-bit
//! - Consistent with the rest of TSN's ZK stack (Poseidon trees, circuits)

// --- Poseidon Goldilocks (current) ---
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field as PlonkyField, PrimeField64};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;

// --- Poseidon2 Goldilocks (plonky3, post-activation) ---
use p3_goldilocks::Goldilocks;
use p3_field::PrimeField64 as P3PrimeField64;
use p3_field::integers::QuotientMap;
use p3_poseidon2::ExternalLayerConstants;
use p3_goldilocks::{
    Poseidon2GoldilocksHL, HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS,
    HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS,
};
use p3_symmetric::{PaddingFreeSponge, CryptographicHasher};

// --- Legacy BN254 (for pre-activation blocks) ---
use ark_bn254::Fr;
use ark_ff::PrimeField;
use light_poseidon::{Poseidon, PoseidonHasher};

use crate::config::{POSEIDON2_ACTIVATION_HEIGHT, POSEIDON2_V2_ACTIVATION_HEIGHT};

/// Domain separation for PoW hashing (prevents cross-protocol attacks).
const DOMAIN_POW: u64 = 42;

/// Maximum number of field elements for a block header.
/// Header = version(4) + prev_hash(32) + merkle_root(32) + commitment_root(32)
///        + nullifier_root(32) + timestamp(8) + difficulty(8) + nonce(64) = 212 bytes
/// At 7 bytes per Goldilocks field element: ceil(212/7) = 31 elements + 1 domain = 32 total
#[allow(dead_code)]
const MAX_HEADER_ELEMENTS: usize = 32;

// =============================================================================
// Goldilocks Poseidon (current implementation)
// =============================================================================

/// Pack arbitrary bytes into Goldilocks field elements (7 bytes per element).
///
/// Each chunk of 7 bytes is interpreted as a little-endian u64.
/// 7 bytes = 56 bits, which is well under the Goldilocks modulus
/// (p = 2^64 - 2^32 + 1 ≈ 1.8 × 10^19), so no modular reduction needed.
fn bytes_to_goldilocks(data: &[u8]) -> Vec<GoldilocksField> {
    let mut elements = Vec::new();
    for chunk in data.chunks(7) {
        let mut val: u64 = 0;
        for (i, &byte) in chunk.iter().enumerate() {
            val |= (byte as u64) << (i * 8);
        }
        elements.push(GoldilocksField::from_canonical_u64(val));
    }
    elements
}

/// Hash a block header using Poseidon over Goldilocks field (ZK-friendly PoW).
///
/// Takes the raw header bytes, packs them into Goldilocks field elements,
/// prepends a domain separator, and returns a 32-byte hash suitable for
/// difficulty checking.
pub fn poseidon_hash_header(header_bytes: &[u8]) -> [u8; 32] {
    let elements = bytes_to_goldilocks(header_bytes);

    // Build input: domain separator + header elements
    let mut inputs = Vec::with_capacity(elements.len() + 1);
    inputs.push(GoldilocksField::from_canonical_u64(DOMAIN_POW));
    inputs.extend_from_slice(&elements);

    // Poseidon hash → HashOut<GoldilocksField> with 4 elements
    let hash_out = PoseidonHash::hash_no_pad(&inputs);

    // Convert 4 × GoldilocksField (each 8 bytes LE) → [u8; 32]
    let mut result = [0u8; 32];
    for (i, &elem) in hash_out.elements.iter().enumerate() {
        let bytes = elem.to_canonical_u64().to_le_bytes();
        result[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }
    result
}

/// Hash a block header from its individual components (optimized for mining).
///
/// The prefix (version + roots) is constant during mining, only timestamp/difficulty/nonce change.
/// This avoids re-serializing the full header on each attempt.
/// The nonce is 64 bytes (512 bits).
pub fn poseidon_hash_header_parts(
    version: u32,
    prev_hash: &[u8; 32],
    merkle_root: &[u8; 32],
    commitment_root: &[u8; 32],
    nullifier_root: &[u8; 32],
    timestamp: u64,
    difficulty: u64,
    nonce: &[u8; 64],
) -> [u8; 32] {
    let mut header_bytes = Vec::with_capacity(212);
    header_bytes.extend_from_slice(&version.to_le_bytes());
    header_bytes.extend_from_slice(prev_hash);
    header_bytes.extend_from_slice(merkle_root);
    header_bytes.extend_from_slice(commitment_root);
    header_bytes.extend_from_slice(nullifier_root);
    header_bytes.extend_from_slice(&timestamp.to_le_bytes());
    header_bytes.extend_from_slice(&difficulty.to_le_bytes());
    header_bytes.extend_from_slice(nonce);

    poseidon_hash_header(&header_bytes)
}

/// Same as `poseidon_hash_header_parts` but height-aware for backward compatibility.
pub fn poseidon_hash_header_parts_for_height(
    version: u32,
    prev_hash: &[u8; 32],
    merkle_root: &[u8; 32],
    commitment_root: &[u8; 32],
    nullifier_root: &[u8; 32],
    timestamp: u64,
    difficulty: u64,
    nonce: &[u8; 64],
    height: u64,
) -> [u8; 32] {
    let mut header_bytes = Vec::with_capacity(212);
    header_bytes.extend_from_slice(&version.to_le_bytes());
    header_bytes.extend_from_slice(prev_hash);
    header_bytes.extend_from_slice(merkle_root);
    header_bytes.extend_from_slice(commitment_root);
    header_bytes.extend_from_slice(nullifier_root);
    header_bytes.extend_from_slice(&timestamp.to_le_bytes());
    header_bytes.extend_from_slice(&difficulty.to_le_bytes());
    header_bytes.extend_from_slice(nonce);

    poseidon_hash_header_for_height(&header_bytes, height)
}

// =============================================================================
// Goldilocks Poseidon2 (plonky3, post-activation at POSEIDON2_V2_ACTIVATION_HEIGHT)
// =============================================================================

/// Pack arbitrary bytes into p3 Goldilocks field elements (7 bytes per element).
/// Same packing as Poseidon v1 — same field, same representation.
fn bytes_to_p3_goldilocks(data: &[u8]) -> Vec<Goldilocks> {
    let mut elements = Vec::new();
    for chunk in data.chunks(7) {
        let mut val: u64 = 0;
        for (i, &byte) in chunk.iter().enumerate() {
            val |= (byte as u64) << (i * 8);
        }
        elements.push(<Goldilocks as QuotientMap<u64>>::from_int(val));
    }
    elements
}

/// Build a deterministic Poseidon2 sponge using the Horizen Labs constants
/// for Goldilocks width-8. Returns a PaddingFreeSponge with rate=4, output=4.
fn make_poseidon2_sponge() -> PaddingFreeSponge<Poseidon2GoldilocksHL<8>, 8, 4, 4> {
    let perm: Poseidon2GoldilocksHL<8> = p3_poseidon2::Poseidon2::new(
        ExternalLayerConstants::<Goldilocks, 8>::new_from_saved_array(
            HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS,
            Goldilocks::new_array,
        ),
        Goldilocks::new_array(HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS).to_vec(),
    );
    PaddingFreeSponge::new(perm)
}

lazy_static::lazy_static! {
    /// Global Poseidon2 sponge instance (deterministic, built from published constants).
    static ref POSEIDON2_SPONGE: PaddingFreeSponge<Poseidon2GoldilocksHL<8>, 8, 4, 4> =
        make_poseidon2_sponge();
}

/// Hash a block header using Poseidon2 over Goldilocks field (plonky3).
///
/// Uses the Horizen Labs Poseidon2 constants for the Goldilocks field with
/// width=8, rate=4, output=4 field elements (32 bytes).
pub fn poseidon_hash_header_v2(header_bytes: &[u8]) -> [u8; 32] {
    let elements = bytes_to_p3_goldilocks(header_bytes);

    let mut inputs = Vec::with_capacity(elements.len() + 1);
    inputs.push(<Goldilocks as QuotientMap<u64>>::from_int(DOMAIN_POW));
    inputs.extend_from_slice(&elements);

    let hash_out: [Goldilocks; 4] = POSEIDON2_SPONGE.hash_slice(&inputs);

    let mut result = [0u8; 32];
    for (i, elem) in hash_out.iter().enumerate() {
        result[i * 8..(i + 1) * 8].copy_from_slice(&elem.as_canonical_u64().to_le_bytes());
    }
    result
}

/// Hash a block header from its individual components using Poseidon2 (optimized for mining).
pub fn poseidon_hash_header_parts_v2(
    version: u32,
    prev_hash: &[u8; 32],
    merkle_root: &[u8; 32],
    commitment_root: &[u8; 32],
    nullifier_root: &[u8; 32],
    timestamp: u64,
    difficulty: u64,
    nonce: &[u8; 64],
) -> [u8; 32] {
    let mut header_bytes = Vec::with_capacity(212);
    header_bytes.extend_from_slice(&version.to_le_bytes());
    header_bytes.extend_from_slice(prev_hash);
    header_bytes.extend_from_slice(merkle_root);
    header_bytes.extend_from_slice(commitment_root);
    header_bytes.extend_from_slice(nullifier_root);
    header_bytes.extend_from_slice(&timestamp.to_le_bytes());
    header_bytes.extend_from_slice(&difficulty.to_le_bytes());
    header_bytes.extend_from_slice(nonce);
    poseidon_hash_header_v2(&header_bytes)
}

/// Pre-allocated mining context for fast Poseidon2 hashing.
/// Keeps a reusable 212-byte header buffer to avoid allocations in the hot loop.
/// Only the nonce bytes (148..212) change each iteration.
#[derive(Clone)]
pub struct MiningHashContext {
    /// Pre-built header bytes (212 bytes). Only nonce portion changes.
    header_bytes: [u8; 212],
}

impl MiningHashContext {
    /// Create a new mining context from the fixed header fields.
    pub fn new(
        version: u32,
        prev_hash: &[u8; 32],
        merkle_root: &[u8; 32],
        commitment_root: &[u8; 32],
        nullifier_root: &[u8; 32],
    ) -> Self {
        let mut header_bytes = [0u8; 212];
        header_bytes[0..4].copy_from_slice(&version.to_le_bytes());
        header_bytes[4..36].copy_from_slice(prev_hash);
        header_bytes[36..68].copy_from_slice(merkle_root);
        header_bytes[68..100].copy_from_slice(commitment_root);
        header_bytes[100..132].copy_from_slice(nullifier_root);
        // timestamp (132..140), difficulty (140..148), nonce (148..212) set per-hash
        Self { header_bytes }
    }

    /// Hash with the given variable fields. Zero heap allocations in hot path.
    #[inline]
    pub fn hash(&self, timestamp: u64, difficulty: u64, nonce: &[u8; 64]) -> [u8; 32] {
        let mut buf = self.header_bytes;
        buf[132..140].copy_from_slice(&timestamp.to_le_bytes());
        buf[140..148].copy_from_slice(&difficulty.to_le_bytes());
        buf[148..212].copy_from_slice(nonce);
        poseidon_hash_header_v2(&buf)
    }

    /// Check if the hash meets the difficulty target.
    #[inline]
    pub fn meets_difficulty(&self, timestamp: u64, difficulty: u64, nonce: &[u8; 64]) -> bool {
        hash_meets_difficulty(&self.hash(timestamp, difficulty, nonce), difficulty)
    }
}

// =============================================================================
// Height-aware hashing (backward compatibility)
// =============================================================================

/// Hash a block header using the appropriate algorithm for the given height.
///
/// - For `height < POSEIDON2_ACTIVATION_HEIGHT`: uses legacy BN254 Poseidon
/// - For `height < POSEIDON2_V2_ACTIVATION_HEIGHT`: uses Goldilocks Poseidon v1 (plonky2)
/// - For `height >= POSEIDON2_V2_ACTIVATION_HEIGHT`: uses Goldilocks Poseidon2 (plonky3)
///
/// This ensures backward compatibility during chain sync for blocks mined
/// before each activation height.
pub fn poseidon_hash_header_for_height(header_bytes: &[u8], height: u64) -> [u8; 32] {
    if height < POSEIDON2_ACTIVATION_HEIGHT {
        poseidon_hash_header_legacy(header_bytes)
    } else if height < POSEIDON2_V2_ACTIVATION_HEIGHT {
        poseidon_hash_header(header_bytes)
    } else {
        poseidon_hash_header_v2(header_bytes)
    }
}

// =============================================================================
// Legacy BN254 implementation (for pre-activation blocks)
// =============================================================================

/// Pack arbitrary bytes into BN254 field elements (31 bytes per element, big-endian).
///
/// Each chunk of 31 bytes is interpreted as a big-endian integer < p (BN254 scalar field order).
/// 31 bytes guarantees the value fits in the ~254-bit field.
fn bytes_to_field_elements_legacy(data: &[u8]) -> Vec<Fr> {
    let mut elements = Vec::new();
    for chunk in data.chunks(31) {
        let mut padded = [0u8; 32];
        padded[32 - chunk.len()..].copy_from_slice(chunk);
        elements.push(Fr::from_be_bytes_mod_order(&padded));
    }
    elements
}

/// Convert a BN254 field element to 32 bytes (big-endian representation).
fn field_element_to_bytes_legacy(fe: &Fr) -> [u8; 32] {
    let bigint = fe.into_bigint();
    let limbs = bigint.0; // [u64; 4] in little-endian limb order
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        bytes[24 - i * 8..32 - i * 8].copy_from_slice(&limb.to_be_bytes());
    }
    bytes
}

/// Hash a block header using legacy BN254 Poseidon (for pre-activation blocks).
pub fn poseidon_hash_header_legacy(header_bytes: &[u8]) -> [u8; 32] {
    let elements = bytes_to_field_elements_legacy(header_bytes);

    let n_inputs = elements.len() + 1;

    let mut poseidon = Poseidon::<Fr>::new_circom(n_inputs)
        .expect("BUG: Poseidon init failed — header produces 1..=7 field elements");

    let mut all_inputs = vec![Fr::from(DOMAIN_POW)];
    all_inputs.extend_from_slice(&elements);

    let hash = poseidon.hash(&all_inputs)
        .expect("BUG: Poseidon hash failed — input count matches init");
    field_element_to_bytes_legacy(&hash)
}

// =============================================================================
// Difficulty checking (numeric difficulty, algorithm-independent)
// =============================================================================

/// Check if a hash meets the numeric difficulty target.
///
/// Interprets the first 8 bytes of the hash as a big-endian u64 and checks
/// that this value is less than u64::MAX / difficulty.
/// Higher difficulty = smaller target = harder to mine.
///
/// For difficulty 0, always returns true.
/// For difficulty 1, nearly all hashes pass.
/// For difficulty 10000, roughly 1 in 10000 hashes pass.
pub fn hash_meets_difficulty(hash: &[u8; 32], difficulty: u64) -> bool {
    // M1 audit fix: difficulty 0 is invalid — no block should pass with zero difficulty
    if difficulty == 0 {
        return false;
    }
    let hash_prefix = u64::from_be_bytes(hash[0..8].try_into().unwrap());
    let target = u64::MAX / difficulty;
    hash_prefix < target
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_pow_deterministic() {
        let header = [0u8; 156];
        let hash1 = poseidon_hash_header(&header);
        let hash2 = poseidon_hash_header(&header);
        assert_eq!(hash1, hash2, "Poseidon PoW must be deterministic");
    }

    #[test]
    fn test_poseidon_pow_different_inputs() {
        let header1 = [0u8; 156];
        let mut header2 = [0u8; 156];
        header2[155] = 1; // Different nonce
        let hash1 = poseidon_hash_header(&header1);
        let hash2 = poseidon_hash_header(&header2);
        assert_ne!(hash1, hash2, "Different inputs must produce different hashes");
    }

    #[test]
    fn test_poseidon_pow_parts() {
        let nonce = [42u8; 64];
        let hash = poseidon_hash_header_parts(
            2, &[0u8; 32], &[1u8; 32], &[2u8; 32], &[3u8; 32],
            1000, 8, &nonce,
        );
        assert_ne!(hash, [0u8; 32], "Hash should not be zero");
    }

    #[test]
    fn test_hash_meets_difficulty() {
        // A hash starting with 0x00 should meet low difficulties
        let mut hash = [0u8; 32];
        hash[0] = 0x00;
        hash[1] = 0x01;
        // hash_prefix = 0x0001_0000_0000_0000 = 281474976710656
        // u64::MAX / 1 = 18446744073709551615 → passes
        assert!(hash_meets_difficulty(&hash, 1));
        // u64::MAX / 10000 = 1844674407370955 → 281474976710656 < 1844674407370955 → passes
        assert!(hash_meets_difficulty(&hash, 10000));
        // u64::MAX / 100000 = 184467440737095 → 281474976710656 > 184467440737095 → fails
        assert!(!hash_meets_difficulty(&hash, 100000));

        // Zero difficulty is invalid (M1 audit fix) — always rejects
        let full_hash = [0xFF; 32];
        assert!(!hash_meets_difficulty(&full_hash, 0));
    }

    #[test]
    fn test_bytes_to_goldilocks() {
        // 7 bytes should produce exactly 1 field element
        let data = vec![42u8; 7];
        let elements = bytes_to_goldilocks(&data);
        assert_eq!(elements.len(), 1);

        // 8 bytes should produce 2 field elements
        let data = vec![42u8; 8];
        let elements = bytes_to_goldilocks(&data);
        assert_eq!(elements.len(), 2);

        // 156 bytes (full header) should produce ceil(156/7) = 23 elements
        let data = vec![0u8; 156];
        let elements = bytes_to_goldilocks(&data);
        assert_eq!(elements.len(), 23);
    }

    #[test]
    fn test_goldilocks_no_overflow() {
        // Max 7-byte value: 0xFF_FF_FF_FF_FF_FF_FF = 2^56 - 1
        // Goldilocks modulus: 2^64 - 2^32 + 1
        // 2^56 - 1 < 2^64 - 2^32 + 1, so no overflow
        let data = vec![0xFF; 7];
        let elements = bytes_to_goldilocks(&data);
        assert_eq!(elements.len(), 1);
        let val = elements[0].to_canonical_u64();
        assert_eq!(val, (1u64 << 56) - 1);
    }

    #[test]
    fn test_hash_produces_32_bytes() {
        let header = [0u8; 156];
        let hash = poseidon_hash_header(&header);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_legacy_still_works() {
        // Legacy BN254 should still produce deterministic hashes
        let header = [0u8; 156];
        let hash1 = poseidon_hash_header_legacy(&header);
        let hash2 = poseidon_hash_header_legacy(&header);
        assert_eq!(hash1, hash2, "Legacy Poseidon must be deterministic");
    }

    #[test]
    fn test_legacy_differs_from_goldilocks() {
        // The two algorithms should produce different hashes for the same input
        let header = [0u8; 156];
        let legacy = poseidon_hash_header_legacy(&header);
        let goldilocks = poseidon_hash_header(&header);
        assert_ne!(legacy, goldilocks, "Legacy and Goldilocks hashes must differ");
    }

    #[test]
    fn test_height_routing() {
        let header = [0u8; 156];

        if POSEIDON2_V2_ACTIVATION_HEIGHT == 0 {
            // All heights use Poseidon2 v2 when V2 activates at genesis
            let h0 = poseidon_hash_header_for_height(&header, 0);
            let direct_v2 = poseidon_hash_header_v2(&header);
            assert_eq!(h0, direct_v2);
        } else if POSEIDON2_ACTIVATION_HEIGHT == 0 {
            // Heights below V2 use Goldilocks v1, post-V2 uses Poseidon2
            let h0 = poseidon_hash_header_for_height(&header, 0);
            let direct = poseidon_hash_header(&header);
            assert_eq!(h0, direct);

            let v2 = poseidon_hash_header_for_height(&header, POSEIDON2_V2_ACTIVATION_HEIGHT);
            let direct_v2 = poseidon_hash_header_v2(&header);
            assert_eq!(v2, direct_v2);
        } else {
            // Pre-activation uses legacy, post-V2 uses Poseidon2
            let pre = poseidon_hash_header_for_height(&header, 0);
            let legacy = poseidon_hash_header_legacy(&header);
            assert_eq!(pre, legacy);

            let v2 = poseidon_hash_header_for_height(&header, POSEIDON2_V2_ACTIVATION_HEIGHT);
            let direct_v2 = poseidon_hash_header_v2(&header);
            assert_eq!(v2, direct_v2);
        }
    }

    // =============================================================================
    // Poseidon2 (plonky3) tests
    // =============================================================================

    #[test]
    fn test_poseidon2_v2_deterministic() {
        let header = [0u8; 156];
        let hash1 = poseidon_hash_header_v2(&header);
        let hash2 = poseidon_hash_header_v2(&header);
        assert_eq!(hash1, hash2, "Poseidon2 v2 PoW must be deterministic");
    }

    #[test]
    fn test_poseidon2_v2_different_inputs() {
        let header1 = [0u8; 156];
        let mut header2 = [0u8; 156];
        header2[155] = 1; // Different nonce
        let hash1 = poseidon_hash_header_v2(&header1);
        let hash2 = poseidon_hash_header_v2(&header2);
        assert_ne!(hash1, hash2, "Different inputs must produce different hashes");
    }

    #[test]
    fn test_poseidon2_v2_produces_32_bytes() {
        let header = [0u8; 156];
        let hash = poseidon_hash_header_v2(&header);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_poseidon2_v2_differs_from_v1() {
        let header = [0u8; 156];
        let v1 = poseidon_hash_header(&header);
        let v2 = poseidon_hash_header_v2(&header);
        assert_ne!(v1, v2, "Poseidon v1 and Poseidon2 v2 hashes must differ");
    }

    #[test]
    fn test_poseidon2_v2_parts() {
        let nonce = [42u8; 64];
        let hash = poseidon_hash_header_parts_v2(
            2, &[0u8; 32], &[1u8; 32], &[2u8; 32], &[3u8; 32],
            1000, 8, &nonce,
        );
        assert_ne!(hash, [0u8; 32], "Hash should not be zero");

        // Parts function should match manual byte construction
        let mut header_bytes = Vec::with_capacity(212);
        header_bytes.extend_from_slice(&2u32.to_le_bytes());
        header_bytes.extend_from_slice(&[0u8; 32]);
        header_bytes.extend_from_slice(&[1u8; 32]);
        header_bytes.extend_from_slice(&[2u8; 32]);
        header_bytes.extend_from_slice(&[3u8; 32]);
        header_bytes.extend_from_slice(&1000u64.to_le_bytes());
        header_bytes.extend_from_slice(&8u64.to_le_bytes());
        header_bytes.extend_from_slice(&nonce);
        let hash_direct = poseidon_hash_header_v2(&header_bytes);
        assert_eq!(hash, hash_direct, "Parts and direct must produce same hash");
    }

    #[test]
    fn test_bytes_to_p3_goldilocks() {
        // 7 bytes should produce exactly 1 field element
        let data = vec![42u8; 7];
        let elements = bytes_to_p3_goldilocks(&data);
        assert_eq!(elements.len(), 1);

        // 8 bytes should produce 2 field elements
        let data = vec![42u8; 8];
        let elements = bytes_to_p3_goldilocks(&data);
        assert_eq!(elements.len(), 2);

        // 156 bytes (full header) should produce ceil(156/7) = 23 elements
        let data = vec![0u8; 156];
        let elements = bytes_to_p3_goldilocks(&data);
        assert_eq!(elements.len(), 23);
    }

}
