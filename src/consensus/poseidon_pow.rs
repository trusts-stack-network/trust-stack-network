//! Poseidon-based Proof-of-Work hash function.
//!
//! Uses Poseidon over the Goldilocks field (p = 2^64 - 2^32 + 1) via plonky2
//! for ZK-friendly block header hashing. Legacy BN254 support is retained for
//! backward compatibility with blocks mined before the activation height.
//!
//! The header bytes are packed into Goldilocks field elements (7 bytes each),
//! then hashed via Poseidon sponge. The output (4 field elements = 32 bytes)
//! is used for leading-zeros difficulty check.
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
///        + nullifier_root(32) + timestamp(8) + difficulty(8) + nonce(8) = 156 bytes
/// At 7 bytes per Goldilocks field element: ceil(156/7) = 23 elements + 1 domain = 24 total
#[allow(dead_code)]
const MAX_HEADER_ELEMENTS: usize = 24;

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
pub fn poseidon_hash_header_parts(
    version: u32,
    prev_hash: &[u8; 32],
    merkle_root: &[u8; 32],
    commitment_root: &[u8; 32],
    nullifier_root: &[u8; 32],
    timestamp: u64,
    difficulty: u64,
    nonce: u64,
) -> [u8; 32] {
    let mut header_bytes = Vec::with_capacity(156);
    header_bytes.extend_from_slice(&version.to_le_bytes());
    header_bytes.extend_from_slice(prev_hash);
    header_bytes.extend_from_slice(merkle_root);
    header_bytes.extend_from_slice(commitment_root);
    header_bytes.extend_from_slice(nullifier_root);
    header_bytes.extend_from_slice(&timestamp.to_le_bytes());
    header_bytes.extend_from_slice(&difficulty.to_le_bytes());
    header_bytes.extend_from_slice(&nonce.to_le_bytes());

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
    nonce: u64,
    height: u64,
) -> [u8; 32] {
    let mut header_bytes = Vec::with_capacity(156);
    header_bytes.extend_from_slice(&version.to_le_bytes());
    header_bytes.extend_from_slice(prev_hash);
    header_bytes.extend_from_slice(merkle_root);
    header_bytes.extend_from_slice(commitment_root);
    header_bytes.extend_from_slice(nullifier_root);
    header_bytes.extend_from_slice(&timestamp.to_le_bytes());
    header_bytes.extend_from_slice(&difficulty.to_le_bytes());
    header_bytes.extend_from_slice(&nonce.to_le_bytes());

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

    // Build input: domain separator + header elements
    let mut inputs = Vec::with_capacity(elements.len() + 1);
    inputs.push(<Goldilocks as QuotientMap<u64>>::from_int(DOMAIN_POW));
    inputs.extend_from_slice(&elements);

    // Hash through sponge → 4 Goldilocks elements
    let hash_out: [Goldilocks; 4] = POSEIDON2_SPONGE.hash_slice(&inputs);

    // Convert 4 × Goldilocks (each 8 bytes LE) → [u8; 32]
    let mut result = [0u8; 32];
    for (i, elem) in hash_out.iter().enumerate() {
        let bytes = elem.as_canonical_u64().to_le_bytes();
        result[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
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
    nonce: u64,
) -> [u8; 32] {
    let mut header_bytes = Vec::with_capacity(156);
    header_bytes.extend_from_slice(&version.to_le_bytes());
    header_bytes.extend_from_slice(prev_hash);
    header_bytes.extend_from_slice(merkle_root);
    header_bytes.extend_from_slice(commitment_root);
    header_bytes.extend_from_slice(nullifier_root);
    header_bytes.extend_from_slice(&timestamp.to_le_bytes());
    header_bytes.extend_from_slice(&difficulty.to_le_bytes());
    header_bytes.extend_from_slice(&nonce.to_le_bytes());
    poseidon_hash_header_v2(&header_bytes)
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
// Difficulty checking (algorithm-independent, works on raw bytes)
// =============================================================================

/// Count leading zero bits in a byte array.
pub fn count_leading_zeros(bytes: &[u8]) -> usize {
    let mut zeros = 0;
    for byte in bytes {
        if *byte == 0 {
            zeros += 8;
        } else {
            zeros += byte.leading_zeros() as usize;
            break;
        }
    }
    zeros
}

/// Check if a hash meets the difficulty target (leading zero bits >= difficulty).
pub fn meets_difficulty(hash: &[u8; 32], difficulty: u64) -> bool {
    count_leading_zeros(hash) >= difficulty as usize
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
        let hash = poseidon_hash_header_parts(
            2, &[0u8; 32], &[1u8; 32], &[2u8; 32], &[3u8; 32],
            1000, 8, 42,
        );
        assert_ne!(hash, [0u8; 32], "Hash should not be zero");
    }

    #[test]
    fn test_leading_zeros() {
        assert_eq!(count_leading_zeros(&[0x00, 0x00, 0xFF]), 16);
        assert_eq!(count_leading_zeros(&[0x0F, 0x00, 0x00]), 4);
        assert_eq!(count_leading_zeros(&[0x80, 0x00, 0x00]), 0);
        assert_eq!(count_leading_zeros(&[0x01, 0x00, 0x00]), 7);
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

        if POSEIDON2_ACTIVATION_HEIGHT == 0 {
            // Heights below V2 activation use Goldilocks v1
            let h0 = poseidon_hash_header_for_height(&header, 0);
            let direct = poseidon_hash_header(&header);
            assert_eq!(h0, direct);
        } else {
            // Pre-activation uses legacy
            let pre = poseidon_hash_header_for_height(&header, 0);
            let legacy = poseidon_hash_header_legacy(&header);
            assert_eq!(pre, legacy);

            // Post-activation uses Goldilocks v1
            let post = poseidon_hash_header_for_height(&header, POSEIDON2_ACTIVATION_HEIGHT);
            let goldilocks = poseidon_hash_header(&header);
            assert_eq!(post, goldilocks);
        }

        // Post V2 activation uses Poseidon2 (plonky3)
        let v2 = poseidon_hash_header_for_height(&header, POSEIDON2_V2_ACTIVATION_HEIGHT);
        let direct_v2 = poseidon_hash_header_v2(&header);
        assert_eq!(v2, direct_v2);
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
        let hash = poseidon_hash_header_parts_v2(
            2, &[0u8; 32], &[1u8; 32], &[2u8; 32], &[3u8; 32],
            1000, 8, 42,
        );
        assert_ne!(hash, [0u8; 32], "Hash should not be zero");

        // Parts function should match manual byte construction
        let mut header_bytes = Vec::with_capacity(156);
        header_bytes.extend_from_slice(&2u32.to_le_bytes());
        header_bytes.extend_from_slice(&[0u8; 32]);
        header_bytes.extend_from_slice(&[1u8; 32]);
        header_bytes.extend_from_slice(&[2u8; 32]);
        header_bytes.extend_from_slice(&[3u8; 32]);
        header_bytes.extend_from_slice(&1000u64.to_le_bytes());
        header_bytes.extend_from_slice(&8u64.to_le_bytes());
        header_bytes.extend_from_slice(&42u64.to_le_bytes());
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
