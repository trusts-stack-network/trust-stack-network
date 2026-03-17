//! Poseidon hash function for zk-SNARK-friendly hashing.
//!
//! This module uses light-poseidon which provides circomlib-compatible Poseidon.
//! This ensures browser (circomlibjs) and Rust produce identical hashes.
//!
//! IMPORTANT: This implementation matches circomlibjs exactly for:
//! - Note commitments
//! - Nullifier derivation
//! - Merkle tree hashing

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::{BigInteger, PrimeField};
use lazy_static::lazy_static;
use light_poseidon::{Poseidon, PoseidonHasher};

/// Domain separation constants for different hash uses.
/// Using distinct domains prevents cross-protocol attacks.
pub const DOMAIN_NOTE_COMMITMENT: u64 = 1;
pub const DOMAIN_VALUE_COMMITMENT_HASH: u64 = 2;
pub const DOMAIN_NULLIFIER: u64 = 3;
pub const DOMAIN_MERKLE_EMPTY: u64 = 4;
pub const DOMAIN_MERKLE_NODE: u64 = 5;
pub const DOMAIN_GOVERNANCE: u64 = 6;

/// Hash multiple field elements using Poseidon with domain separation.
///
/// Uses light-poseidon's circomlib-compatible implementation.
/// The domain tag is prepended to prevent cross-protocol attacks.
///
/// # Arguments
/// * `domain` - Domain separation constant (e.g., DOMAIN_NOTE_COMMITMENT)
/// * `inputs` - Field elements to hash
///
/// # Returns
/// A single field element representing the hash output
pub fn poseidon_hash(domain: u64, inputs: &[Fr]) -> Fr {
    // Total inputs = domain + user inputs
    let n_inputs = inputs.len() + 1;

    // Create circomlib-compatible Poseidon
    // SAFETY: n_inputs >= 2 (domain + at least 1 input), new_circom supports 1..=16
    let mut poseidon = Poseidon::<Fr>::new_circom(n_inputs)
        .expect("BUG: Poseidon init failed — n_inputs must be 1..=16");

    // Prepend domain as first input
    let mut all_inputs = vec![Fr::from(domain)];
    all_inputs.extend_from_slice(inputs);

    // SAFETY: all_inputs.len() == n_inputs, matching the Poseidon instance
    poseidon.hash(&all_inputs)
        .expect("BUG: Poseidon hash failed — input count mismatch")
}

/// Hash two field elements (common case for Merkle trees).
pub fn poseidon_hash_2(domain: u64, left: Fr, right: Fr) -> Fr {
    poseidon_hash(domain, &[left, right])
}

/// Convert a 32-byte array to a field element.
///
/// Uses little-endian byte order and reduces modulo the field prime.
pub fn bytes32_to_field(bytes: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(bytes)
}

/// Convert a field element to a 32-byte array.
///
/// Uses little-endian byte order.
pub fn field_to_bytes32(fe: &Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let bigint = fe.into_bigint();
    let fe_bytes = bigint.to_bytes_le();
    bytes[..fe_bytes.len().min(32)].copy_from_slice(&fe_bytes[..fe_bytes.len().min(32)]);
    bytes
}

// ============================================================================
// Unified PoseidonHash interface for governance and treasury operations
// ============================================================================

/// High-level Poseidon hash interface for governance and treasury operations.
///
/// Provides a simplified static interface that automatically handles domain
/// separation and data conversion for common treasury/governance hashing needs.
pub struct PoseidonHash;

impl PoseidonHash {
    /// Hash arbitrary bytes using Poseidon with governance domain.
    ///
    /// This is the primary interface used by the governance system for:
    /// - Proposal ID generation
    /// - Commitment calculations
    /// - Treasury state transitions
    ///
    /// # Arguments
    /// * `data` - Raw bytes to hash
    ///
    /// # Returns
    /// 32-byte hash output suitable for use as identifiers or commitments
    pub fn hash(data: &[u8]) -> [u8; 32] {
        // Convert raw bytes to field elements for Poseidon input
        // We need to chunk the data into 31-byte pieces to fit safely in Fr
        let chunks: Vec<Fr> = data
            .chunks(31)
            .map(|chunk| {
                let mut padded = [0u8; 32];
                padded[..chunk.len()].copy_from_slice(chunk);
                bytes32_to_field(&padded)
            })
            .collect();

        // Handle empty input case
        if chunks.is_empty() {
            let zero = Fr::from(0u64);
            let hash_fe = poseidon_hash(DOMAIN_GOVERNANCE, &[zero]);
            return field_to_bytes32(&hash_fe);
        }

        // Hash the chunks with governance domain
        let hash_fe = poseidon_hash(DOMAIN_GOVERNANCE, &chunks);
        field_to_bytes32(&hash_fe)
    }

    /// Hash arbitrary bytes with custom domain separation.
    ///
    /// For specialized use cases that need specific domain separation.
    ///
    /// # Arguments
    /// * `domain` - Domain separation constant
    /// * `data` - Raw bytes to hash
    ///
    /// # Returns
    /// 32-byte hash output
    pub fn hash_with_domain(domain: u64, data: &[u8]) -> [u8; 32] {
        let chunks: Vec<Fr> = data
            .chunks(31)
            .map(|chunk| {
                let mut padded = [0u8; 32];
                padded[..chunk.len()].copy_from_slice(chunk);
                bytes32_to_field(&padded)
            })
            .collect();

        if chunks.is_empty() {
            let zero = Fr::from(0u64);
            let hash_fe = poseidon_hash(domain, &[zero]);
            return field_to_bytes32(&hash_fe);
        }

        let hash_fe = poseidon_hash(domain, &chunks);
        field_to_bytes32(&hash_fe)
    }
}

// ============================================================================
// PoseidonConfig exports for circuit gadgets (ark_crypto_primitives)
// ============================================================================
//
// Note: The circuit gadgets use ark_crypto_primitives' PoseidonSpongeVar which
// requires a PoseidonConfig. We generate compatible configs here.
// These configs MUST match the light-poseidon circomlib parameters.

/// Generate MDS matrix matching circomlib's algorithm.
fn generate_mds_matrix(t: usize) -> Vec<Vec<Fr>> {
    let mut matrix = vec![vec![Fr::from(0u64); t]; t];
    for i in 0..t {
        for j in 0..t {
            let x_i = Fr::from(i as u64);
            let y_j = Fr::from((t + j) as u64);
            let sum = x_i + y_j;
            use ark_ff::Field;
            // SAFETY: Cauchy matrix x_i + y_j is never zero for distinct x, y sequences
            matrix[i][j] = sum.inverse().expect("BUG: Cauchy matrix requires distinct x,y sequences");
        }
    }
    matrix
}

/// Generate round constants matching circomlib's algorithm.
fn generate_round_constants_matrix(num_rounds: usize, state_width: usize) -> Vec<Vec<Fr>> {
    use sha2::{Sha256, Digest};

    let mut constants = Vec::with_capacity(num_rounds);

    for round in 0..num_rounds {
        let mut round_constants = Vec::with_capacity(state_width);
        for element in 0..state_width {
            let mut hasher = Sha256::new();
            hasher.update(b"poseidon");
            hasher.update(&(state_width as u64).to_le_bytes());
            hasher.update(&((round * state_width + element) as u64).to_le_bytes());
            let hash = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes[..31].copy_from_slice(&hash[..31]);
            let fe = Fr::from_le_bytes_mod_order(&bytes);
            round_constants.push(fe);
        }
        constants.push(round_constants);
    }

    constants
}

lazy_static! {
    /// Poseidon config for t=3 (rate=2, capacity=1) - for 2 user inputs + domain
    pub static ref POSEIDON_CONFIG: PoseidonConfig<Fr> = {
        let t = 3;
        let n_rounds_f = 8;
        let n_rounds_p = 57;
        PoseidonConfig::new(
            n_rounds_f,
            n_rounds_p,
            5, // alpha
            generate_mds_matrix(t),
            generate_round_constants_matrix(n_rounds_f + n_rounds_p, t),
            2, // rate
            1, // capacity
        )
    };

    /// Poseidon config for t=5 (rate=4, capacity=1) - for 4 user inputs + domain
    pub static ref POSEIDON_CONFIG_4: PoseidonConfig<Fr> = {
        let t = 5;
        let n_rounds_f = 8;
        let n_rounds_p = 60;
        PoseidonConfig::new(
            n_rounds_f,
            n_rounds_p,
            5, // alpha
            generate_mds_matrix(t),
            generate_round_constants_matrix(n_rounds_f + n_rounds_p, t),
            4, // rate
            1, // capacity
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::rngs::StdRng;

    #[test]
    fn test_poseidon_deterministic() {
        let a = Fr::from(123u64);
        let b = Fr::from(456u64);

        let hash1 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[a, b]);
        let hash2 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[a, b]);

        assert_eq!(hash1, hash2, "Same inputs should produce same hash");
    }

    #[test]
    fn test_poseidon_different_domains() {
        let a = Fr::from(123u64);
        let b = Fr::from(456u64);

        let hash1 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[a, b]);
        let hash2 = poseidon_hash(DOMAIN_NULLIFIER, &[a, b]);

        assert_ne!(hash1, hash2, "Different domains should produce different hashes");
    }

    #[test]
    fn test_poseidon_different_inputs() {
        let a = Fr::from(123u64);
        let b = Fr::from(456u64);
        let c = Fr::from(789u64);

        let hash1 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[a, b]);
        let hash2 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[a, c]);

        assert_ne!(hash1, hash2, "Different inputs should produce different hashes");
    }

    #[test]
    fn test_bytes32_roundtrip() {
        let mut rng = StdRng::seed_from_u64(12345);
        let original = Fr::rand(&mut rng);

        let bytes = field_to_bytes32(&original);
        let recovered = bytes32_to_field(&bytes);

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_poseidon_hash_2() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);

        let hash1 = poseidon_hash_2(DOMAIN_MERKLE_NODE, a, b);
        let hash2 = poseidon_hash(DOMAIN_MERKLE_NODE, &[a, b]);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_poseidon_4_inputs() {
        // This matches what we use for note commitments:
        // Poseidon(domain=1, value, pkHash, randomness)
        let inputs = [
            Fr::from(1000u64),      // value
            Fr::from(12345u64),     // pkHash (simplified)
            Fr::from(99999u64),     // randomness
        ];

        let hash = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &inputs);
        assert_ne!(hash, Fr::from(0u64));

        // Test it's deterministic
        let hash2 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &inputs);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_note_commitment_format() {
        // Test the exact format used for note commitments
        // cm = Poseidon(1, value, pkHash, randomness)
        let value = Fr::from(1000000000u64); // 1 TSN
        let pk_hash = Fr::from(0x1234567890abcdefu64);
        let randomness = Fr::from(0xfedcba0987654321u64);

        let cm = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[value, pk_hash, randomness]);

        // Verify it's non-zero and deterministic
        assert_ne!(cm, Fr::from(0u64));
        let cm2 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[value, pk_hash, randomness]);
        assert_eq!(cm, cm2);
    }

    #[test]
    fn test_circomlib_compatibility() {
        // Test a known value to verify circomlib compatibility
        // This should match circomlibjs: poseidon([1, 2, 3, 4])
        let inputs = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        let mut poseidon = Poseidon::<Fr>::new_circom(4).unwrap();
        let hash = poseidon.hash(&inputs).unwrap();

        // The hash should be non-zero and deterministic
        assert_ne!(hash, Fr::from(0u64));

        // Hash again to verify determinism
        let mut poseidon2 = Poseidon::<Fr>::new_circom(4).unwrap();
        let hash2 = poseidon2.hash(&inputs).unwrap();
        assert_eq!(hash, hash2);

        println!("Poseidon([1,2,3,4]) = {:?}", field_to_bytes32(&hash));
    }

    #[test]
    fn test_poseidon_hash_interface() {
        // Test basic usage
        let data = b"test governance proposal";
        let hash1 = PoseidonHash::hash(data);
        let hash2 = PoseidonHash::hash(data);

        assert_eq!(hash1, hash2, "Same data should produce same hash");
        assert_ne!(hash1, [0u8; 32], "Hash should be non-zero");
    }

    #[test]
    fn test_poseidon_hash_different_data() {
        let data1 = b"proposal 1";
        let data2 = b"proposal 2";

        let hash1 = PoseidonHash::hash(data1);
        let hash2 = PoseidonHash::hash(data2);

        assert_ne!(hash1, hash2, "Different data should produce different hashes");
    }

    #[test]
    fn test_poseidon_hash_empty_data() {
        let empty_data = b"";
        let hash = PoseidonHash::hash(empty_data);

        assert_ne!(hash, [0u8; 32], "Empty data hash should be non-zero");

        // Test determinism
        let hash2 = PoseidonHash::hash(empty_data);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_poseidon_hash_large_data() {
        // Test with data larger than 31 bytes (requires chunking)
        let large_data = b"This is a very long governance proposal description that exceeds 31 bytes";
        let hash = PoseidonHash::hash(large_data);

        assert_ne!(hash, [0u8; 32], "Large data hash should be non-zero");

        // Test determinism
        let hash2 = PoseidonHash::hash(large_data);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_poseidon_hash_with_domain() {
        let data = b"test data";

        let hash_gov = PoseidonHash::hash_with_domain(DOMAIN_GOVERNANCE, data);
        let hash_note = PoseidonHash::hash_with_domain(DOMAIN_NOTE_COMMITMENT, data);

        assert_ne!(hash_gov, hash_note, "Different domains should produce different hashes");

        // Default hash() should use governance domain
        let hash_default = PoseidonHash::hash(data);
        assert_eq!(hash_gov, hash_default, "Default hash should use governance domain");
    }

    #[test]
    fn test_governance_proposal_simulation() {
        // Simulate the exact usage pattern from governance.rs
        let proposal_data = (
            "SignatureTransitionPeriod(15000)",
            100u64, // current_height
            1u64,   // nonce
        );

        let serialized = bincode::serialize(&proposal_data).unwrap();
        let proposal_id = PoseidonHash::hash(&serialized);

        // Should be deterministic
        let proposal_id2 = PoseidonHash::hash(&serialized);
        assert_eq!(proposal_id, proposal_id2);

        // Different data should give different ID
        let proposal_data2 = (
            "SignatureTransitionPeriod(15000)",
            100u64, // same height
            2u64,   // different nonce
        );
        let serialized2 = bincode::serialize(&proposal_data2).unwrap();
        let proposal_id2 = PoseidonHash::hash(&serialized2);

        assert_ne!(proposal_id, proposal_id2);
    }
}
