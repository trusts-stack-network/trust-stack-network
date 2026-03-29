//! Commitment schemes for hiding note values and creating note commitments.
//!
//! Uses Pedersen commitments on BLS12-381 for value commitments (homomorphic)
//! and Poseidon for note commitments (efficient in circuits).

use ark_bn254::{Fr, G1Projective as G1};
use ark_ec::Group;
use ark_ff::{Field, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};

use super::poseidon::{poseidon_hash, bytes32_to_field, field_to_bytes32, DOMAIN_NOTE_COMMITMENT};

/// A commitment to a note (value || recipient_pk_hash || randomness).
/// This is what gets stored in the commitment tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NoteCommitment(pub [u8; 32]);

impl NoteCommitment {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Convert to field element for use in circuits.
    pub fn to_field_element(&self) -> Fr {
        Fr::from_le_bytes_mod_order(&self.0)
    }
}

impl Default for NoteCommitment {
    fn default() -> Self {
        Self([0u8; 32])
    }
}

impl AsRef<[u8]> for NoteCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A Pedersen commitment to a value. Used for balance verification.
/// Commitment = value * G + randomness * H
/// where G and H are independent generators on BLS12-381 G1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValueCommitment {
    pub commitment: G1,
    pub randomness: Fr,
}

impl ValueCommitment {
    /// Serialize to bytes for storage/transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.commitment.serialize_compressed(&mut bytes).unwrap();
        bytes
    }

    /// Get the commitment point as a 48-byte compressed representation.
    pub fn commitment_bytes(&self) -> [u8; 48] {
        let mut bytes = [0u8; 48];
        self.commitment.serialize_compressed(&mut bytes[..]).unwrap();
        bytes
    }

    /// Get a 32-byte hash of the commitment for compact storage.
    /// This is a binding commitment that can be used for verification.
    pub fn commitment_hash(&self) -> [u8; 32] {
        let mut hasher = Blake2s256::new();
        hasher.update(b"TSN_ValueCommitmentHash");
        hasher.update(&self.commitment_bytes());
        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }

    /// Deserialize from compressed bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        let commitment = G1::deserialize_compressed(bytes)
            .map_err(|_| "Failed to deserialize commitment")?;
        Ok(Self {
            commitment,
            randomness: Fr::ZERO, // Unknown when deserializing
        })
    }
}

impl Serialize for ValueCommitment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.to_bytes();
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for ValueCommitment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// Hash-to-curve using try-and-increment (Elligator-like).
/// Derives a curve point from a domain tag such that the discrete log
/// relative to other generators is unknown. This is critical for Pedersen
/// commitment binding: if log_G(H) were known, an attacker could forge
/// commitments and inflate the supply.
///
/// Method: Hash(tag || counter) → x-coordinate, test if on curve, increment counter.
/// This is deterministic and produces a valid G1 point with unknown discrete log
/// relative to the standard generator or any other hash-derived point.
fn hash_to_curve_g1(domain_tag: &[u8]) -> G1 {
    use ark_bn254::{Fq, G1Affine};
    use ark_ec::AffineRepr;

    for counter in 0u32..256 {
        let mut hasher = Blake2s256::new();
        hasher.update(domain_tag);
        hasher.update(&counter.to_le_bytes());
        let hash = hasher.finalize();

        // Interpret hash as x-coordinate on BN254 G1
        let x = Fq::from_le_bytes_mod_order(&hash);

        // Try to decompress: find y such that y² = x³ + 3 (BN254 curve equation)
        if let Some(point) = G1Affine::get_point_from_x_unchecked(x, false) {
            // Ensure point is on the curve and in the correct subgroup
            if point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve() {
                let projective: G1 = point.into();
                // Ensure not the identity point
                if projective != G1::default() {
                    return projective;
                }
            }
        }
    }
    // Statistically impossible to reach here with a good hash function
    panic!("BUG: hash_to_curve failed after 256 attempts — should never happen");
}

lazy_static::lazy_static! {
    // Generator points for Pedersen commitment.
    // These are fixed points on BN254 derived via hash-to-curve (try-and-increment).
    // The discrete log between G and H is UNKNOWN by construction — this is critical
    // for the binding property of Pedersen commitments.
    //
    // SECURITY: Previously used scalar*Generator which made log_G(H) = s_H/s_G publicly
    // computable, breaking binding. Fixed in v0.7.1 audit remediation.

    /// Generator G for value component: hash-to-curve("TSN_PedersenG_v2")
    pub static ref VALUE_GENERATOR_G: G1 = {
        hash_to_curve_g1(b"TSN_PedersenG_v2")
    };

    /// Generator H for randomness component: hash-to-curve("TSN_PedersenH_v2")
    pub static ref VALUE_GENERATOR_H: G1 = {
        hash_to_curve_g1(b"TSN_PedersenH_v2")
    };
}

/// Create a Pedersen commitment to a value.
/// Returns (commitment, randomness) where commitment = value * G + randomness * H.
pub fn commit_to_value<R: RngCore>(value: u64, rng: &mut R) -> ValueCommitment {
    let randomness = Fr::rand(rng);
    let value_scalar = Fr::from(value);
    let commitment = *VALUE_GENERATOR_G * value_scalar + *VALUE_GENERATOR_H * randomness;

    ValueCommitment {
        commitment,
        randomness,
    }
}

/// Create a Pedersen commitment to a value with a specific randomness.
/// Used when we need to control the randomness (e.g., for binding signatures).
pub fn commit_to_value_with_randomness(value: u64, randomness: Fr) -> ValueCommitment {
    let value_scalar = Fr::from(value);
    let commitment = *VALUE_GENERATOR_G * value_scalar + *VALUE_GENERATOR_H * randomness;

    ValueCommitment {
        commitment,
        randomness,
    }
}

/// Create a note commitment using Poseidon hash.
/// cm = Poseidon(DOMAIN_NOTE_COMMITMENT, value, pk_hash, randomness)
///
/// This is a binding and hiding commitment to the note contents.
/// Using Poseidon ensures efficient verification in zk-SNARK circuits.
pub fn commit_to_note(value: u64, recipient_pk_hash: &[u8; 32], randomness: &Fr) -> NoteCommitment {
    // Convert all inputs to field elements
    let value_fe = Fr::from(value);
    let pk_hash_fe = bytes32_to_field(recipient_pk_hash);

    // Hash: Poseidon(domain, value, pk_hash, randomness)
    let hash = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[value_fe, pk_hash_fe, *randomness]);

    // Convert field element back to bytes
    let result = field_to_bytes32(&hash);

    NoteCommitment(result)
}

/// Verify that a value commitment is correctly formed (for testing).
pub fn verify_value_commitment(value: u64, commitment: &ValueCommitment) -> bool {
    let value_scalar = Fr::from(value);
    let expected = *VALUE_GENERATOR_G * value_scalar + *VALUE_GENERATOR_H * commitment.randomness;
    expected == commitment.commitment
}

/// Add two value commitments (homomorphic property).
/// commit(a) + commit(b) = commit(a + b) with combined randomness.
pub fn add_value_commitments(a: &ValueCommitment, b: &ValueCommitment) -> ValueCommitment {
    ValueCommitment {
        commitment: a.commitment + b.commitment,
        randomness: a.randomness + b.randomness,
    }
}

/// Subtract two value commitments.
/// commit(a) - commit(b) = commit(a - b) with difference in randomness.
pub fn sub_value_commitments(a: &ValueCommitment, b: &ValueCommitment) -> ValueCommitment {
    ValueCommitment {
        commitment: a.commitment - b.commitment,
        randomness: a.randomness - b.randomness,
    }
}

/// Negate a value commitment.
pub fn negate_value_commitment(c: &ValueCommitment) -> ValueCommitment {
    ValueCommitment {
        commitment: -c.commitment,
        randomness: -c.randomness,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::rngs::StdRng;

    #[test]
    fn test_value_commitment_roundtrip() {
        let mut rng = StdRng::seed_from_u64(12345);
        let value = 1000u64;
        let commitment = commit_to_value(value, &mut rng);

        assert!(verify_value_commitment(value, &commitment));
        assert!(!verify_value_commitment(value + 1, &commitment));
    }

    #[test]
    fn test_value_commitment_homomorphic() {
        let mut rng = StdRng::seed_from_u64(12345);
        let a = 100u64;
        let b = 200u64;

        let commit_a = commit_to_value(a, &mut rng);
        let commit_b = commit_to_value(b, &mut rng);
        let commit_sum = add_value_commitments(&commit_a, &commit_b);

        // The sum commitment should verify for a + b with combined randomness
        assert!(verify_value_commitment(a + b, &commit_sum));
    }

    #[test]
    fn test_note_commitment_deterministic() {
        let value = 1000u64;
        let pk_hash = [1u8; 32];
        let randomness = Fr::from(42u64);

        let cm1 = commit_to_note(value, &pk_hash, &randomness);
        let cm2 = commit_to_note(value, &pk_hash, &randomness);

        assert_eq!(cm1, cm2);
    }

    #[test]
    fn test_note_commitment_different_values() {
        let pk_hash = [1u8; 32];
        let randomness = Fr::from(42u64);

        let cm1 = commit_to_note(1000, &pk_hash, &randomness);
        let cm2 = commit_to_note(2000, &pk_hash, &randomness);

        assert_ne!(cm1, cm2);
    }

    #[test]
    fn test_value_commitment_serialization() {
        let mut rng = StdRng::seed_from_u64(12345);
        let commitment = commit_to_value(1000, &mut rng);

        let bytes = commitment.to_bytes();
        let recovered = ValueCommitment::from_bytes(&bytes).unwrap();

        assert_eq!(commitment.commitment, recovered.commitment);
    }
}
