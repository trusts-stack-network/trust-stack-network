//! Hash-based commitments for post-quantum security.
//!
//! This module replaces Pedersen commitments (vulnerable to quantum attacks)
//! with pure hash-based commitments using Poseidon over Goldilocks field.
//!
//! ## Security Model
//!
//! Hash-based commitments provide:
//! - **Hiding**: Cannot determine committed value from commitment (randomness)
//! - **Binding**: Cannot find two values with same commitment (collision resistance)
//!
//! Unlike Pedersen commitments, hash-based commitments are NOT homomorphic.
//! Balance verification must happen inside the ZK proof instead.
//!
//! ## Hash Format
//!
//! To match Plonky2's circuit, all hashes are 4 Goldilocks field elements (256 bits).
//! This is stored as 32 bytes in serialized form.

use serde::{Deserialize, Serialize};

use super::poseidon_pq::{
    poseidon_pq_hash, bytes_to_hash_out, hash_out_to_bytes, u64_to_goldilocks,
    DOMAIN_NOTE_COMMIT_PQ, DOMAIN_VALUE_COMMIT_PQ,
};

/// A hash-based value commitment (post-quantum secure).
///
/// Unlike Pedersen commitments, this is NOT homomorphic.
/// Balance verification happens in the STARK proof instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueCommitmentPQ {
    /// The commitment hash.
    #[serde(with = "hex_bytes_32")]
    pub commitment: [u8; 32],
}

impl ValueCommitmentPQ {
    /// Create a new value commitment.
    ///
    /// commitment = Poseidon(DOMAIN_VALUE_COMMIT_PQ, value, randomness)
    pub fn commit(value: u64, randomness: &[u8; 32]) -> Self {
        let commitment = commit_to_value_pq(value, randomness);
        Self { commitment }
    }

    /// Get the commitment as bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.commitment
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { commitment: bytes }
    }

    /// Verify that a commitment matches a value and randomness.
    /// Used during proof generation to verify our own commitments.
    pub fn verify(&self, value: u64, randomness: &[u8; 32]) -> bool {
        let expected = commit_to_value_pq(value, randomness);
        self.commitment == expected
    }
}

impl AsRef<[u8; 32]> for ValueCommitmentPQ {
    fn as_ref(&self) -> &[u8; 32] {
        &self.commitment
    }
}

impl From<[u8; 32]> for ValueCommitmentPQ {
    fn from(bytes: [u8; 32]) -> Self {
        Self { commitment: bytes }
    }
}

/// A hash-based note commitment (post-quantum secure).
///
/// Commits to: (value, recipient_pk_hash, randomness)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NoteCommitmentPQ(#[serde(with = "hex_bytes_32")] pub [u8; 32]);

impl NoteCommitmentPQ {
    /// Create a new note commitment.
    ///
    /// commitment = Poseidon(DOMAIN_NOTE_COMMIT_PQ, value, pk_hash, randomness)
    pub fn commit(value: u64, recipient_pk_hash: &[u8; 32], randomness: &[u8; 32]) -> Self {
        let commitment = commit_to_note_pq(value, recipient_pk_hash, randomness);
        Self(commitment)
    }

    /// Get the commitment as bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Verify that a commitment matches the given values.
    pub fn verify(&self, value: u64, recipient_pk_hash: &[u8; 32], randomness: &[u8; 32]) -> bool {
        let expected = commit_to_note_pq(value, recipient_pk_hash, randomness);
        self.0 == expected
    }
}

impl AsRef<[u8]> for NoteCommitmentPQ {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for NoteCommitmentPQ {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Default for NoteCommitmentPQ {
    fn default() -> Self {
        Self([0u8; 32])
    }
}

/// Compute a value commitment using Poseidon hash.
///
/// This is a standalone function for use in circuits and elsewhere.
/// Input: domain (1) + value (1) + randomness (4) = 6 field elements
/// Output: 4 field elements (32 bytes)
pub fn commit_to_value_pq(value: u64, randomness: &[u8; 32]) -> [u8; 32] {
    let value_fe = u64_to_goldilocks(value);
    let randomness_elems = bytes_to_hash_out(randomness);

    let mut inputs = vec![DOMAIN_VALUE_COMMIT_PQ, value_fe];
    inputs.extend_from_slice(&randomness_elems);

    let hash = poseidon_pq_hash(&inputs);
    hash_out_to_bytes(&hash)
}

/// Compute a note commitment using Poseidon hash.
///
/// This is a standalone function for use in circuits and elsewhere.
/// Input: domain (1) + value (1) + pk_hash (4) + randomness (4) = 10 field elements
/// Output: 4 field elements (32 bytes)
pub fn commit_to_note_pq(value: u64, recipient_pk_hash: &[u8; 32], randomness: &[u8; 32]) -> [u8; 32] {
    let value_fe = u64_to_goldilocks(value);
    let pk_hash_elems = bytes_to_hash_out(recipient_pk_hash);
    let randomness_elems = bytes_to_hash_out(randomness);

    let mut inputs = vec![DOMAIN_NOTE_COMMIT_PQ, value_fe];
    inputs.extend_from_slice(&pk_hash_elems);
    inputs.extend_from_slice(&randomness_elems);

    let hash = poseidon_pq_hash(&inputs);
    hash_out_to_bytes(&hash)
}

/// Derive a nullifier for a note (post-quantum version).
///
/// nullifier = Poseidon(DOMAIN_NULLIFIER_PQ, nullifier_key, commitment, position)
/// Input: domain (1) + nullifier_key (4) + commitment (4) + position (1) = 10 field elements
/// Output: 4 field elements (32 bytes)
pub fn derive_nullifier_pq(
    nullifier_key: &[u8; 32],
    commitment: &[u8; 32],
    position: u64,
) -> [u8; 32] {
    use super::poseidon_pq::DOMAIN_NULLIFIER_PQ;

    let nk_elems = bytes_to_hash_out(nullifier_key);
    let cm_elems = bytes_to_hash_out(commitment);
    let pos_fe = u64_to_goldilocks(position);

    let mut inputs = vec![DOMAIN_NULLIFIER_PQ];
    inputs.extend_from_slice(&nk_elems);
    inputs.extend_from_slice(&cm_elems);
    inputs.push(pos_fe);

    let hash = poseidon_pq_hash(&inputs);
    hash_out_to_bytes(&hash)
}

/// Helper module for hex serialization of 32-byte arrays.
mod hex_bytes_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("Invalid length for 32-byte array"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_commitment_determinism() {
        let value = 1000u64;
        let randomness = [42u8; 32];

        let cm1 = ValueCommitmentPQ::commit(value, &randomness);
        let cm2 = ValueCommitmentPQ::commit(value, &randomness);

        assert_eq!(cm1, cm2);
    }

    #[test]
    fn test_value_commitment_hiding() {
        let value = 1000u64;
        let randomness1 = [42u8; 32];
        let randomness2 = [43u8; 32];

        let cm1 = ValueCommitmentPQ::commit(value, &randomness1);
        let cm2 = ValueCommitmentPQ::commit(value, &randomness2);

        // Different randomness should produce different commitments
        assert_ne!(cm1, cm2);
    }

    #[test]
    fn test_value_commitment_binding() {
        let randomness = [42u8; 32];

        let cm1 = ValueCommitmentPQ::commit(1000, &randomness);
        let cm2 = ValueCommitmentPQ::commit(1001, &randomness);

        // Different values should produce different commitments
        assert_ne!(cm1, cm2);
    }

    #[test]
    fn test_value_commitment_verify() {
        let value = 1000u64;
        let randomness = [42u8; 32];

        let cm = ValueCommitmentPQ::commit(value, &randomness);

        assert!(cm.verify(value, &randomness));
        assert!(!cm.verify(value + 1, &randomness));
        assert!(!cm.verify(value, &[43u8; 32]));
    }

    #[test]
    fn test_note_commitment_determinism() {
        let value = 1000u64;
        let pk_hash = [1u8; 32];
        let randomness = [42u8; 32];

        let cm1 = NoteCommitmentPQ::commit(value, &pk_hash, &randomness);
        let cm2 = NoteCommitmentPQ::commit(value, &pk_hash, &randomness);

        assert_eq!(cm1, cm2);
    }

    #[test]
    fn test_note_commitment_binding() {
        let pk_hash = [1u8; 32];
        let randomness = [42u8; 32];

        let cm1 = NoteCommitmentPQ::commit(1000, &pk_hash, &randomness);
        let cm2 = NoteCommitmentPQ::commit(1001, &pk_hash, &randomness);

        assert_ne!(cm1, cm2);
    }

    #[test]
    fn test_nullifier_derivation() {
        let nk = [1u8; 32];
        let cm = [2u8; 32];
        let position = 123u64;

        let nf1 = derive_nullifier_pq(&nk, &cm, position);
        let nf2 = derive_nullifier_pq(&nk, &cm, position);

        assert_eq!(nf1, nf2);

        // Different position should produce different nullifier
        let nf3 = derive_nullifier_pq(&nk, &cm, position + 1);
        assert_ne!(nf1, nf3);
    }
}
