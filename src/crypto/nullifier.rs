//! Nullifier derivation for double-spend prevention.
//!
//! A nullifier uniquely identifies a spent note without revealing which note was spent.
//! nf = Poseidon(DOMAIN_NULLIFIER, nullifier_key, commitment, position)
//!
//! Properties:
//! - Given nf, you cannot determine which note was spent (without the nullifier key)
//! - Each note produces a unique nullifier
//! - The same note always produces the same nullifier (prevents double-spend)

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};

use super::commitment::NoteCommitment;
use super::poseidon::{poseidon_hash, bytes32_to_field, field_to_bytes32, DOMAIN_NULLIFIER};

/// A nullifier that marks a note as spent.
/// Published on-chain to prevent double-spending.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Nullifier(pub [u8; 32]);

impl Nullifier {
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

impl Default for Nullifier {
    fn default() -> Self {
        Self([0u8; 32])
    }
}

impl AsRef<[u8]> for Nullifier {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Secret key used to derive nullifiers.
/// Derived from the wallet's secret key material.
/// Must be kept secret - anyone with this can compute nullifiers for your notes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NullifierKey {
    key: Fr,
}

impl NullifierKey {
    /// Create a new nullifier key from random bytes.
    pub fn new(secret_bytes: &[u8]) -> Self {
        let mut hasher = Blake2s256::new();
        hasher.update(b"TSN_NullifierKey");
        hasher.update(secret_bytes);
        let hash = hasher.finalize();
        let key = Fr::from_le_bytes_mod_order(&hash);
        Self { key }
    }

    /// Create from a field element directly.
    pub fn from_field_element(key: Fr) -> Self {
        Self { key }
    }

    /// Get the underlying field element.
    pub fn to_field_element(&self) -> Fr {
        self.key
    }

    /// Serialize to bytes for storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.key.serialize_compressed(&mut bytes).unwrap();
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        use ark_serialize::CanonicalDeserialize;
        let key = Fr::deserialize_compressed(bytes)
            .map_err(|_| "Failed to deserialize nullifier key")?;
        Ok(Self { key })
    }
}

impl Serialize for NullifierKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.to_bytes();
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for NullifierKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// Derive a nullifier for a note using Poseidon hash.
///
/// nf = Poseidon(DOMAIN_NULLIFIER, nk, cm, position)
///
/// # Arguments
/// * `nullifier_key` - The secret nullifier key
/// * `commitment` - The note commitment
/// * `position` - The position of the note in the commitment tree
pub fn derive_nullifier(
    nullifier_key: &NullifierKey,
    commitment: &NoteCommitment,
    position: u64,
) -> Nullifier {
    // Convert inputs to field elements
    let nk_fe = nullifier_key.key;
    let cm_fe = bytes32_to_field(&commitment.0);
    let position_fe = Fr::from(position);

    // Hash: Poseidon(domain, nk, cm, position)
    let hash = poseidon_hash(DOMAIN_NULLIFIER, &[nk_fe, cm_fe, position_fe]);

    // Convert field element to bytes
    let result = field_to_bytes32(&hash);

    Nullifier(result)
}

/// Verify that a nullifier was correctly derived (for testing/debugging).
pub fn verify_nullifier(
    nullifier_key: &NullifierKey,
    commitment: &NoteCommitment,
    position: u64,
    expected: &Nullifier,
) -> bool {
    let computed = derive_nullifier(nullifier_key, commitment, position);
    computed == *expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_derivation_deterministic() {
        let nk = NullifierKey::new(b"test_secret_key");
        let cm = NoteCommitment([1u8; 32]);
        let position = 42u64;

        let nf1 = derive_nullifier(&nk, &cm, position);
        let nf2 = derive_nullifier(&nk, &cm, position);

        assert_eq!(nf1, nf2);
    }

    #[test]
    fn test_nullifier_different_commitments() {
        let nk = NullifierKey::new(b"test_secret_key");
        let cm1 = NoteCommitment([1u8; 32]);
        let cm2 = NoteCommitment([2u8; 32]);
        let position = 42u64;

        let nf1 = derive_nullifier(&nk, &cm1, position);
        let nf2 = derive_nullifier(&nk, &cm2, position);

        assert_ne!(nf1, nf2);
    }

    #[test]
    fn test_nullifier_different_positions() {
        let nk = NullifierKey::new(b"test_secret_key");
        let cm = NoteCommitment([1u8; 32]);

        let nf1 = derive_nullifier(&nk, &cm, 0);
        let nf2 = derive_nullifier(&nk, &cm, 1);

        assert_ne!(nf1, nf2);
    }

    #[test]
    fn test_nullifier_different_keys() {
        let nk1 = NullifierKey::new(b"key1");
        let nk2 = NullifierKey::new(b"key2");
        let cm = NoteCommitment([1u8; 32]);
        let position = 42u64;

        let nf1 = derive_nullifier(&nk1, &cm, position);
        let nf2 = derive_nullifier(&nk2, &cm, position);

        assert_ne!(nf1, nf2);
    }

    #[test]
    fn test_nullifier_key_serialization() {
        let nk = NullifierKey::new(b"test_secret_key");
        let bytes = nk.to_bytes();
        let recovered = NullifierKey::from_bytes(&bytes).unwrap();

        assert_eq!(nk.key, recovered.key);
    }

    #[test]
    fn test_verify_nullifier() {
        let nk = NullifierKey::new(b"test_secret_key");
        let cm = NoteCommitment([1u8; 32]);
        let position = 42u64;

        let nf = derive_nullifier(&nk, &cm, position);

        assert!(verify_nullifier(&nk, &cm, position, &nf));
        assert!(!verify_nullifier(&nk, &cm, position + 1, &nf));
    }
}
