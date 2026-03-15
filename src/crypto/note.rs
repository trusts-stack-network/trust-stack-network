//! Note structure and encryption for private transactions.
//!
//! A note represents a private value owned by a recipient.
//! Notes are encrypted on-chain so only the recipient can read them.

use ark_bn254::Fr;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::{Blake2s256, Digest};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};

use super::commitment::{commit_to_note, NoteCommitment};
use super::nullifier::{derive_nullifier, Nullifier, NullifierKey};

/// A note representing a private value.
/// This is the private data that only the owner knows.
#[derive(Clone, Debug)]
pub struct Note {
    /// The value in the smallest unit (like satoshis).
    pub value: u64,
    /// Hash of the recipient's public key.
    pub recipient_pk_hash: [u8; 32],
    /// Random value for hiding the note contents.
    pub randomness: Fr,
}

impl Note {
    /// Create a new note with random blinding factor.
    pub fn new<R: ark_std::rand::RngCore>(value: u64, recipient_pk_hash: [u8; 32], rng: &mut R) -> Self {
        Self {
            value,
            recipient_pk_hash,
            randomness: Fr::rand(rng),
        }
    }

    /// Create a note with a specific randomness (for testing or deterministic creation).
    pub fn with_randomness(value: u64, recipient_pk_hash: [u8; 32], randomness: Fr) -> Self {
        Self {
            value,
            recipient_pk_hash,
            randomness,
        }
    }

    /// Compute the commitment for this note.
    pub fn commitment(&self) -> NoteCommitment {
        commit_to_note(self.value, &self.recipient_pk_hash, &self.randomness)
    }

    /// Compute the nullifier for this note given the nullifier key and position.
    pub fn nullifier(&self, nullifier_key: &NullifierKey, position: u64) -> Nullifier {
        let commitment = self.commitment();
        derive_nullifier(nullifier_key, &commitment, position)
    }

    /// Serialize to bytes for encryption.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.value.to_le_bytes());
        bytes.extend_from_slice(&self.recipient_pk_hash);
        // serialize_compressed on Fr never fails for a valid field element
        self.randomness.serialize_compressed(&mut bytes)
            .expect("BUG: Fr serialization cannot fail for valid field element");
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 8 + 32 + 32 {
            return Err("Note bytes too short");
        }

        // SAFETY: length checked above (>= 72), slice is exactly 8 bytes
        let value = u64::from_le_bytes(bytes[0..8].try_into().unwrap());

        let mut recipient_pk_hash = [0u8; 32];
        recipient_pk_hash.copy_from_slice(&bytes[8..40]);

        let randomness = Fr::deserialize_compressed(&bytes[40..])
            .map_err(|_| "Failed to deserialize randomness")?;

        Ok(Self {
            value,
            recipient_pk_hash,
            randomness,
        })
    }
}

/// An encrypted note that can be stored on-chain.
/// Only the recipient can decrypt it using their viewing key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedNote {
    /// The encrypted note data (value || pk_hash || randomness).
    pub ciphertext: Vec<u8>,
    /// Ephemeral public key for ECDH key agreement (compressed).
    pub ephemeral_pk: Vec<u8>,
}

impl EncryptedNote {
    /// Get the size of this encrypted note in bytes.
    pub fn size(&self) -> usize {
        self.ciphertext.len() + self.ephemeral_pk.len()
    }
}

/// A viewing key derived from the secret key.
/// Allows scanning the blockchain for incoming notes without spending ability.
#[derive(Clone, Debug)]
pub struct ViewingKey {
    /// The viewing secret (derived from wallet secret).
    viewing_secret: [u8; 32],
}

impl ViewingKey {
    /// Create a viewing key from secret material.
    pub fn new(secret_bytes: &[u8]) -> Self {
        let mut hasher = Blake2s256::new();
        hasher.update(b"TSN_ViewingKey");
        hasher.update(secret_bytes);
        let hash = hasher.finalize();
        let mut viewing_secret = [0u8; 32];
        viewing_secret.copy_from_slice(&hash);
        Self { viewing_secret }
    }

    /// Get the viewing key bytes for serialization.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.viewing_secret
    }

    /// Create from bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            viewing_secret: bytes,
        }
    }

    /// Create a viewing key directly from a pk_hash.
    /// Used for encrypting notes to recipients - they can decrypt using their own pk_hash.
    /// This allows senders to encrypt notes that only the recipient (who knows their pk_hash) can decrypt.
    pub fn from_pk_hash(pk_hash: [u8; 32]) -> Self {
        Self {
            viewing_secret: pk_hash,
        }
    }

    /// Derive the symmetric encryption key for a note.
    /// Uses the ephemeral public key to derive a shared secret.
    pub(crate) fn derive_encryption_key(&self, ephemeral_pk: &[u8]) -> [u8; 32] {
        let mut hasher = Blake2s256::new();
        hasher.update(b"TSN_NoteEncryption");
        hasher.update(&self.viewing_secret);
        hasher.update(ephemeral_pk);
        let hash = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);
        key
    }

    /// Encrypt a note so only this viewing key can decrypt it.
    pub fn encrypt_note<R: ark_std::rand::RngCore>(&self, note: &Note, rng: &mut R) -> EncryptedNote {
        // Generate ephemeral randomness for this encryption
        let mut ephemeral_secret = [0u8; 32];
        rng.fill_bytes(&mut ephemeral_secret);

        // Derive ephemeral "public key" (just a hash of the secret for simplicity)
        let mut hasher = Blake2s256::new();
        hasher.update(b"TSN_EphemeralPK");
        hasher.update(&ephemeral_secret);
        let ephemeral_pk: Vec<u8> = hasher.finalize().to_vec();

        // Derive encryption key
        let encryption_key = self.derive_encryption_key(&ephemeral_pk);

        // Encrypt using ChaCha20-Poly1305
        // SAFETY: encryption_key is always 32 bytes (Blake2s256 output)
        let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key)
            .expect("BUG: Blake2s256 always produces 32-byte key");

        // Use first 12 bytes of ephemeral_pk as nonce
        let nonce = Nonce::from_slice(&ephemeral_pk[0..12]);

        let plaintext = note.to_bytes();
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .expect("BUG: ChaCha20Poly1305 encryption cannot fail with valid key/nonce");

        EncryptedNote {
            ciphertext,
            ephemeral_pk,
        }
    }

    /// Try to decrypt an encrypted note.
    /// Returns None if decryption fails (note wasn't for us).
    pub fn decrypt_note(&self, encrypted: &EncryptedNote) -> Option<Note> {
        // Derive encryption key
        let encryption_key = self.derive_encryption_key(&encrypted.ephemeral_pk);

        // Decrypt using ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key).ok()?;

        // Use first 12 bytes of ephemeral_pk as nonce
        if encrypted.ephemeral_pk.len() < 12 {
            return None;
        }
        let nonce = Nonce::from_slice(&encrypted.ephemeral_pk[0..12]);

        let plaintext = cipher.decrypt(nonce, encrypted.ciphertext.as_ref()).ok()?;

        Note::from_bytes(&plaintext).ok()
    }

    /// Check if an encrypted note is intended for this viewing key by attempting decryption.
    pub fn can_decrypt(&self, encrypted: &EncryptedNote) -> bool {
        self.decrypt_note(encrypted).is_some()
    }
}

impl Serialize for ViewingKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.viewing_secret)
    }
}

impl<'de> Deserialize<'de> for ViewingKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Invalid viewing key length"));
        }
        let mut viewing_secret = [0u8; 32];
        viewing_secret.copy_from_slice(&bytes);
        Ok(Self { viewing_secret })
    }
}

/// Compute the public key hash for an address.
/// Used when creating notes for a recipient.
pub fn compute_pk_hash(public_key: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(b"TSN_PkHash");
    hasher.update(public_key);
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

/// Encrypt a V2/PQ note for the recipient.
///
/// This creates an encrypted note that the recipient can decrypt using their
/// viewing key (derived from their pk_hash). Unlike V1 notes which use BN254
/// field elements, V2 notes use raw byte arrays for randomness.
///
/// # Arguments
/// * `value` - The note value in base units
/// * `pk_hash` - The recipient's public key hash (32 bytes)
/// * `randomness` - Random bytes for hiding the note (32 bytes)
///
/// # Returns
/// An `EncryptedNote` that can be included in a V2 transaction output.
pub fn encrypt_note_pq(value: u64, pk_hash: &[u8; 32], randomness: &[u8; 32]) -> EncryptedNote {
    use rand::RngCore;

    // Create viewing key from recipient's pk_hash
    let viewing_key = ViewingKey::from_pk_hash(*pk_hash);

    // Serialize the PQ note data: value || pk_hash || randomness
    let mut plaintext = Vec::with_capacity(8 + 32 + 32);
    plaintext.extend_from_slice(&value.to_le_bytes());
    plaintext.extend_from_slice(pk_hash);
    plaintext.extend_from_slice(randomness);

    // Generate ephemeral randomness for encryption
    let mut rng = rand::thread_rng();
    let mut ephemeral_secret = [0u8; 32];
    rng.fill_bytes(&mut ephemeral_secret);

    // Derive ephemeral "public key"
    let mut hasher = Blake2s256::new();
    hasher.update(b"TSN_EphemeralPK");
    hasher.update(&ephemeral_secret);
    let ephemeral_pk: Vec<u8> = hasher.finalize().to_vec();

    // Derive encryption key
    let encryption_key = viewing_key.derive_encryption_key(&ephemeral_pk);

    // Encrypt using ChaCha20-Poly1305
    // SAFETY: encryption_key is always 32 bytes (Blake2s256 output)
    let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key)
        .expect("BUG: Blake2s256 always produces 32-byte key");
    let nonce = Nonce::from_slice(&ephemeral_pk[0..12]);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .expect("BUG: ChaCha20Poly1305 encryption cannot fail with valid key/nonce");

    EncryptedNote {
        ciphertext,
        ephemeral_pk,
    }
}

/// Decrypt a V2/PQ note.
///
/// # Arguments
/// * `encrypted` - The encrypted note data
/// * `pk_hash` - The recipient's public key hash (used as viewing key)
///
/// # Returns
/// `Some((value, pk_hash, randomness))` if decryption succeeds, `None` otherwise.
pub fn decrypt_note_pq(encrypted: &EncryptedNote, pk_hash: &[u8; 32]) -> Option<(u64, [u8; 32], [u8; 32])> {
    let viewing_key = ViewingKey::from_pk_hash(*pk_hash);

    // Derive encryption key
    let encryption_key = viewing_key.derive_encryption_key(&encrypted.ephemeral_pk);

    // Decrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key).ok()?;
    if encrypted.ephemeral_pk.len() < 12 {
        return None;
    }
    let nonce = Nonce::from_slice(&encrypted.ephemeral_pk[0..12]);
    let plaintext = cipher.decrypt(nonce, encrypted.ciphertext.as_ref()).ok()?;

    // Parse: value (8) || pk_hash (32) || randomness (32)
    if plaintext.len() < 72 {
        return None;
    }

    let value = u64::from_le_bytes(plaintext[0..8].try_into().ok()?);
    let mut note_pk_hash = [0u8; 32];
    note_pk_hash.copy_from_slice(&plaintext[8..40]);
    let mut randomness = [0u8; 32];
    randomness.copy_from_slice(&plaintext[40..72]);

    Some((value, note_pk_hash, randomness))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::rngs::StdRng;

    #[test]
    fn test_note_roundtrip() {
        let mut rng = StdRng::seed_from_u64(12345);
        let note = Note::new(1000, [1u8; 32], &mut rng);

        let bytes = note.to_bytes();
        let recovered = Note::from_bytes(&bytes).unwrap();

        assert_eq!(note.value, recovered.value);
        assert_eq!(note.recipient_pk_hash, recovered.recipient_pk_hash);
        assert_eq!(note.randomness, recovered.randomness);
    }

    #[test]
    fn test_note_commitment() {
        let mut rng = StdRng::seed_from_u64(12345);
        let note = Note::new(1000, [1u8; 32], &mut rng);

        let cm1 = note.commitment();
        let cm2 = note.commitment();

        assert_eq!(cm1, cm2);
    }

    #[test]
    fn test_note_encryption_decryption() {
        let mut rng = StdRng::seed_from_u64(12345);

        let viewing_key = ViewingKey::new(b"test_secret");
        let note = Note::new(1000, [1u8; 32], &mut rng);

        let encrypted = viewing_key.encrypt_note(&note, &mut rng);
        let decrypted = viewing_key.decrypt_note(&encrypted).unwrap();

        assert_eq!(note.value, decrypted.value);
        assert_eq!(note.recipient_pk_hash, decrypted.recipient_pk_hash);
        assert_eq!(note.randomness, decrypted.randomness);
    }

    #[test]
    fn test_wrong_viewing_key_cannot_decrypt() {
        let mut rng = StdRng::seed_from_u64(12345);

        let viewing_key1 = ViewingKey::new(b"secret1");
        let viewing_key2 = ViewingKey::new(b"secret2");

        let note = Note::new(1000, [1u8; 32], &mut rng);
        let encrypted = viewing_key1.encrypt_note(&note, &mut rng);

        // Wrong key should fail to decrypt
        assert!(viewing_key2.decrypt_note(&encrypted).is_none());
    }

    #[test]
    fn test_note_nullifier() {
        let mut rng = StdRng::seed_from_u64(12345);
        let note = Note::new(1000, [1u8; 32], &mut rng);
        let nk = NullifierKey::new(b"nullifier_secret");

        let nf1 = note.nullifier(&nk, 42);
        let nf2 = note.nullifier(&nk, 42);

        assert_eq!(nf1, nf2);

        // Different position gives different nullifier
        let nf3 = note.nullifier(&nk, 43);
        assert_ne!(nf1, nf3);
    }

    #[test]
    fn test_pk_hash() {
        let pk1 = b"public_key_1";
        let pk2 = b"public_key_2";

        let hash1 = compute_pk_hash(pk1);
        let hash2 = compute_pk_hash(pk2);

        assert_ne!(hash1, hash2);

        // Same input gives same hash
        let hash1_again = compute_pk_hash(pk1);
        assert_eq!(hash1, hash1_again);
    }
}
