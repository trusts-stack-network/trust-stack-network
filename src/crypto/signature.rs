//! Signature verification using ML-DSA-65 (FIPS 204) post-quantum signatures.
//!
//! This module provides Dilithium signatures for transaction signing.
//! All signatures are 3309 bytes (ML-DSA-65).
//!
//! ## Security Parameters (FIPS 204)
//!
//! ML-DSA-65 provides NIST Level III security (equivalent to AES-192):
//! - Classical security: ~192 bits
//! - Quantum security: ~128 bits (resistant to Grover's algorithm)
//!
//! ## Implementation Notes
//!
//! - Uses `fips204` crate which is a Rust implementation of FIPS 204
//! - All operations are constant-time where required by the spec
//! - Signatures are detached (message not embedded in signature)
//! - Empty context string is used for basic signing

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument, trace, warn};

use super::keys::{KeyPair, SIGNATURE_SIZE, PUBLIC_KEY_SIZE};

/// A ML-DSA-65 signature wrapper with serialization support.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// Create a signature from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the raw signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to a hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Parse from a hex string.
    #[instrument(skip(s), fields(sig_len = s.len()), err)]
    pub fn from_hex(s: &str) -> Result<Self, SignatureError> {
        let bytes = hex::decode(s).map_err(|_| SignatureError::InvalidHex)?;
        Ok(Self(bytes))
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature({}...)", &self.to_hex()[..16.min(self.0.len() * 2)])
    }
}

/// Sign a message using a keypair.
///
/// Uses ML-DSA-65 (FIPS 204) detached signatures for signing arbitrary data.
/// The signature is 3309 bytes.
#[instrument(skip(message, keypair), fields(msg_len = message.len()), ret)]
pub fn sign(message: &[u8], keypair: &KeyPair) -> Signature {
    trace!("Signing message with ML-DSA-65");
    // Empty context for basic signing (as per FIPS 204)
    let context: &[u8] = &[];
    // ML-DSA-65 signing can only fail on catastrophic RNG failure — unrecoverable
    let sig: [u8; SIGNATURE_SIZE] = keypair.secret_key().try_sign(message, context)
        .expect("CRITICAL: ML-DSA-65 signing failed — likely RNG failure");
    debug!(signature_size = SIGNATURE_SIZE, "Message signed successfully");
    Signature(sig.to_vec())
}

/// Verify a signature against a message and public key.
///
/// Returns true if the signature is valid, false otherwise.
#[instrument(skip(message, signature, public_key), fields(msg_len = message.len(), sig_len = signature.0.len(), pk_len = public_key.len()), ret)]
pub fn verify(message: &[u8], signature: &Signature, public_key: &[u8]) -> Result<bool, SignatureError> {
    trace!("Verifying ML-DSA-65 signature");
    
    let pk_array: [u8; PUBLIC_KEY_SIZE] = public_key
        .try_into()
        .map_err(|_| {
            warn!(pk_len = public_key.len(), expected = PUBLIC_KEY_SIZE, "Invalid public key length");
            SignatureError::InvalidPublicKey
        })?;

    let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_array)
        .map_err(|_| {
            warn!("Failed to parse ML-DSA-65 public key");
            SignatureError::InvalidPublicKey
        })?;

    let sig_array: [u8; SIGNATURE_SIZE] = signature.0
        .as_slice()
        .try_into()
        .map_err(|_| {
            warn!(sig_len = signature.0.len(), expected = SIGNATURE_SIZE, "Invalid signature length");
            SignatureError::InvalidSignature
        })?;

    // Empty context for basic verification (as per FIPS 204)
    let context: &[u8] = &[];
    let result = pk.verify(message, &sig_array, context);
    
    if result {
        debug!("Signature verification successful");
    } else {
        warn!("Signature verification failed");
    }
    
    Ok(result)
}

/// Verify an ML-DSA-65 signature against a message and public key.
///
/// This is a convenience wrapper around [`verify`] that provides a simpler
/// API for the consensus layer. It takes raw bytes directly rather than
/// wrapped types.
///
/// # Arguments
///
/// * `public_key` - The ML-DSA-65 public key (1952 bytes)
/// * `message` - The message that was signed
/// * `signature` - The signature to verify (3309 bytes)
///
/// # Returns
///
/// Returns `true` if the signature is valid, `false` otherwise.
///
/// # Security
///
/// This function performs full ML-DSA-65 verification as specified in FIPS 204.
/// All operations are constant-time where required by the specification.
///
/// # References
///
/// - FIPS 204: <https://csrc.nist.gov/pubs/fips/204/final>
/// - CRYSTALS-Dilithium: <https://pq-crystals.org/dilithium/>
#[instrument(skip(public_key, message, signature), 
    fields(pk_len = public_key.len(), msg_len = message.len(), sig_len = signature.len()), 
    ret
)]
pub fn verify_mldsa65(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    trace!("Verifying ML-DSA-65 signature (consensus API)");
    
    // Validate public key length (must be exactly 1952 bytes for ML-DSA-65)
    let pk_array: [u8; PUBLIC_KEY_SIZE] = match public_key.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            warn!(pk_len = public_key.len(), expected = PUBLIC_KEY_SIZE, "Invalid public key length");
            return false;
        }
    };
    
    // Parse the public key
    let pk = match ml_dsa_65::PublicKey::try_from_bytes(pk_array) {
        Ok(pk) => pk,
        Err(_) => {
            warn!("Failed to parse ML-DSA-65 public key");
            return false;
        }
    };
    
    // Validate signature length (must be exactly 3309 bytes for ML-DSA-65)
    let sig_array: [u8; SIGNATURE_SIZE] = match signature.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            warn!(sig_len = signature.len(), expected = SIGNATURE_SIZE, "Invalid signature length");
            return false;
        }
    };
    
    // Empty context for basic verification (as per FIPS 204 Section 5.2)
    let context: &[u8] = &[];
    
    // Perform the verification
    let result = pk.verify(message, &sig_array, context);
    
    if result {
        debug!("ML-DSA-65 signature verification successful");
    } else {
        warn!("ML-DSA-65 signature verification failed");
    }
    
    result
}

/// Hash a public key to produce an address.
///
/// This is a convenience function that delegates to [`Address::from_public_key`]
/// in the address module. The address is computed as the first 20 bytes of
/// SHA-256(public_key).
///
/// # Arguments
///
/// * `public_key` - The public key to hash (typically 1952 bytes for ML-DSA-65)
///
/// # Returns
///
/// A 20-byte address derived from the public key hash.
///
/// # Security
///
/// Uses SHA-256 which provides 128-bit collision resistance, sufficient
/// for address generation. The truncation to 160 bits follows Ethereum's
/// design and provides adequate security for blockchain addresses.
#[instrument(skip(public_key), fields(pk_len = public_key.len()), ret)]
pub fn hash_public_key(public_key: &[u8]) -> [u8; 20] {
    use sha2::{Digest, Sha256};
    
    trace!("Hashing public key to derive address");
    let hash = Sha256::digest(public_key);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[..20]);
    debug!("Public key hashed successfully");
    addr
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("Invalid hex encoding")]
    InvalidHex,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid signature format")]
    InvalidSignature,
}

/// Batch verify multiple signatures efficiently.
///
/// Returns a vector of booleans indicating verification results.
/// Note: This performs individual verification - batch verification
/// optimizations may be added in the future.
#[instrument(skip(messages, signatures, public_keys), fields(batch_size = messages.len()), ret)]
pub fn verify_batch(
    messages: &[&[u8]],
    signatures: &[&Signature],
    public_keys: &[&[u8]],
) -> Vec<Result<bool, SignatureError>> {
    debug!(batch_size = messages.len(), "Starting batch signature verification");
    
    if messages.len() != signatures.len() || messages.len() != public_keys.len() {
        warn!(
            msg_count = messages.len(),
            sig_count = signatures.len(),
            pk_count = public_keys.len(),
            "Mismatched batch verification input lengths"
        );
    }
    
    let results: Vec<_> = messages
        .iter()
        .zip(signatures.iter())
        .zip(public_keys.iter())
        .map(|((msg, sig), pk)| verify(msg, sig, pk))
        .collect();
    
    let success_count = results.iter().filter(|r| matches!(r, Ok(true))).count();
    debug!(success_count, total = results.len(), "Batch verification complete");
    
    results
}

/// Verify a signature with additional context for structured logging.
#[instrument(
    skip(message, signature, public_key),
    fields(
        operation = "signature_verify",
        msg_len = message.len(),
        sig_prefix = %signature.to_hex().get(..16).unwrap_or("").to_string(),
        pk_prefix = %hex::encode(public_key.get(..8).unwrap_or(&[])),
    ),
    ret
)]
pub fn verify_with_context(
    message: &[u8],
    signature: &Signature,
    public_key: &[u8],
    context: &str,
) -> Result<bool, SignatureError> {
    trace!(%context, "Verifying signature with context");
    verify(message, signature, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::keys::KeyPair;

    #[test]
    fn test_sign_verify_roundtrip() {
        let keypair = KeyPair::generate();
        let message = b"Hello, TSN!";
        
        let signature = sign(message, &keypair);
        let result = verify(message, &signature, &keypair.public_key_bytes()).unwrap();
        
        assert!(result);
    }

    #[test]
    fn test_verify_mldsa65_roundtrip() {
        let keypair = KeyPair::generate();
        let message = b"Hello, TSN!";
        
        let signature = sign(message, &keypair);
        let result = verify_mldsa65(&keypair.public_key_bytes(), message, signature.as_bytes());
        
        assert!(result);
    }

    #[test]
    fn test_verify_mldsa65_wrong_message() {
        let keypair = KeyPair::generate();
        let message = b"Hello, TSN!";
        let wrong_message = b"Goodbye, TSN!";
        
        let signature = sign(message, &keypair);
        let result = verify_mldsa65(&keypair.public_key_bytes(), wrong_message, signature.as_bytes());
        
        assert!(!result);
    }

    #[test]
    fn test_verify_mldsa65_invalid_signature_length() {
        let keypair = KeyPair::generate();
        let message = b"Hello, TSN!";
        let invalid_sig = vec![0u8; 100]; // Wrong size
        
        let result = verify_mldsa65(&keypair.public_key_bytes(), message, &invalid_sig);
        
        assert!(!result);
    }

    #[test]
    fn test_verify_mldsa65_invalid_public_key_length() {
        let invalid_pk = vec![0u8; 100]; // Wrong size
        let message = b"Hello, TSN!";
        let signature = vec![0u8; SIGNATURE_SIZE];
        
        let result = verify_mldsa65(&invalid_pk, message, &signature);
        
        assert!(!result);
    }

    #[test]
    fn test_hash_public_key() {
        let keypair = KeyPair::generate();
        let pk_bytes = keypair.public_key_bytes();
        
        let hash1 = hash_public_key(&pk_bytes);
        let hash2 = hash_public_key(&pk_bytes);
        
        // Same public key should produce same hash
        assert_eq!(hash1, hash2);
        
        // Hash should be 20 bytes
        assert_eq!(hash1.len(), 20);
        
        // Different key should produce different hash
        let keypair2 = KeyPair::generate();
        let hash3 = hash_public_key(&keypair2.public_key_bytes());
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_signature_serialization() {
        let keypair = KeyPair::generate();
        let message = b"Test message";
        let signature = sign(message, &keypair);
        
        let hex = signature.to_hex();
        let restored = Signature::from_hex(&hex).unwrap();
        
        assert_eq!(signature.as_bytes(), restored.as_bytes());
    }

    #[test]
    fn test_signature_debug() {
        let sig = Signature(vec![0xab; 32]);
        let debug_str = format!("{:?}", sig);
        assert!(debug_str.starts_with("Signature("));
        assert!(debug_str.contains("abab"));
    }
}
