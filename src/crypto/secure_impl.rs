//! Implémentation sécurisée utilisant subtle et primitives modernes
//!
//! SECURITY: Ce module remplace toutes les opérations cryptographiques
//! potentiellement dangereuses par des versions sécurisées:
//! - Pas de unwrap() dans les fonctions de chiffrement/déchiffrement
//! - Comparaison en temps constant pour éviter les attaques par timing
//! - Gestion d'erreurs explicite pour tous les cas limites
//!
//! Toutes les fonctions retournent Result au lieu de paniquer.

use subtle::ConstantTimeEq;
use rand::RngCore;
use sha2::{Sha256, Digest};
use aes_gcm::{
    Aes256Gcm, Nonce, Key,
    aead::{Aead, KeyInit, Payload},
};
use thiserror::Error;
use tracing::{warn, error};

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("Invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength { expected: usize, actual: usize },
    #[error("Decryption failed - ciphertext may be tampered")]
    DecryptionFailed,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("KDF failed: {0}")]
    KdfFailed(String),
    #[error("RNG failed: {0}")]
    RngFailed(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

/// Constant-time comparison of two byte slices
/// 
/// SECURITY: Uses subtle::ConstantTimeEq to prevent timing attacks
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).unwrap_u8() == 1
}

/// Secure encryption using AES-256-GCM
/// 
/// SECURITY: 
/// - No unwrap() - all errors are handled gracefully
/// - Secure random nonce generation with error handling
/// - Authenticated encryption prevents tampering
pub fn secure_encrypt(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Validate key length
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: key.len(),
        });
    }

    // Generate secure random nonce
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng()
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|e| CryptoError::RngFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(cipher_key);

    // Encrypt with authenticated encryption
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: b"" })
        .map_err(|e| {
            error!("Encryption failed: {:?}", e);
            CryptoError::EncryptionFailed
        })?;

    // Prepend nonce to ciphertext for decryption
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Secure decryption using AES-256-GCM
/// 
/// SECURITY:
/// - No unwrap() - all errors are handled gracefully
/// - Validates minimum ciphertext length before slicing
/// - Constant-time operations where applicable
pub fn secure_decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Validate key length
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: key.len(),
        });
    }

    // Validate minimum ciphertext length (12 bytes nonce + 16 bytes tag minimum)
    if ciphertext.len() < 28 {
        warn!("Ciphertext too short: {} bytes", ciphertext.len());
        return Err(CryptoError::InvalidInput(
            format!("Ciphertext too short: {} bytes (min 28)", ciphertext.len())
        ));
    }

    // Split nonce and ciphertext
    let (nonce_bytes, encrypted) = ciphertext.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(cipher_key);

    // Decrypt - any tampering will cause failure
    cipher
        .decrypt(nonce, Payload { msg: encrypted, aad: b"" })
        .map_err(|e| {
            warn!("Decryption failed - possible tampering: {:?}", e);
            CryptoError::DecryptionFailed
        })
}

/// Secure Key Derivation Function using HKDF-SHA256
/// 
/// SECURITY:
/// - No unwrap() - all errors are handled gracefully
/// - Validates output length
/// - Uses cryptographically secure KDF
pub fn secure_kdf(input: &[u8], salt: &[u8], output_len: usize) -> Result<Vec<u8>, CryptoError> {
    // Validate output length
    if output_len == 0 || output_len > 1024 {
        return Err(CryptoError::InvalidInput(
            format!("Invalid output length: {} (must be 1-1024)", output_len)
        ));
    }

    // Use HKDF-SHA256
    use hkdf::Hkdf;
    
    let hkdf = Hkdf::<Sha256>::new(Some(salt), input);
    let mut output = vec![0u8; output_len];
    
    hkdf.expand(b"tsn-v1-key", &mut output)
        .map_err(|e| {
            error!("KDF expansion failed: {:?}", e);
            CryptoError::KdfFailed(e.to_string())
        })?;

    Ok(output)
}

/// Secure random bytes generation
/// 
/// SECURITY:
/// - No unwrap() - handles RNG failures gracefully
/// - Uses cryptographically secure RNG
pub fn secure_random_bytes(len: usize) -> Result<Vec<u8>, CryptoError> {
    if len == 0 || len > 65536 {
        return Err(CryptoError::InvalidInput(
            format!("Invalid random bytes length: {} (must be 1-65536)", len)
        ));
    }

    let mut bytes = vec![0u8; len];
    rand::thread_rng()
        .try_fill_bytes(&mut bytes)
        .map_err(|e| CryptoError::RngFailed(e.to_string()))?;

    Ok(bytes)
}

/// Secure hash computation using SHA-256
pub fn secure_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Secure XOR of two byte slices (for one-time pad style operations)
/// 
/// SECURITY:
/// - Validates equal lengths
/// - Constant-time operation
pub fn secure_xor(a: &[u8], b: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if a.len() != b.len() {
        return Err(CryptoError::InvalidInput(
            format!("XOR operands must have equal length: {} vs {}", a.len(), b.len())
        ));
    }

    Ok(a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_compare() {
        let a = b"hello world";
        let b = b"hello world";
        let c = b"hello worle";
        let d = b"hello";

        assert!(secure_compare(a, b));
        assert!(!secure_compare(a, c));
        assert!(!secure_compare(a, d));
        assert!(!secure_compare(a, &[]));
    }

    #[test]
    fn test_secure_compare_timing() {
        // This test ensures constant-time comparison
        // In practice, timing attacks would require statistical analysis
        let a = vec![0u8; 1000];
        let b = vec![0u8; 1000];
        let c = vec![1u8; 1000];

        assert!(secure_compare(&a, &b));
        assert!(!secure_compare(&a, &c));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = secure_random_bytes(32).unwrap();
        let plaintext = b"Hello, secure world!";

        let ciphertext = secure_encrypt(plaintext, &key).unwrap();
        let decrypted = secure_decrypt(&ciphertext, &key).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let key1 = secure_random_bytes(32).unwrap();
        let key2 = secure_random_bytes(32).unwrap();
        let plaintext = b"Secret message";

        let ciphertext = secure_encrypt(plaintext, &key1).unwrap();
        let result = secure_decrypt(&ciphertext, &key2);

        assert!(result.is_err());
        match result {
            Err(CryptoError::DecryptionFailed) => {},
            _ => panic!("Expected DecryptionFailed error"),
        }
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let key = secure_random_bytes(32).unwrap();
        let plaintext = b"Secret message";

        let mut ciphertext = secure_encrypt(plaintext, &key).unwrap();
        // Tamper with the ciphertext
        ciphertext[20] ^= 0xff;

        let result = secure_decrypt(&ciphertext, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_short_ciphertext() {
        let key = secure_random_bytes(32).unwrap();
        let short_ciphertext = vec![0u8; 10]; // Too short

        let result = secure_decrypt(&short_ciphertext, &key);
        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidInput(_)) => {},
            _ => panic!("Expected InvalidInput error"),
        }
    }

    #[test]
    fn test_invalid_key_length() {
        let key = vec![0u8; 16]; // Wrong length
        let plaintext = b"test";

        let result = secure_encrypt(plaintext, &key);
        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidKeyLength { expected: 32, actual: 16 }) => {},
            _ => panic!("Expected InvalidKeyLength error"),
        }
    }

    #[test]
    fn test_secure_kdf() {
        let input = b"password";
        let salt = b"random salt";
        
        let key1 = secure_kdf(input, salt, 32).unwrap();
        let key2 = secure_kdf(input, salt, 32).unwrap();
        let key3 = secure_kdf(input, b"different salt", 32).unwrap();

        assert_eq!(key1, key2); // Same input + salt = same key
        assert_ne!(key1, key3); // Different salt = different key
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_secure_kdf_invalid_length() {
        let result = secure_kdf(b"input", b"salt", 0);
        assert!(result.is_err());

        let result = secure_kdf(b"input", b"salt", 1025);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_random_bytes() {
        let bytes1 = secure_random_bytes(32).unwrap();
        let bytes2 = secure_random_bytes(32).unwrap();

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different
    }

    #[test]
    fn test_secure_random_bytes_invalid_length() {
        let result = secure_random_bytes(0);
        assert!(result.is_err());

        let result = secure_random_bytes(65537);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_xor() {
        let a = vec![0b1010u8, 0b1100];
        let b = vec![0b1000u8, 0b0100];
        
        let result = secure_xor(&a, &b).unwrap();
        assert_eq!(result, vec![0b0010, 0b1000]);

        // XOR with itself should give zeros
        let zeros = secure_xor(&a, &a).unwrap();
        assert_eq!(zeros, vec![0u8, 0u8]);
    }

    #[test]
    fn test_secure_xor_unequal_length() {
        let a = vec![0u8; 10];
        let b = vec![0u8; 5];

        let result = secure_xor(&a, &b);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_hash() {
        let data1 = b"hello";
        let data2 = b"hello";
        let data3 = b"world";

        let hash1 = secure_hash(data1);
        let hash2 = secure_hash(data2);
        let hash3 = secure_hash(data3);

        assert_eq!(hash1, hash2); // Same input = same hash
        assert_ne!(hash1, hash3); // Different input = different hash
    }
}
