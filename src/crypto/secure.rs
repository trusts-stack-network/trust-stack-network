//! Implémentation sécurisée de primitives cryptographiques
//! 
//! Règles appliquées:
//! - Constant-time operations via `subtle`
//! - Zeroization automatique via `ZeroizeOnDrop`
//! - AEAD uniquement (pas de padding oracle possible)
//! - RNG système sécurisé
//! - Aucun unwrap/expect - erreurs propagées via Result

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, generic_array::GenericArray},
    Aes256Gcm, Nonce,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};
use thiserror::Error;

/// Erreurs cryptographiques sécurisées
#[derive(Debug, Error, Clone, PartialEq)]
pub enum CryptoError {
    #[error("Invalid key size")]
    InvalidKeySize,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("RNG failure: {0}")]
    RngFailure(String),
    #[error("Invalid ciphertext format")]
    InvalidCiphertext,
    #[error("MAC verification failed")]
    MacVerificationFailed,
    #[error("Invalid nonce")]
    InvalidNonce,
}

type HmacSha256 = Hmac<Sha256>;

/// Clé secrète protégée en mémoire
#[derive(Clone)]
pub struct SecretKey {
    bytes: Vec<u8>,
    _guard: SecretGuard,
}

impl SecretKey {
    /// Generate a new random secret key
    /// 
    /// SECURITY: Returns Result instead of panicking on RNG failure
    pub fn generate(size: usize) -> Result<Self, CryptoError> {
        let mut bytes = vec![0u8; size];
        getrandom::getrandom(&mut bytes)
            .map_err(|e| {
                CryptoError::RngFailure(format!("getrandom failed: {}", e))
            })?;
        Ok(Self {
            bytes,
            _guard: SecretGuard,
        })
    }
    
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let v = bytes.to_vec();
        Self {
            bytes: v,
            _guard: SecretGuard,
        }
    }
    
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

// Marqueur pour zeroization
struct SecretGuard;

impl Drop for SecretGuard {
    fn drop(&mut self) {
        // Logique additionnelle si nécessaire
    }
}

/// Chiffrement AEAD AES-256-GCM
#[must_use]
pub fn encrypt_aes_gcm(
    key: &SecretKey,
    plaintext: &[u8],
    _associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.as_slice().len() != 32 {
        return Err(CryptoError::InvalidKeySize);
    }
    
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key.as_slice()));
    let nonce = Nonce::from(OsRng.gen::<[u8; 12]>());
    
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    
    // Format: nonce (12 bytes) || ciphertext || tag (16 bytes)
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    
    Ok(result)
}

/// Déchiffrement AEAD AES-256-GCM
#[must_use]
pub fn decrypt_aes_gcm(
    key: &SecretKey,
    ciphertext: &[u8],
    _associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.as_slice().len() != 32 {
        return Err(CryptoError::InvalidKeySize);
    }
    
    if ciphertext.len() < 12 {
        return Err(CryptoError::InvalidCiphertext);
    }
    
    let (nonce_bytes, encrypted) = ciphertext.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key.as_slice()));
    
    cipher
        .decrypt(nonce, encrypted)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// HMAC-SHA256 avec vérification constant-time
#[must_use]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKeySize)?;
    mac.update(message);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);
    Ok(output)
}

/// Vérification HMAC constant-time
/// 
/// SECURITY: Uses subtle::ConstantTimeEq to prevent timing attacks
#[must_use]
pub fn verify_hmac_sha256(key: &[u8], message: &[u8], expected: &[u8]) -> Result<bool, CryptoError> {
    let computed = hmac_sha256(key, message)?;
    
    if expected.len() != 32 {
        return Err(CryptoError::InvalidCiphertext);
    }
    
    let expected_array: [u8; 32] = expected.try_into()
        .map_err(|_| CryptoError::InvalidCiphertext)?;
    
    Ok(computed.ct_eq(&expected_array).into())
}

/// Génération de nonce sécurisée
#[must_use]
pub fn generate_nonce(size: usize) -> Result<Vec<u8>, CryptoError> {
    let mut nonce = vec![0u8; size];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| CryptoError::RngFailure(format!("getrandom failed: {}", e)))?;
    Ok(nonce)
}

/// Constant-time comparison of two byte slices
/// 
/// SECURITY: Always use this instead of == for sensitive comparisons
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_key_generation() {
        let key = SecretKey::generate(32).expect("Key generation should succeed in test");
        assert_eq!(key.as_slice().len(), 32);
        
        // Verify key is not all zeros
        assert!(!key.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secret_key_from_bytes() {
        let bytes = vec![1u8, 2, 3, 4, 5];
        let key = SecretKey::from_bytes(&bytes);
        assert_eq!(key.as_slice(), &bytes);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = SecretKey::generate(32).expect("Key generation should succeed");
        let plaintext = b"Hello, secure world!";
        let aad = b"associated data";
        
        let ciphertext = encrypt_aes_gcm(&key, plaintext, aad)
            .expect("Encryption should succeed");
        
        let decrypted = decrypt_aes_gcm(&key, &ciphertext, aad)
            .expect("Decryption should succeed");
        
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key1 = SecretKey::generate(32).expect("Key generation should succeed");
        let key2 = SecretKey::generate(32).expect("Key generation should succeed");
        let plaintext = b"Hello, secure world!";
        let aad = b"associated data";
        
        let ciphertext = encrypt_aes_gcm(&key1, plaintext, aad)
            .expect("Encryption should succeed");
        
        let result = decrypt_aes_gcm(&key2, &ciphertext, aad);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let key = SecretKey::generate(32).expect("Key generation should succeed");
        let plaintext = b"Hello, secure world!";
        let aad = b"associated data";
        
        let mut ciphertext = encrypt_aes_gcm(&key, plaintext, aad)
            .expect("Encryption should succeed");
        
        // Tamper with the ciphertext
        ciphertext[15] ^= 0xFF;
        
        let result = decrypt_aes_gcm(&key, &ciphertext, aad);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_invalid_key_size() {
        let key = SecretKey::from_bytes(&[1u8; 16]); // 16 bytes instead of 32
        let plaintext = b"test";
        
        let result = encrypt_aes_gcm(&key, plaintext, b"");
        assert!(matches!(result, Err(CryptoError::InvalidKeySize)));
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"secret key";
        let message = b"message to authenticate";
        
        let mac = hmac_sha256(key, message).expect("HMAC should succeed");
        assert_eq!(mac.len(), 32);
        
        // Verify same input produces same output
        let mac2 = hmac_sha256(key, message).expect("HMAC should succeed");
        assert_eq!(mac, mac2);
    }

    #[test]
    fn test_verify_hmac_sha256() {
        let key = b"secret key";
        let message = b"message to authenticate";
        
        let mac = hmac_sha256(key, message).expect("HMAC should succeed");
        
        // Correct verification
        assert!(verify_hmac_sha256(key, message, &mac).expect("Verification should succeed"));
        
        // Wrong message
        let wrong_message = b"different message";
        assert!(!verify_hmac_sha256(key, wrong_message, &mac).expect("Verification should succeed"));
        
        // Wrong key
        let wrong_key = b"wrong key";
        assert!(!verify_hmac_sha256(wrong_key, message, &mac).expect("Verification should succeed"));
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8, 2, 3, 4, 5];
        let b = [1u8, 2, 3, 4, 5];
        let c = [1u8, 2, 3, 4, 6];
        
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &a[..4])); // Different lengths
    }

    #[test]
    fn test_generate_nonce() {
        let nonce1 = generate_nonce(12).expect("Nonce generation should succeed");
        let nonce2 = generate_nonce(12).expect("Nonce generation should succeed");
        
        assert_eq!(nonce1.len(), 12);
        assert_eq!(nonce2.len(), 12);
        
        // Nonces should be different (with extremely high probability)
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_invalid_ciphertext_too_short() {
        let key = SecretKey::generate(32).expect("Key generation should succeed");
        let short_ciphertext = vec![1u8; 5]; // Less than 12 bytes
        
        let result = decrypt_aes_gcm(&key, &short_ciphertext, b"");
        assert!(matches!(result, Err(CryptoError::InvalidCiphertext)));
    }
}
