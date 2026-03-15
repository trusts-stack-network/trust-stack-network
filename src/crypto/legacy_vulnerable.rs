//! Legacy cryptographic implementations - VULNERABLE TO QUANTUM ATTACKS
//! 
//! ⚠️  WARNING: This module contains intentionally vulnerable cryptographic
//! implementations for educational/comparative purposes only. DO NOT USE IN PRODUCTION.
//! 
//! These algorithms are vulnerable to:
//! - Shor's algorithm (breaks RSA, ECDSA)
//! - Grover's algorithm (reduces effective key strength by half)
//! - Classical cryptanalysis advances

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum LegacyCryptoError {
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Invalid IV length")]
    InvalidIvLength,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid MAC")]
    InvalidMac,
}

/// Vulnerable AES-256-CTR encryption
/// 
/// ⚠️  VULNERABLE: No quantum resistance, weak key derivation
pub fn encrypt_aes256ctr_vulnerable(
    plaintext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, LegacyCryptoError> {
    if key.len() != 32 {
        return Err(LegacyCryptoError::InvalidKeyLength);
    }
    if iv.len() != 16 {
        return Err(LegacyCryptoError::InvalidIvLength);
    }

    let mut ciphertext = plaintext.to_vec();
    
    // VULNERABLE: Direct key usage without KDF
    let cipher = Aes256Ctr::new_from_slices(key, iv)
        .map_err(|_| LegacyCryptoError::EncryptionFailed)?;
    
    // VULNERABLE: No authentication
    cipher.apply_keystream(&mut ciphertext);
    
    Ok(ciphertext)
}

/// Vulnerable AES-256-CTR decryption
/// 
/// ⚠️  VULNERABLE: No quantum resistance, no authentication
pub fn decrypt_aes256ctr_vulnerable(
    ciphertext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, LegacyCryptoError> {
    if key.len() != 32 {
        return Err(LegacyCryptoError::InvalidKeyLength);
    }
    if iv.len() != 16 {
        return Err(LegacyCryptoError::InvalidIvLength);
    }

    let mut plaintext = ciphertext.to_vec();
    
    // VULNERABLE: Same key for encryption/decryption
    let cipher = Aes256Ctr::new_from_slices(key, iv)
        .map_err(|_| LegacyCryptoError::DecryptionFailed)?;
    
    cipher.apply_keystream(&mut plaintext);
    
    Ok(plaintext)
}

/// Vulnerable HMAC-SHA256 (for comparison with post-quantum signatures)
/// 
/// ⚠️  VULNERABLE: Classical cryptography, no quantum resistance
pub fn hmac_sha256_vulnerable(
    data: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, LegacyCryptoError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| LegacyCryptoError::InvalidKeyLength)?;
    
    mac.update(data);
    
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Vulnerable key derivation (for educational purposes)
/// 
/// ⚠️  VULNERABLE: No salt, no iterations, direct SHA256
pub fn derive_key_vulnerable(password: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    
    // VULNERABLE: No salt, no PBKDF2/Argon2
    let mut hasher = Sha256::new();
    hasher.update(password);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerable_encryption_decryption() {
        let key = b"0123456789abcdef0123456789abcdef"; // 32 bytes
        let iv = b"0123456789abcdef"; // 16 bytes
        let plaintext = b"Hello, vulnerable world!";
        
        let ciphertext = encrypt_aes256ctr_vulnerable(plaintext, key, iv).unwrap();
        let decrypted = decrypt_aes256ctr_vulnerable(&ciphertext, key, iv).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_vulnerable_hmac() {
        let key = b"weak_key";
        let data = b"important_data";
        
        let mac = hmac_sha256_vulnerable(data, key).unwrap();
        assert_eq!(mac.len(), 32); // SHA256 output size
    }

    #[test]
    fn test_vulnerable_key_derivation() {
        let password = b"password123";
        let key1 = derive_key_vulnerable(password);
        let key2 = derive_key_vulnerable(password);
        
        assert_eq!(key1, key2); // Deterministic (VULNERABLE!)
    }
}