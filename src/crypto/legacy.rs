//! Legacy cryptographic primitives for backward compatibility
//! 
//! This module provides legacy cryptographic functions that are being
//! phased out in favor of post-quantum alternatives.
//! 
//! # Security Warning
//! Functions in this module should only be used for migration purposes.
//! New code should use the post-quantum primitives in `src/crypto/pq/`.

use thiserror::Error;

/// Errors that can occur during legacy cryptographic operations
#[derive(Debug, Error)]
pub enum LegacyCryptoError {
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    
    #[error("Operation not supported for legacy crypto")]
    OperationNotSupported,
}

/// Result type for legacy crypto operations
pub type Result<T> = std::result::Result<T, LegacyCryptoError>;

/// Legacy signature verification (for migration only)
pub fn verify_legacy_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool> {
    // SAFETY: This is a temporary migration function
    // TODO: Remove after block height 1_000_000
    if public_key.len() != 32 {
        return Err(LegacyCryptoError::InvalidKeyLength {
            expected: 32,
            actual: public_key.len(),
        });
    }
    
    // Placeholder implementation - replace with actual legacy verification
    Ok(signature.len() == 64)
}

/// Legacy key derivation (for migration only)
pub fn derive_legacy_key(
    seed: &[u8],
    index: u32,
) -> Result<[u8; 32]> {
    use sha2::{Sha256, Digest};
    
    if seed.len() < 16 {
        return Err(LegacyCryptoError::InvalidKeyLength {
            expected: 16,
            actual: seed.len(),
        });
    }
    
    let mut hasher = Sha256::new();
    hasher.update(b"tsn_legacy_key");
    hasher.update(seed);
    hasher.update(index.to_le_bytes());
    
    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legacy_key_derivation() {
        let seed = b"test_seed_123456";
        let key = derive_legacy_key(seed, 0).unwrap();
        assert_eq!(key.len(), 32);
        
        // Derivation should be deterministic
        let key2 = derive_legacy_key(seed, 0).unwrap();
        assert_eq!(key, key2);
        
        // Different indices should produce different keys
        let key3 = derive_legacy_key(seed, 1).unwrap();
        assert_ne!(key, key3);
    }

    #[test]
    fn test_invalid_seed_length() {
        let short_seed = b"short";
        let result = derive_legacy_key(short_seed, 0);
        assert!(matches!(
            result,
            Err(LegacyCryptoError::InvalidKeyLength { .. })
        ));
    }
}