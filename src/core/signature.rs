//! SLH-DSA (SPHINCS+) Signature Scheme Implementation
//! 
//! Remplace ML-DSA-65 par SLH-DSA-SHA2-128s (FIPS 205)
//! - Sécurité: NIST Level 1 (équivalent AES-128)
//! - Clé publique: 32 octets
//! - Signature: 7 856 octets
//! 
//! Alternative disponible: SLH-DSA-SHA2-256s pour Level 3 (pk=64, sig=29792)

use sha2::{Sha256, Digest};
use std::fmt;
use thiserror::Error;

/// Erreurs de signature SLH-DSA
#[derive(Error, Debug, Clone, PartialEq)]
pub enum SignatureError {
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Invalid signature length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("Invalid public key length")]
    InvalidPublicKey,
    #[error("Context string too long")]
    ContextTooLong,
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
}

/// Paramètres SLH-DSA utilisés
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlhDsaVariant {
    /// SLH-DSA-SHA2-128s: Petit, NIST Level 1
    Sha2_128s,
    /// SLH-DSA-SHA2-128f: Rapide, NIST Level 1  
    Sha2_128f,
    /// SLH-DSA-SHA2-256s: Petit, NIST Level 3
    Sha2_256s,
    /// SLH-DSA-SHA2-256f: Rapide, NIST Level 3
    Sha2_256f,
}

impl SlhDsaVariant {
    pub const fn public_key_size(&self) -> usize {
        match self {
            SlhDsaVariant::Sha2_128s | SlhDsaVariant::Sha2_128f => 32,
            SlhDsaVariant::Sha2_256s | SlhDsaVariant::Sha2_256f => 64,
        }
    }

    pub const fn signature_size(&self) -> usize {
        match self {
            SlhDsaVariant::Sha2_128s => 7856,
            SlhDsaVariant::Sha2_128f => 17088,
            SlhDsaVariant::Sha2_256s => 29792,
            SlhDsaVariant::Sha2_256f => 49856,
        }
    }
}

/// Clé publique SLH-DSA (taille fixe selon la variante)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SlhDsaPublicKey {
    bytes: [u8; 64], // Taille max pour Sha2_256s
    variant: SlhDsaVariant,
    len: usize,
}

impl SlhDsaPublicKey {
    pub const fn max_size() -> usize {
        64 // Sha2_256s/Sha2_256f
    }

    pub fn new(bytes: &[u8], variant: SlhDsaVariant) -> Result<Self, SignatureError> {