//! SLH-DSA (SPHINCS+) implementation wrapper
//! 
//! This module provides post-quantum signature types using SLH-DSA-SHA2-128f
//! as the default secure parameter set. SLH-DSA offers stateless hash-based
//! signatures with minimal public key sizes (~32 bytes) but larger signatures
//! (~7.8 KB for 128f parameter set).

use std::fmt;
use std::hash::{Hash, Hasher};
use rand::{CryptoRng, RngCore};

/// Size of SLH-DSA-SHA2-128f public key in bytes
pub const SLH_DSA_PUBLIC_KEY_SIZE: usize = 32;
/// Size of SLH-DSA-SHA2-128f secret key seed in bytes  
pub const SLH_DSA_SECRET_KEY_SIZE: usize = 64;
/// Size of SLH-DSA-SHA2-128f signature in bytes
pub const SLH_DSA_SIGNATURE_SIZE: usize = 7856;

/// Error types for SLH-DSA operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlhDsaError {
    InvalidPublicKey,
    InvalidSecretKey,
    InvalidSignature,
    SignatureVerificationFailed,
    RandomnessGenerationFailed,
    SerializationError,
}

impl fmt::Display for SlhDsaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKey => write!(f, "Invalid SLH-DSA public key"),
            Self::InvalidSecretKey => write!(f, "Invalid SLH-DSA secret key"),
            Self::InvalidSignature => write!(f, "Invalid SLH-DSA signature"),
            Self::SignatureVerificationFailed => write!(f, "Signature verification failed"),
            Self::RandomnessGenerationFailed => write!(f, "Failed to generate secure randomness"),
            Self::SerializationError => write!(f, "Serialization error"),
        }
    }
}

impl std::error::Error for SlhDsaError {}

/// SLH-DSA public key (32 bytes for 128f parameter set)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SlhDsaPublicKey {
    bytes: [u8; SLH_DSA_PUBLIC_KEY_SIZE],
}

impl SlhDsaPublicKey {
    pub const SIZE: usize = SLH_DSA_PUBLIC_KEY_SIZE;
    
    pub fn new(bytes: [u8; SLH_DSA_PUBLIC_KEY_SIZE]) -> Self {
        Self { bytes }
    }
    
    pub fn from_slice(slice: &[u8]) -> Result<Self, SlhDsaError> {
        if slice.len() != SLH_DSA_PUBLIC_KEY_SIZE {
            return Err(SlhDsaError::InvalidPublicKey);
        }
        let mut bytes = [0u8; SLH_DSA_PUBLIC_KEY_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    
    pub fn to_bytes(&self) -> [u8; SLH_DSA_PUBLIC_KEY_SIZE] {
        self.bytes
    }
}

impl fmt::Debug for SlhDsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SlhDsaPublicKey({})", hex::encode(&self.bytes[..8]))
    }
}

impl Hash for SlhDsaPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

/// SLH-DSA secret key seed (64 bytes, expands to full secret key internally)
#[derive(Clone)]
pub struct SlhDsaSecretKey {
    seed: [u8; SLH_DSA_SECRET_KEY_SIZE],
}

impl SlhDsaSecretKey {
    pub const SIZE: usize = SLH_DSA_SECRET_KEY_SIZE;
    
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self, SlhDsaError> {
        let mut seed = [0u8; SLH_DSA_SECRET_KEY_SIZE];
        rng.fill