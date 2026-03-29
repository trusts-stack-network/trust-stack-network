//! Core types for blockchain with SLH-DSA (SPHINCS+) signatures
//! 
//! SLH-DSA-SHA2-128s parameters:
//! - Public key: 32 bytes
//! - Signature: 7,856 bytes (approx 7.8 KB)
//! - Security level: 128-bit (NIST Level 1)

use sha2::{Sha256, Digest};
use std::fmt;

/// Size of SLH-DSA-SHA2-128s public key
pub const SLH_DSA_PK_SIZE: usize = 32;
/// Size of SLH-DSA-SHA2-128s signature
pub const SLH_DSA_SIG_SIZE: usize = 7856;

/// SLH-DSA Public Key (hash-based, stateless)
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SlhDsaPublicKey(pub [u8; SLH_DSA_PK_SIZE]);

impl fmt::Debug for SlhDsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SlhDsaPublicKey({})", hex::encode(&self.0[..8]))
    }
}

impl AsRef<[u8]> for SlhDsaPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; SLH_DSA_PK_SIZE]> for SlhDsaPublicKey {
    fn from(bytes: [u8; SLH_DSA_PK_SIZE]) -> Self {
        Self(bytes)
    }
}

/// SLH-DSA Signature
/// 
/// Note: Much larger than ML-DSA-65 (3.3KB vs 7.8KB)
#[derive(Clone, PartialEq, Eq)]
pub struct SlhDsaSignature(pub [u8; SLH_DSA_SIG_SIZE]);

impl fmt::Debug for SlhDsaSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SlhDsaSignature({} bytes)", self.0.len())
    }
}

impl AsRef<[u8]> for SlhDsaSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; SLH_DSA_SIG_SIZE]> for SlhDsaSignature {
    fn from(bytes: [u8; SLH_DSA_SIG_SIZE]) -> Self {
        Self(bytes)
    }
}

/// Hash type (32 bytes)
pub type Hash = [u8; 32];

/// Transaction input
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionInput {
    pub prev_tx_hash: Hash,
    pub prev_output_index: u32,
    pub sequence: u32,
}

/// Transaction output
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionOutput {
    pub amount: u64,
    pub pubkey_hash: Hash, // Hash of SLH-DSA public key
}

/// Transaction with SLH-DSA signatures
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    /// SLH-DSA signatures for each input
    /// Previously ML-DSA-65 signatures (3.3KB), now SLH-DSA (7.8KB)
    pub witnesses: Vec<SlhDsaSignature>,
    pub lock_time: u