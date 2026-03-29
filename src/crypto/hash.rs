//! Hash primitives for TSN blockchain

use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};

pub const HASH_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash(pub [u8; HASH_LEN]);

impl Hash {
    pub fn zero() -> Self {
        Hash([0u8; HASH_LEN])
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl std::fmt::Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hash({})", hex::encode(&self.0[..4]))
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl Default for Hash {
    fn default() -> Self {
        Hash::zero()
    }
}

/// Compute SHA-256 hash of arbitrary data
pub fn hash(data: &[u8]) -> Hash {
    let result = Sha256::digest(data);
    let mut h = [0u8; HASH_LEN];
    h.copy_from_slice(&result);
    Hash(h)
}
