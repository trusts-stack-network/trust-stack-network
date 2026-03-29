use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Address size in bytes (160 bits = 20 bytes, like Ethereum)
pub const ADDRESS_SIZE: usize = 20;

/// A blockchain address derived from the hash of a public key.
///
/// Addresses are the first 20 bytes (160 bits) of the SHA-256 hash
/// of the Dilithium public key. This provides a compact identifier
/// while maintaining sufficient collision resistance.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address([u8; ADDRESS_SIZE]);

impl Address {
    /// Create an address from raw bytes.
    pub fn from_bytes(bytes: [u8; ADDRESS_SIZE]) -> Self {
        Self(bytes)
    }

    /// Derive an address from a public key.
    ///
    /// The address is SHA-256(public_key)[0..20].
    pub fn from_public_key(public_key: &[u8]) -> Self {
        let hash = Sha256::digest(public_key);
        let mut addr = [0u8; ADDRESS_SIZE];
        addr.copy_from_slice(&hash[..ADDRESS_SIZE]);
        Self(addr)
    }

    /// Parse an address from a hex string.
    pub fn from_hex(s: &str) -> Result<Self, AddressError> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|_| AddressError::InvalidHex)?;
        if bytes.len() != ADDRESS_SIZE {
            return Err(AddressError::InvalidLength(bytes.len()));
        }
        let mut addr = [0u8; ADDRESS_SIZE];
        addr.copy_from_slice(&bytes);
        Ok(Self(addr))
    }

    /// Convert to a hex string (without 0x prefix).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; ADDRESS_SIZE] {
        &self.0
    }

    /// Create a zero address (used for coinbase transactions).
    pub fn zero() -> Self {
        Self([0u8; ADDRESS_SIZE])
    }

    /// Check if this is the zero address.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; ADDRESS_SIZE]
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", self.to_hex())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address(0x{})", self.to_hex())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AddressError {
    #[error("Invalid hex encoding")]
    InvalidHex,
    #[error("Invalid address length: expected {}, got {0}", ADDRESS_SIZE)]
    InvalidLength(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_from_public_key() {
        let fake_pk = vec![0u8; 1952]; // Dilithium3 public key size
        let addr = Address::from_public_key(&fake_pk);

        assert_eq!(addr.as_bytes().len(), ADDRESS_SIZE);
    }

    #[test]
    fn test_address_hex_roundtrip() {
        let addr = Address::from_bytes([
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22,
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
        ]);

        let hex = addr.to_hex();
        let parsed = Address::from_hex(&hex).unwrap();

        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_address_with_0x_prefix() {
        let hex = "0x123456789abcdef0112233445566778899aabbcc";
        let addr = Address::from_hex(hex).unwrap();

        assert_eq!(addr.to_hex(), "123456789abcdef0112233445566778899aabbcc");
    }

    #[test]
    fn test_zero_address() {
        let zero = Address::zero();
        assert!(zero.is_zero());
        assert_eq!(zero.as_bytes(), &[0u8; ADDRESS_SIZE]);
    }

    #[test]
    fn test_different_keys_different_addresses() {
        let pk1 = vec![1u8; 1952];
        let pk2 = vec![2u8; 1952];

        let addr1 = Address::from_public_key(&pk1);
        let addr2 = Address::from_public_key(&pk2);

        assert_ne!(addr1, addr2);
    }
}
