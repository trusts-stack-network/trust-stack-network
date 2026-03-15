use fips204::ml_dsa_65;
use fips204::traits::SerDes;

use super::Address;

/// A quantum-resistant keypair using ML-DSA-65 (FIPS 204).
///
/// ML-DSA (formerly CRYSTALS-Dilithium) is a lattice-based signature scheme
/// standardized by NIST in FIPS 204. It provides security against both
/// classical and quantum computer attacks.
#[derive(Clone)]
pub struct KeyPair {
    public_key: ml_dsa_65::PublicKey,
    secret_key: ml_dsa_65::PrivateKey,
}

impl KeyPair {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        // CRITICAL: keygen can only fail on catastrophic OS RNG failure — unrecoverable
        let (public_key, secret_key) = ml_dsa_65::try_keygen()
            .expect("CRITICAL: ML-DSA-65 keygen failed — OS RNG unavailable");
        Self {
            public_key,
            secret_key,
        }
    }

    /// Reconstruct a keypair from raw bytes.
    pub fn from_bytes(public_key: &[u8], secret_key: &[u8]) -> Result<Self, KeyError> {
        let pk_array: [u8; PUBLIC_KEY_SIZE] = public_key
            .try_into()
            .map_err(|_| KeyError::InvalidPublicKey)?;
        let sk_array: [u8; SECRET_KEY_SIZE] = secret_key
            .try_into()
            .map_err(|_| KeyError::InvalidSecretKey)?;

        let public_key = ml_dsa_65::PublicKey::try_from_bytes(pk_array)
            .map_err(|_| KeyError::InvalidPublicKey)?;
        let secret_key = ml_dsa_65::PrivateKey::try_from_bytes(sk_array)
            .map_err(|_| KeyError::InvalidSecretKey)?;

        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Get the public key bytes.
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.public_key.clone().into_bytes()
    }

    /// Get the secret key bytes.
    pub fn secret_key_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        self.secret_key.clone().into_bytes()
    }

    /// Get a reference to the internal public key.
    pub fn public_key(&self) -> &ml_dsa_65::PublicKey {
        &self.public_key
    }

    /// Get a reference to the internal secret key.
    pub fn secret_key(&self) -> &ml_dsa_65::PrivateKey {
        &self.secret_key
    }

    /// Derive the address from this keypair's public key.
    pub fn address(&self) -> Address {
        Address::from_public_key(&self.public_key_bytes())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("Invalid public key bytes")]
    InvalidPublicKey,
    #[error("Invalid secret key bytes")]
    InvalidSecretKey,
}

/// ML-DSA-65 key sizes (FIPS 204):
/// - Public key: 1952 bytes
/// - Secret key: 4032 bytes
/// - Signature: 3309 bytes
pub const PUBLIC_KEY_SIZE: usize = 1952;
pub const SECRET_KEY_SIZE: usize = 4032;
pub const SIGNATURE_SIZE: usize = 3309;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = KeyPair::generate();

        assert_eq!(keypair.public_key_bytes().len(), PUBLIC_KEY_SIZE);
        assert_eq!(keypair.secret_key_bytes().len(), SECRET_KEY_SIZE);
    }

    #[test]
    fn test_keypair_roundtrip() {
        let keypair = KeyPair::generate();
        let pk_bytes = keypair.public_key_bytes();
        let sk_bytes = keypair.secret_key_bytes();

        let restored = KeyPair::from_bytes(&pk_bytes, &sk_bytes).unwrap();

        assert_eq!(restored.public_key_bytes(), keypair.public_key_bytes());
        assert_eq!(restored.secret_key_bytes(), keypair.secret_key_bytes());
    }

    #[test]
    fn test_different_keypairs() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();

        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }
}
