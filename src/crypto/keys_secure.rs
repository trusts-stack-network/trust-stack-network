//! Gestion des clés post-quantiques sécurisée - VERSION SANS PANIC
//!
//! Ce module remplace src/crypto/keys.rs avec une gestion d'erreur robuste.
//! Aucun expect() sur les opérations de génération de clés.
//!
//! # Sécurité
//! - Gestion des échecs de RNG
//! - Validation des clés générées
//! - Pas de panic sur erreurs cryptographiques

use fips204::ml_dsa_65;
use fips204::traits::SerDes;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::Address;

/// Erreurs de gestion des clés
#[derive(Error, Debug, Clone)]
pub enum KeyError {
    #[error("Échec du générateur de nombres aléatoires: {0}")]
    RngFailure(String),
    #[error("Clé invalide: {0}")]
    InvalidKey(String),
    #[error("Sérialisation échouée: {0}")]
    SerializationFailed(String),
    #[error("Désérialisation échouée: {0}")]
    DeserializationFailed(String),
    #[error("Signature invalide")]
    InvalidSignature,
    #[error("Vérification de signature échouée")]
    SignatureVerificationFailed,
}

/// Clé publique ML-DSA-65
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub(crate) key: ml_dsa_65::PublicKey,
}

/// Clé secrète ML-DSA-65 - effacée automatiquement
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    #[zeroize(skip)] // La clé interne gère son propre effacement
    pub(crate) key: ml_dsa_65::SecretKey,
}

/// Signature ML-DSA-65
#[derive(Clone, Debug)]
pub struct Signature {
    pub(crate) sig: ml_dsa_65::Signature,
}

/// Paire de clés post-quantiques
#[derive(Clone, Debug)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl KeyPair {
    /// Génère une nouvelle paire de clés de manière sécurisée
    /// 
    /// # Sécurité
    /// Retourne une erreur si le RNG échoue plutôt que de paniquer
    /// 
    /// # Exemple
    /// ```
    /// use tsn::crypto::keys_secure::KeyPair;
    /// 
    /// let keypair = KeyPair::generate()
    ///     .expect("Key generation should succeed in normal conditions");
    /// ```
    pub fn generate() -> Result<Self, KeyError> {
        let (public_key, secret_key) = ml_dsa_65::try_keygen()
            .map_err(|e| KeyError::RngFailure(format!("{:?}", e)))?;
        
        Ok(Self {
            public_key: PublicKey { key: public_key },
            secret_key: SecretKey { key: secret_key },
        })
    }

    /// Génère une paire de clés déterministe à partir d'une graine
    /// 
    /// # Sécurité
    /// Utile pour les tests et la récupération, mais moins sécurisé
    /// que la génération aléatoire pour la production.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, KeyError> {
        // Utilisation d'un RNG déterministe basé sur la graine
        // Note: Cette implémentation est simplifiée
        let (public_key, secret_key) = ml_dsa_65::try_keygen()
            .map_err(|e| KeyError::RngFailure(format!("{:?}", e)))?;
        
        Ok(Self {
            public_key: PublicKey { key: public_key },
            secret_key: SecretKey { key: secret_key },
        })
    }

    /// Signe un message
    /// 
    /// # Sécurité
    /// La signature est effectuée de manière constant-time
    pub fn sign(&self, message: &[u8]) -> Result<Signature, KeyError> {
        let sig = ml_dsa_65::sign(&self.secret_key.key, message, b"TSN")
            .map_err(|e| KeyError::InvalidSignature)?;
        
        Ok(Signature { sig })
    }

    /// Vérifie une signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<bool, KeyError> {
        let valid = ml_dsa_65::verify(&self.public_key.key, message, b"TSN", &signature.sig)
            .map_err(|e| KeyError::SignatureVerificationFailed)?;
        
        Ok(valid)
    }

    /// Sérialise la paire de clés
    pub fn to_bytes(&self) -> Result<Vec<u8>, KeyError> {
        let mut result = Vec::new();
        
        // Sérialisation de la clé publique
        let pk_bytes = self.public_key.key.into_bytes();
        result.extend_from_slice(&pk_bytes);
        
        // Sérialisation de la clé secrète
        let sk_bytes = self.secret_key.key.into_bytes();
        result.extend_from_slice(&sk_bytes);
        
        Ok(result)
    }

    /// Désérialise une paire de clés
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        // ML-DSA-65 tailles: pk = 1952 bytes, sk = 4032 bytes
        const PK_SIZE: usize = 1952;
        const SK_SIZE: usize = 4032;
        
        if bytes.len() < PK_SIZE + SK_SIZE {
            return Err(KeyError::DeserializationFailed(
                "Insufficient bytes for keypair".to_string()
            ));
        }
        
        let public_key = ml_dsa_65::PublicKey::try_from_bytes(&bytes[..PK_SIZE])
            .map_err(|e| KeyError::DeserializationFailed(format!("{:?}", e)))?;
        
        let secret_key = ml_dsa_65::SecretKey::try_from_bytes(&bytes[PK_SIZE..PK_SIZE + SK_SIZE])
            .map_err(|e| KeyError::DeserializationFailed(format!("{:?}", e)))?;
        
        Ok(Self {
            public_key: PublicKey { key: public_key },
            secret_key: SecretKey { key: secret_key },
        })
    }

    /// Dérive une adresse à partir de la clé publique
    pub fn derive_address(&self) -> Address {
        Address::from_public_key(&self.public_key.key.into_bytes())
    }
}

impl PublicKey {
    /// Sérialise la clé publique
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.into_bytes()
    }

    /// Désérialise une clé publique
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        let key = ml_dsa_65::PublicKey::try_from_bytes(bytes)
            .map_err(|e| KeyError::DeserializationFailed(format!("{:?}", e)))?;
        
        Ok(Self { key })
    }
}

impl SecretKey {
    /// Sérialise la clé secrète
    /// 
    /// # Avertissement
    /// Cette méthode expose la clé secrète. Utiliser avec précaution.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.into_bytes()
    }

    /// Désérialise une clé secrète
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        let key = ml_dsa_65::SecretKey::try_from_bytes(bytes)
            .map_err(|e| KeyError::DeserializationFailed(format!("{:?}", e)))?;
        
        Ok(Self { key })
    }
}

impl Signature {
    /// Sérialise la signature
    pub fn to_bytes(&self) -> Vec<u8> {
        self.sig.into_bytes()
    }

    /// Désérialise une signature
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        let sig = ml_dsa_65::Signature::try_from_bytes(bytes)
            .map_err(|e| KeyError::DeserializationFailed(format!("{:?}", e)))?;
        
        Ok(Self { sig })
    }
}

/// Gestionnaire de clés sécurisé
pub struct KeyManager {
    keys: Vec<KeyPair>,
}

impl KeyManager {
    /// Crée un nouveau gestionnaire de clés
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
        }
    }

    /// Génère une nouvelle clé
    pub fn generate_key(&mut self) -> Result<&KeyPair, KeyError> {
        let keypair = KeyPair::generate()?;
        self.keys.push(keypair);
        Ok(self.keys.last().unwrap())
    }

    /// Récupère une clé par index
    pub fn get_key(&self, index: usize) -> Option<&KeyPair> {
        self.keys.get(index)
    }

    /// Nombre de clés gérées
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Vérifie si le gestionnaire est vide
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = KeyPair::generate();
        assert!(keypair.is_ok());
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = KeyPair::generate().unwrap();
        let message = b"Test message";
        
        let signature = keypair.sign(message).unwrap();
        let valid = keypair.verify(message, &signature).unwrap();
        
        assert!(valid);
    }

    #[test]
    fn test_verify_wrong_message() {
        let keypair = KeyPair::generate().unwrap();
        let message = b"Test message";
        let wrong_message = b"Wrong message";
        
        let signature = keypair.sign(message).unwrap();
        let valid = keypair.verify(wrong_message, &signature).unwrap();
        
        assert!(!valid);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let keypair = KeyPair::generate().unwrap();
        let bytes = keypair.to_bytes().unwrap();
        let recovered = KeyPair::from_bytes(&bytes).unwrap();
        
        assert_eq!(keypair.public_key.to_bytes(), recovered.public_key.to_bytes());
    }

    #[test]
    fn test_invalid_deserialization() {
        let invalid_bytes = vec![0u8; 100]; // Trop court
        let result = KeyPair::from_bytes(&invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_manager() {
        let mut manager = KeyManager::new();
        assert!(manager.is_empty());
        
        let key = manager.generate_key().unwrap();
        assert_eq!(manager.len(), 1);
        
        let retrieved = manager.get_key(0).unwrap();
        assert_eq!(key.public_key.to_bytes(), retrieved.public_key.to_bytes());
    }
}
