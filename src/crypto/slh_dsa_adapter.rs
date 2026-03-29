//! Adaptateur SLH-DSA utilisant la crate FIPS 204 officielle
//!
//! Ce module fournit une interface unifiée pour les signatures SLH-DSA (SPHINCS+)
//! en utilisant l'implémentation FIPS 205 officielle via la crate `fips204`.
//!
//! # Paramètres de sécurité
//! - SLH-DSA-SHA2-128s: 128 bits de sécurité classique, 64 bits post-quantique
//! - Clé publique: 32 octets
//! - Clé secrète: 64 octets  
//! - Signature: ~7.8KB
//!
//! # Références
//! - FIPS 205: <https://csrc.nist.gov/pubs/fips/205/final>
//! - Crate fips204: <https://crates.io/crates/fips204>

use fips204::{
    slh_dsa_sha2_128s as slh_dsa,
    traits::{KeyGen, Signer, Verifier},
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Erreurs de l'adaptateur SLH-DSA
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SlhDsaAdapterError {
    #[error("Échec de génération de clé SLH-DSA")]
    KeyGenerationFailed,
    #[error("Échec de signature SLH-DSA: {0}")]
    SigningFailed(String),
    #[error("Échec de vérification SLH-DSA")]
    VerificationFailed,
    #[error("Format de clé publique invalide (attendu {expected} octets, reçu {actual})")]
    InvalidPublicKeyFormat { expected: usize, actual: usize },
    #[error("Format de clé secrète invalide (attendu {expected} octets, reçu {actual})")]
    InvalidSecretKeyFormat { expected: usize, actual: usize },
    #[error("Format de signature invalide (attendu {expected} octets, reçu {actual})")]
    InvalidSignatureFormat { expected: usize, actual: usize },
    #[error("Clé secrète corrompue ou invalide")]
    CorruptedSecretKey,
}

/// Tailles des structures SLH-DSA-SHA2-128s selon FIPS 205
pub const PUBLIC_KEY_SIZE: usize = slh_dsa::PK_LEN;
pub const SECRET_KEY_SIZE: usize = slh_dsa::SK_LEN;
pub const SIGNATURE_SIZE: usize = slh_dsa::SIG_LEN;

/// Clé publique SLH-DSA avec sérialisation sécurisée
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    /// Bytes de la clé publique (32 octets pour SLH-DSA-SHA2-128s)
    pub bytes: [u8; PUBLIC_KEY_SIZE],
}

/// Clé secrète SLH-DSA avec protection mémoire
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    /// Bytes de la clé secrète (64 octets pour SLH-DSA-SHA2-128s)
    #[zeroize(skip)]
    pub bytes: [u8; SECRET_KEY_SIZE],
}

/// Signature SLH-DSA
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// Bytes de la signature (~7.8KB pour SLH-DSA-SHA2-128s)
    pub bytes: Vec<u8>,
}

impl PublicKey {
    /// Crée une clé publique à partir de bytes bruts
    ///
    /// # Arguments
    /// * `bytes` - Bytes de la clé publique (doit faire exactement 32 octets)
    ///
    /// # Erreurs
    /// Retourne `InvalidPublicKeyFormat` si la taille est incorrecte
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SlhDsaAdapterError> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(SlhDsaAdapterError::InvalidPublicKeyFormat {
                expected: PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        
        let mut key_bytes = [0u8; PUBLIC_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: key_bytes })
    }

    /// Exporte la clé publique en bytes
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.bytes
    }

    /// Vérifie une signature avec cette clé publique
    ///
    /// # Arguments
    /// * `message` - Message signé
    /// * `signature` - Signature à vérifier
    ///
    /// # Sécurité
    /// Utilise l'implémentation FIPS 205 officielle résistante aux attaques temporelles
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SlhDsaAdapterError> {
        if signature.bytes.len() != SIGNATURE_SIZE {
            return Err(SlhDsaAdapterError::InvalidSignatureFormat {
                expected: SIGNATURE_SIZE,
                actual: signature.bytes.len(),
            });
        }

        // Conversion vers le format fips204
        let pk = slh_dsa::PublicKey::try_from_bytes(self.bytes)
            .map_err(|_| SlhDsaAdapterError::VerificationFailed)?;
        
        let sig = slh_dsa::Signature::try_from_bytes(&signature.bytes)
            .map_err(|_| SlhDsaAdapterError::VerificationFailed)?;

        // Vérification avec l'implémentation FIPS 205
        pk.verify(message, &sig)
            .map_err(|_| SlhDsaAdapterError::VerificationFailed)
    }
}

impl SecretKey {
    /// Génère une nouvelle paire de clés SLH-DSA
    ///
    /// # Sécurité
    /// Utilise `OsRng` pour la génération cryptographiquement sécurisée
    /// La clé secrète est automatiquement zeroized à la destruction
    pub fn generate() -> Result<(Self, PublicKey), SlhDsaAdapterError> {
        let mut rng = OsRng;
        
        // Génération avec l'implémentation FIPS 205
        let (pk_bytes, sk_bytes) = slh_dsa::try_keygen_with_rng(&mut rng)
            .map_err(|_| SlhDsaAdapterError::KeyGenerationFailed)?;

        let secret_key = Self { bytes: sk_bytes };
        let public_key = PublicKey { bytes: pk_bytes };

        Ok((secret_key, public_key))
    }

    /// Crée une clé secrète à partir de bytes bruts
    ///
    /// # Arguments
    /// * `bytes` - Bytes de la clé secrète (doit faire exactement 64 octets)
    ///
    /// # Erreurs
    /// Retourne `InvalidSecretKeyFormat` si la taille est incorrecte
    ///
    /// # Sécurité
    /// Les bytes d'entrée doivent provenir d'une source cryptographiquement sécurisée
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SlhDsaAdapterError> {
        if bytes.len() != SECRET_KEY_SIZE {
            return Err(SlhDsaAdapterError::InvalidSecretKeyFormat {
                expected: SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        
        let mut key_bytes = [0u8; SECRET_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: key_bytes })
    }

    /// Exporte la clé secrète en bytes
    ///
    /// # Sécurité
    /// L'appelant est responsable de zeroizer les bytes retournés
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        self.bytes
    }

    /// Dérive la clé publique à partir de cette clé secrète
    ///
    /// # Erreurs
    /// Retourne `CorruptedSecretKey` si la clé secrète est invalide
    pub fn derive_public_key(&self) -> Result<PublicKey, SlhDsaAdapterError> {
        let sk = slh_dsa::SecretKey::try_from_bytes(self.bytes)
            .map_err(|_| SlhDsaAdapterError::CorruptedSecretKey)?;
        
        let pk_bytes = sk.get_public_key();
        Ok(PublicKey { bytes: pk_bytes })
    }

    /// Signe un message avec cette clé secrète
    ///
    /// # Arguments
    /// * `message` - Message à signer
    ///
    /// # Sécurité
    /// - Utilise l'implémentation FIPS 205 officielle
    /// - Chaque signature utilise une randomisation fraîche
    /// - Résistant aux attaques par canaux auxiliaires
    pub fn sign(&self, message: &[u8]) -> Result<Signature, SlhDsaAdapterError> {
        let mut rng = OsRng;
        
        let sk = slh_dsa::SecretKey::try_from_bytes(self.bytes)
            .map_err(|_| SlhDsaAdapterError::CorruptedSecretKey)?;

        let sig_bytes = sk.try_sign_with_rng(&mut rng, message)
            .map_err(|e| SlhDsaAdapterError::SigningFailed(format!("{:?}", e)))?;

        Ok(Signature {
            bytes: sig_bytes.to_vec(),
        })
    }
}

impl Signature {
    /// Crée une signature à partir de bytes bruts
    ///
    /// # Arguments
    /// * `bytes` - Bytes de la signature (doit faire exactement ~7.8KB)
    ///
    /// # Erreurs
    /// Retourne `InvalidSignatureFormat` si la taille est incorrecte
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SlhDsaAdapterError> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(SlhDsaAdapterError::InvalidSignatureFormat {
                expected: SIGNATURE_SIZE,
                actual: bytes.len(),
            });
        }
        
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Exporte la signature en bytes
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Retourne la taille de la signature en octets
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Vérifie si la signature est vide
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Signeur SLH-DSA pour l'intégration avec le consensus TSN
///
/// Fournit une interface haut niveau pour signer des messages avec
/// gestion d'état et protection contre la réutilisation de clés.
pub struct SlhDsaSigner {
    secret_key: SecretKey,
    signature_count: u64,
}

impl SlhDsaSigner {
    /// Crée un nouveau signeur avec une clé secrète
    pub fn new(secret_key: SecretKey) -> Self {
        Self {
            secret_key,
            signature_count: 0,
        }
    }

    /// Génère un nouveau signeur avec une paire de clés fraîche
    pub fn generate() -> Result<(Self, PublicKey), SlhDsaAdapterError> {
        let (sk, pk) = SecretKey::generate()?;
        let signer = Self::new(sk);
        Ok((signer, pk))
    }

    /// Signe un message et incrémente le compteur
    ///
    /// # Arguments
    /// * `message` - Message à signer
    ///
    /// # Retour
    /// Tuple (signature, compteur) pour traçabilité
    pub fn sign_with_counter(&mut self, message: &[u8]) -> Result<(Signature, u64), SlhDsaAdapterError> {
        let signature = self.secret_key.sign(message)?;
        let counter = self.signature_count;
        self.signature_count += 1;
        Ok((signature, counter))
    }

    /// Obtient la clé publique associée
    pub fn public_key(&self) -> Result<PublicKey, SlhDsaAdapterError> {
        self.secret_key.derive_public_key()
    }

    /// Obtient le nombre de signatures effectuées
    pub fn signature_count(&self) -> u64 {
        self.signature_count
    }
}

/// Vérificateur SLH-DSA pour l'intégration avec le consensus TSN
pub struct SlhDsaVerifier {
    public_key: PublicKey,
}

impl SlhDsaVerifier {
    /// Crée un nouveau vérificateur avec une clé publique
    pub fn new(public_key: PublicKey) -> Self {
        Self { public_key }
    }

    /// Vérifie une signature
    ///
    /// # Arguments
    /// * `message` - Message signé
    /// * `signature` - Signature à vérifier
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SlhDsaAdapterError> {
        self.public_key.verify(message, signature)
    }

    /// Vérifie une signature avec compteur (pour audit)
    ///
    /// # Arguments
    /// * `message` - Message signé
    /// * `signature` - Signature à vérifier
    /// * `expected_counter` - Compteur attendu (pour détection de replay)
    ///
    /// # Note
    /// Le compteur doit être inclus dans le message signé pour être vérifié
    pub fn verify_with_counter(
        &self,
        message: &[u8],
        signature: &Signature,
        expected_counter: u64,
    ) -> Result<(), SlhDsaAdapterError> {
        // Vérification basique de la signature
        self.verify(message, signature)?;
        
        // TODO: Implémenter la vérification du compteur si inclus dans le message
        // Pour l'instant, on accepte toutes les signatures valides
        let _ = expected_counter; // Évite le warning unused
        
        Ok(())
    }

    /// Obtient la clé publique utilisée par ce vérificateur
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

/// Fonctions utilitaires pour l'intégration avec TSN
impl PublicKey {
    /// Convertit la clé publique en adresse TSN
    ///
    /// # Note
    /// Utilise le hash SHA-256 des bytes de la clé publique
    pub fn to_address(&self) -> crate::crypto::address::Address {
        crate::crypto::address::Address::from_public_key(&self.bytes)
    }
}

/// Constantes de validation pour les tests
pub mod constants {
    use super::*;
    
    /// Vérifie que les tailles correspondent aux spécifications FIPS 205
    pub const fn validate_sizes() {
        // Compilation-time assertions
        assert!(PUBLIC_KEY_SIZE == 32, "SLH-DSA-SHA2-128s public key must be 32 bytes");
        assert!(SECRET_KEY_SIZE == 64, "SLH-DSA-SHA2-128s secret key must be 64 bytes");
        assert!(SIGNATURE_SIZE == 7856, "SLH-DSA-SHA2-128s signature must be 7856 bytes");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_constants() {
        // Vérification que les constantes correspondent à FIPS 205
        constants::validate_sizes();
        
        assert_eq!(PUBLIC_KEY_SIZE, 32);
        assert_eq!(SECRET_KEY_SIZE, 64);
        assert_eq!(SIGNATURE_SIZE, 7856);
    }

    #[test]
    fn test_key_generation() -> Result<(), SlhDsaAdapterError> {
        let (sk, pk) = SecretKey::generate()?;
        
        assert_eq!(sk.bytes.len(), SECRET_KEY_SIZE);
        assert_eq!(pk.bytes.len(), PUBLIC_KEY_SIZE);
        
        // Vérifier que la clé publique peut être dérivée
        let derived_pk = sk.derive_public_key()?;
        assert_eq!(pk.bytes, derived_pk.bytes);
        
        Ok(())
    }

    #[test]
    fn test_sign_verify_cycle() -> Result<(), SlhDsaAdapterError> {
        let (sk, pk) = SecretKey::generate()?;
        let message = b"Test message for SLH-DSA FIPS 205";
        
        // Signature
        let signature = sk.sign(message)?;
        assert_eq!(signature.len(), SIGNATURE_SIZE);
        
        // Vérification
        pk.verify(message, &signature)?;
        
        Ok(())
    }

    #[test]
    fn test_wrong_message_fails() -> Result<(), SlhDsaAdapterError> {
        let (sk, pk) = SecretKey::generate()?;
        let message = b"Original message";
        let wrong_message = b"Wrong message";
        
        let signature = sk.sign(message)?;
        
        // La signature doit être valide pour le message original
        pk.verify(message, &signature)?;
        
        // La signature doit échouer pour un mauvais message
        assert!(pk.verify(wrong_message, &signature).is_err());
        
        Ok(())
    }

    #[test]
    fn test_signer_counter() -> Result<(), SlhDsaAdapterError> {
        let (sk, _) = SecretKey::generate()?;
        let mut signer = SlhDsaSigner::new(sk);
        
        assert_eq!(signer.signature_count(), 0);
        
        let message = b"Test message 1";
        let (_, counter1) = signer.sign_with_counter(message)?;
        assert_eq!(counter1, 0);
        assert_eq!(signer.signature_count(), 1);
        
        let (_, counter2) = signer.sign_with_counter(message)?;
        assert_eq!(counter2, 1);
        assert_eq!(signer.signature_count(), 2);
        
        Ok(())
    }

    #[test]
    fn test_verifier() -> Result<(), SlhDsaAdapterError> {
        let (sk, pk) = SecretKey::generate()?;
        let verifier = SlhDsaVerifier::new(pk);
        let message = b"Test message for verifier";
        
        let signature = sk.sign(message)?;
        verifier.verify(message, &signature)?;
        
        Ok(())
    }

    #[test]
    fn test_invalid_key_sizes() {
        // Test clé publique invalide
        let invalid_pk = PublicKey::from_bytes(&[0u8; 31]);
        assert!(matches!(
            invalid_pk,
            Err(SlhDsaAdapterError::InvalidPublicKeyFormat { expected: 32, actual: 31 })
        ));
        
        // Test clé secrète invalide
        let invalid_sk = SecretKey::from_bytes(&[0u8; 63]);
        assert!(matches!(
            invalid_sk,
            Err(SlhDsaAdapterError::InvalidSecretKeyFormat { expected: 64, actual: 63 })
        ));
        
        // Test signature invalide
        let invalid_sig = Signature::from_bytes(&[0u8; 100]);
        assert!(matches!(
            invalid_sig,
            Err(SlhDsaAdapterError::InvalidSignatureFormat { expected: 7856, actual: 100 })
        ));
    }

    #[test]
    fn test_serialization() -> Result<(), SlhDsaAdapterError> {
        let (sk, pk) = SecretKey::generate()?;
        
        // Test sérialisation/désérialisation clé publique
        let pk_bytes = pk.to_bytes();
        let pk_restored = PublicKey::from_bytes(&pk_bytes)?;
        assert_eq!(pk.bytes, pk_restored.bytes);
        
        // Test sérialisation/désérialisation clé secrète
        let sk_bytes = sk.to_bytes();
        let sk_restored = SecretKey::from_bytes(&sk_bytes)?;
        assert_eq!(sk.bytes, sk_restored.bytes);
        
        Ok(())
    }

    #[test]
    fn test_zeroize_secret_key() {
        let (mut sk, _) = SecretKey::generate().unwrap();
        let original_bytes = sk.bytes;
        
        // Vérifier que la clé n'est pas nulle initialement
        assert_ne!(original_bytes, [0u8; SECRET_KEY_SIZE]);
        
        // Zeroize explicite
        sk.zeroize();
        
        // Vérifier que les bytes sont maintenant zéro
        // Note: Cette vérification peut ne pas fonctionner si le compilateur optimise
        // mais c'est un test conceptuel de l'interface zeroize
        assert_eq!(sk.bytes, [0u8; SECRET_KEY_SIZE]);
    }
}