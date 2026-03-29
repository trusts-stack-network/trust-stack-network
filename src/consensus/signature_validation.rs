//! Validation des signatures de blocs et transactions
//! Support hybride ML-DSA-65 (legacy) et SLH-DSA (nouveau)
//! 
//! INVARIANTS:
//! - Une clé ne peut être utilisée qu'une seule fois dans SLH-DSA
//! - Les adresses de signature doivent être monotonically increasing
//! - La transition entre ML-DSA et SLH-DSA est gérée par un point d'activation
//!
//! ## Références
//! - FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)
//! - FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA)

use crate::crypto::{SignatureScheme, PublicKey, Signature, CryptoError};
use crate::crypto::pq::slh_dsa_impl::{self, PublicKey as SlhDsaPublicKey, Signature as SlhDsaSignature};
use crate::crypto::signature::verify_mldsa65;
use crate::core::{Block, Transaction, BlockHeader};
use thiserror::Error;
use std::collections::HashSet;

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("Signature invalide: {0}")]
    InvalidSignature(String),
    #[error("Clé SLH-DSA réutilisée: {0}")]
    SlhDsaKeyReuse(String),
    #[error("Adresse de signature invalide: {0}")]
    InvalidSignatureAddress(u64),
    #[error("Schéma de signature non supporté: {0}")]
    UnsupportedScheme(String),
    #[error("Erreur cryptographique: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("Erreur SLH-DSA: {0}")]
    SlhDsaError(String),
    #[error("Taille de signature invalide: attendu {expected}, reçu {actual}")]
    InvalidSignatureSize { expected: usize, actual: usize },
}

impl From<slh_dsa_impl::SlhDsaError> for SignatureError {
    fn from(err: slh_dsa_impl::SlhDsaError) -> Self {
        SignatureError::SlhDsaError(err.to_string())
    }
}

/// Point d'activation pour la transition ML-DSA → SLH-DSA
const SLH_DSA_ACTIVATION_HEIGHT: u64 = 1_000_000; // À calibrer avec l'équipe

/// Paramètres SLH-DSA par défaut pour le consensus
const DEFAULT_SLH_DSA_PARAMS: slh_dsa_impl::SlhDsaParameterSet = slh_dsa_impl::SlhDsaParameterSet::Sha2_128s;

/// Validateur de signatures pour le consensus
pub struct SignatureValidator {
    /// Ensemble des clés SLH-DSA déjà utilisées (empêche la réutilisation)
    used_slh_keys: HashSet<[u8; 32]>,
    /// Adresse de signature actuelle pour SLH-DSA
    current_signature_address: u64,
}

impl SignatureValidator {
    pub fn new() -> Self {
        Self {
            used_slh_keys: HashSet::new(),
            current_signature_address: 0,
        }
    }

    /// Valide la signature d'un bloc en fonction de sa hauteur
    pub fn validate_block_signature(
        &mut self,
        block: &Block,
        public_key: &PublicKey,
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        // Détermine le schéma de signature à utiliser
        let scheme = self.get_signature_scheme(block.header.height);
        
        match scheme {
            SignatureScheme::MlDsa65 => {
                self.validate_mldsa_signature(block, public_key, signature)
            }
            SignatureScheme::SlhDsa => {
                self.validate_slh_signature(block, public_key, signature)
            }
        }
    }

    /// Valide la signature d'une transaction
    pub fn validate_transaction_signature(
        &mut self,
        tx: &Transaction,
        public_key: &PublicKey,
        signature: &Signature,
        block_height: u64,
    ) -> Result<(), SignatureError> {
        let scheme = self.get_signature_scheme(block_height);
        
        match scheme {
            SignatureScheme::MlDsa65 => {
                self.validate_mldsa_signature(tx, public_key, signature)
            }
            SignatureScheme::SlhDsa => {
                // Pour les transactions, on utilise une adresse dérivée du hash
                let signature_address = self.derive_signature_address(tx);
                self.validate_slh_signature_with_address(
                    tx,
                    public_key,
                    signature,
                    signature_address,
                )
            }
        }
    }

    /// Détermine le schéma de signature à utiliser selon la hauteur du bloc
    fn get_signature_scheme(&self, block_height: u64) -> SignatureScheme {
        if block_height >= SLH_DSA_ACTIVATION_HEIGHT {
            SignatureScheme::SlhDsa
        } else {
            SignatureScheme::MlDsa65
        }
    }

    /// Valide une signature ML-DSA-65 (legacy)
    fn validate_mldsa_signature(
        &self,
        data: &impl AsRef<[u8]>,
        public_key: &PublicKey,
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        // Appelle la validation ML-DSA-65 du module crypto
        verify_mldsa65(public_key, data.as_ref(), signature)
            .map_err(|e| SignatureError::CryptoError(e))?;
        Ok(())
    }

    /// Valide une signature SLH-DSA avec vérification anti-réutilisation
    fn validate_slh_signature(
        &mut self,
        data: &impl AsRef<[u8]>,
        public_key: &PublicKey,
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        let key_id = self.derive_key_id(public_key);
        
        // Vérifie que la clé n'a pas été utilisée
        if self.used_slh_keys.contains(&key_id) {
            return Err(SignatureError::SlhDsaKeyReuse(
                format!("Clé déjà utilisée: {:?}", key_id)
            ));
        }

        // Valide la signature via le module crypto SLH-DSA
        self.verify_slh_signature(data, public_key, signature)?;

        // Marque la clé comme utilisée
        self.used_slh_keys.insert(key_id);
        self.current_signature_address += 1;

        Ok(())
    }

    /// Valide une signature SLH-DSA avec adresse spécifique
    fn validate_slh_signature_with_address(
        &mut self,
        data: &impl AsRef<[u8]>,
        public_key: &PublicKey,
        signature: &Signature,
        signature_address: u64,
    ) -> Result<(), SignatureError> {
        // Vérifie que l'adresse est valide
        if signature_address != self.current_signature_address {
            return Err(SignatureError::InvalidSignatureAddress(signature_address));
        }

        self.validate_slh_signature(data, public_key, signature)
    }

    /// Dérive un identifiant unique pour une clé publique
    fn derive_key_id(&self, public_key: &PublicKey) -> [u8; 32] {
        // Utilise SHA-256 pour dériver un identifiant unique de la clé publique
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(public_key.as_bytes());
        hasher.finalize().into()
    }

    /// Dérive une adresse de signature pour une transaction
    fn derive_signature_address(&self, tx: &Transaction) -> u64 {
        // Utilise une partie du hash de la transaction comme adresse
        // Les 8 premiers octets du hash forment l'adresse
        let hash_bytes = tx.hash.as_ref();
        if hash_bytes.len() >= 8 {
            let bytes: [u8; 8] = hash_bytes[0..8].try_into().unwrap_or([0u8; 8]);
            u64::from_le_bytes(bytes)
        } else {
            0
        }
    }

    /// Vérifie une signature SLH-DSA (appel au module crypto)
    /// 
    /// ## Implémentation
    /// Cette fonction utilise le module `slh_dsa_impl` pour la vérification
    /// cryptographique conforme à FIPS 205.
    ///
    /// ## Paramètres de sécurité
    /// - Algorithme: SLH-DSA-SHA2-128s (par défaut)
    /// - Niveau de sécurité: 128 bits post-quantique
    /// - Taille de signature: ~7.8 KB
    /// - Taille de clé publique: 32 octets
    fn verify_slh_signature(
        &self,
        data: &impl AsRef<[u8]>,
        public_key: &PublicKey,
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        // Vérifie la taille de la signature (≈8KB pour Sha2_128s)
        let expected_sig_size = DEFAULT_SLH_DSA_PARAMS.signature_size();
        let sig_bytes = signature.as_ref();
        
        if sig_bytes.len() != expected_sig_size {
            return Err(SignatureError::InvalidSignatureSize {
                expected: expected_sig_size,
                actual: sig_bytes.len(),
            });
        }
        
        // Vérifie la taille de la clé publique
        let expected_pk_size = DEFAULT_SLH_DSA_PARAMS.public_key_size();
        let pk_bytes = public_key.as_bytes();
        
        if pk_bytes.len() != expected_pk_size {
            return Err(SignatureError::SlhDsaError(format!(
                "Taille de clé publique invalide: attendu {}, reçu {}",
                expected_pk_size, pk_bytes.len()
            )));
        }
        
        // Convertit vers les types SLH-DSA
        let slh_pk = SlhDsaPublicKey::from_bytes(pk_bytes)
            .map_err(|e| SignatureError::SlhDsaError(format!("Clé publique invalide: {}", e)))?;
        
        let slh_sig = SlhDsaSignature::from_bytes(sig_bytes)
            .map_err(|e| SignatureError::SlhDsaError(format!("Signature invalide: {}", e)))?;
        
        // Appelle la vérification SLH-DSA du module crypto
        slh_dsa_impl::verify(&slh_pk, data.as_ref(), &slh_sig)
            .map_err(|e| SignatureError::from(e))?;
        
        Ok(())
    }
    
    /// Génère une paire de clés SLH-DSA pour les tests
    #[cfg(test)]
    pub fn generate_slh_keypair(
        &self,
    ) -> Result<(slh_dsa_impl::SecretKey, slh_dsa_impl::PublicKey), SignatureError> {
        let (sk, pk) = slh_dsa_impl::generate_keypair(DEFAULT_SLH_DSA_PARAMS)
            .map_err(|e| SignatureError::from(e))?;
        Ok((sk, pk))
    }
    
    /// Signe des données avec une clé SLH-DSA (pour les tests)
    #[cfg(test)]
    pub fn sign_with_slh(
        &self,
        data: &[u8],
        secret_key: &slh_dsa_impl::SecretKey,
    ) -> Result<Vec<u8>, SignatureError> {
        let signature = slh_dsa_impl::sign(secret_key, data)
            .map_err(|e| SignatureError::from(e))?;
        Ok(signature.to_bytes().to_vec())
    }
}

impl Default for SignatureValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{BlockHeader, Hash};
    use crate::crypto::{PrivateKey, KeyPair};

    fn create_test_block(height: u64) -> Block {
        Block {
            header: BlockHeader {
                height,
                timestamp: 1234567890,
                previous_hash: Hash::from_bytes([0u8; 32]),
                merkle_root: Hash::from_bytes([1u8; 32]),
                state_root: Hash::from_bytes([2u8; 32]),
                difficulty: 1000,
                nonce: 0,
            },
            transactions: vec![],
            signature: Signature::from_bytes(&[0u8; 64]).unwrap(),
        }
    }

    #[test]
    fn test_signature_scheme_selection() {
        let validator = SignatureValidator::new();
        
        // Avant activation: ML-DSA-65
        assert_eq!(
            validator.get_signature_scheme(SLH_DSA_ACTIVATION_HEIGHT - 1),
            SignatureScheme::MlDsa65
        );
        
        // Après activation: SLH-DSA
        assert_eq!(
            validator.get_signature_scheme(SLH_DSA_ACTIVATION_HEIGHT),
            SignatureScheme::SlhDsa
        );
    }

    #[test]
    fn test_slh_key_reuse_prevention() {
        let mut validator = SignatureValidator::new();
        let pk = PublicKey::from_bytes(&[0u8; 32]).unwrap();
        
        // Première validation
        let key_id = validator.derive_key_id(&pk);
        assert!(!validator.used_slh_keys.contains(&key_id));
        
        // Simule l'ajout de la clé
        validator.used_slh_keys.insert(key_id);
        assert!(validator.used_slh_keys.contains(&key_id));
    }

    #[test]
    fn test_signature_address_derivation() {
        let validator = SignatureValidator::new();
        let tx = Transaction::default();
        
        // L'adresse doit être dérivée des 8 premiers octets du hash
        let address = validator.derive_signature_address(&tx);
        
        // Vérifie que l'adresse est cohérente
        let expected_address = if tx.hash.as_ref().len() >= 8 {
            let bytes: [u8; 8] = tx.hash.as_ref()[0..8].try_into().unwrap();
            u64::from_le_bytes(bytes)
        } else {
            0
        };
        
        assert_eq!(address, expected_address);
    }
    
    #[test]
    fn test_key_id_derivation() {
        let validator = SignatureValidator::new();
        let pk1 = PublicKey::from_bytes(&[1u8; 32]).unwrap();
        let pk2 = PublicKey::from_bytes(&[2u8; 32]).unwrap();
        
        let id1 = validator.derive_key_id(&pk1);
        let id2 = validator.derive_key_id(&pk2);
        
        // Les IDs doivent être différents pour des clés différentes
        assert_ne!(id1, id2);
        
        // Les IDs doivent être déterministes
        assert_eq!(id1, validator.derive_key_id(&pk1));
    }
}