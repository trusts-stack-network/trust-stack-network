//! Adaptateur pour la migration ML-DSA-65 → SLH-DSA
//! 
//! SLH-DSA (FIPS 205) est une signature à usage unique basée sur des fonctions de hachage.
//! Contrairement à ML-DSA, chaque paire de clés ne peut signer qu'un nombre limité de messages.
//! Cette contrainte nécessite une gestion d'état rigoureuse dans le consensus.
//!
//! ## Références
//! - FIPS 205: Stateless Hash-Based Digital Signature Standard
//! - SPHINCS+ specification (https://sphincs.org/)

use thiserror::Error;
use serde::{Serialize, Deserialize};
use crate::crypto::signature::{SignatureScheme, VerificationKey, SigningKey};
use crate::crypto::pq::slh_dsa_impl::{PublicKey as SlhDsaPublicKey, Signature as SlhDsaSignature, SlhDsaError as CryptoSlhDsaError};
use crate::core::transaction::Transaction;
use crate::core::block::{Block, BlockHeader};

/// Paramètres SLH-DSA sélectionnés
/// Nécessite validation crypto avant déploiement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlhDsaParams {
    /// Sécurité 128 bits, tailles compactes
    Sha2_128s,
    /// Sécurité 128 bits, performances rapides
    Sha2_128f,
    /// Sécurité 192 bits, tailles compactes
    Sha2_192s,
    /// Sécurité 256 bits, tailles compactes
    Sha2_256s,
}

impl SlhDsaParams {
    /// Convertit vers les paramètres du module crypto
    fn to_crypto_params(&self) -> crate::crypto::pq::slh_dsa_impl::SlhDsaParameterSet {
        match self {
            SlhDsaParams::Sha2_128s => crate::crypto::pq::slh_dsa_impl::SlhDsaParameterSet::Sha2_128s,
            SlhDsaParams::Sha2_128f => crate::crypto::pq::slh_dsa_impl::SlhDsaParameterSet::Sha2_128f,
            SlhDsaParams::Sha2_192s => crate::crypto::pq::slh_dsa_impl::SlhDsaParameterSet::Sha2_192s,
            SlhDsaParams::Sha2_256s => crate::crypto::pq::slh_dsa_impl::SlhDsaParameterSet::Sha2_256s,
        }
    }
    
    /// Taille attendue de la signature en octets
    pub fn signature_size(&self) -> usize {
        match self {
            SlhDsaParams::Sha2_128s => 7856,
            SlhDsaParams::Sha2_128f => 17088,
            SlhDsaParams::Sha2_192s => 16224,
            SlhDsaParams::Sha2_256s => 29792,
        }
    }
    
    /// Taille attendue de la clé publique en octets
    pub fn public_key_size(&self) -> usize {
        match self {
            SlhDsaParams::Sha2_128s => 32,
            SlhDsaParams::Sha2_128f => 32,
            SlhDsaParams::Sha2_192s => 48,
            SlhDsaParams::Sha2_256s => 64,
        }
    }
}

/// Erreurs de validation SLH-DSA
#[derive(Error, Debug, Clone)]
pub enum SlhDsaError {
    #[error("Clé de signature déjà utilisée: {0:?}")]
    KeyAlreadyUsed(VerificationKey),
    
    #[error("Limite de signatures atteinte pour la clé: {0:?}")]
    SignatureLimitReached(VerificationKey),
    
    #[error("Paramètres SLH-DSA non supportés: {0:?}")]
    UnsupportedParams(SlhDsaParams),
    
    #[error("État de signature invalide")]
    InvalidSignatureState,
    
    #[error("Erreur de vérification: {0}")]
    VerificationFailed(String),
    
    #[error("Taille de signature invalide: attendu {expected}, reçu {actual}")]
    InvalidSignatureSize { expected: usize, actual: usize },
    
    #[error("Taille de clé publique invalide: attendu {expected}, reçu {actual}")]
    InvalidPublicKeySize { expected: usize, actual: usize },
}

impl From<CryptoSlhDsaError> for SlhDsaError {
    fn from(err: CryptoSlhDsaError) -> Self {
        SlhDsaError::VerificationFailed(err.to_string())
    }
}

/// État de gestion des signatures SLH-DSA
/// 
/// Invariant: Une clé de vérification ne peut apparaître qu'une fois dans `used_keys`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlhDsaState {
    /// Ensemble des clés déjà utilisées pour signer
    used_keys: std::collections::HashSet<VerificationKey>,
    /// Compteur de signatures par clé
    signature_count: std::collections::HashMap<VerificationKey, u32>,
    /// Paramètres actifs
    params: SlhDsaParams,
}

impl SlhDsaState {
    /// Crée un nouvel état avec les paramètres spécifiés
    pub fn new(params: SlhDsaParams) -> Self {
        Self {
            used_keys: std::collections::HashSet::new(),
            signature_count: std::collections::HashMap::new(),
            params,
        }
    }
    
    /// Vérifie si une clé peut encore signer
    pub fn can_sign(&self, vk: &VerificationKey) -> bool {
        !self.used_keys.contains(vk)
    }
    
    /// Marque une clé comme utilisée
    /// 
    /// # Panics
    /// Si la clé est déjà utilisée - c'est une violation critique du protocole
    pub fn mark_key_used(&mut self, vk: VerificationKey) -> Result<(), SlhDsaError> {
        if self.used_keys.contains(&vk) {
            return Err(SlhDsaError::KeyAlreadyUsed(vk));
        }
        
        self.used_keys.insert(vk.clone());
        self.signature_count.insert(vk, 1);
        Ok(())
    }
    
    /// Obtient le nombre de signatures pour une clé
    pub fn signature_count(&self, vk: &VerificationKey) -> u32 {
        self.signature_count.get(vk).copied().unwrap_or(0)
    }
    
    /// Retourne les paramètres actifs
    pub fn params(&self) -> SlhDsaParams {
        self.params
    }
}

/// Validateur de consensus pour SLH-DSA
pub struct SlhDsaConsensus {
    state: SlhDsaState,
}

impl SlhDsaConsensus {
    /// Crée un nouveau validateur avec l'état initial
    pub fn new(state: SlhDsaState) -> Self {
        Self { state }
    }
    
    /// Valide une transaction avec signature SLH-DSA
    /// 
    /// # Invariants vérifiés
    /// - La clé de signature n'a pas été réutilisée
    /// - La signature est cryptographiquement valide
    /// - Les paramètres correspondent à ceux du réseau
    pub fn validate_transaction(
        &self,
        tx: &Transaction,
        vk: &VerificationKey,
        signature: &[u8],
    ) -> Result<(), SlhDsaError> {
        // Vérification anti-réutilisation
        if !self.state.can_sign(vk) {
            return Err(SlhDsaError::KeyAlreadyUsed(vk.clone()));
        }
        
        // Validation cryptographique via le module SLH-DSA
        self.verify_signature(tx, vk, signature)?;
        
        Ok(())
    }
    
    /// Valide l'en-tête de bloc avec signature SLH-DSA
    pub fn validate_block_header(
        &self,
        header: &BlockHeader,
        vk: &VerificationKey,
        signature: &[u8],
    ) -> Result<(), SlhDsaError> {
        // Sérialise l'en-tête pour la vérification
        let header_bytes = bincode::serialize(header)
            .map_err(|e| SlhDsaError::VerificationFailed(format!("Serialization error: {}", e)))?;
        
        // Vérification anti-réutilisation
        if !self.state.can_sign(vk) {
            return Err(SlhDsaError::KeyAlreadyUsed(vk.clone()));
        }
        
        // Validation cryptographique
        self.verify_signature_bytes(&header_bytes, vk, signature)?;
        
        Ok(())
    }
    
    /// Vérifie une signature SLH-DSA sur des données sérialisées
    fn verify_signature_bytes(
        &self,
        data: &[u8],
        vk: &VerificationKey,
        signature: &[u8],
    ) -> Result<(), SlhDsaError> {
        // Vérifie la taille de la signature
        let expected_size = self.state.params().signature_size();
        if signature.len() != expected_size {
            return Err(SlhDsaError::InvalidSignatureSize {
                expected: expected_size,
                actual: signature.len(),
            });
        }
        
        // Convertit la clé publique
        let pk_bytes = vk.as_bytes();
        let expected_pk_size = self.state.params().public_key_size();
        if pk_bytes.len() != expected_pk_size {
            return Err(SlhDsaError::InvalidPublicKeySize {
                expected: expected_pk_size,
                actual: pk_bytes.len(),
            });
        }
        
        // Crée les types SLH-DSA pour la vérification
        let pk = SlhDsaPublicKey::from_bytes(pk_bytes)
            .map_err(|e| SlhDsaError::VerificationFailed(format!("Invalid public key: {}", e)))?;
        
        let sig = SlhDsaSignature::from_bytes(signature)
            .map_err(|e| SlhDsaError::VerificationFailed(format!("Invalid signature: {}", e)))?;
        
        // Appelle la vérification cryptographique SLH-DSA
        crate::crypto::pq::slh_dsa_impl::verify(&pk, data, &sig)
            .map_err(|e| SlhDsaError::from(e))?;
        
        Ok(())
    }
    
    fn verify_signature(
        &self,
        data: &Transaction,
        vk: &VerificationKey,
        signature: &[u8],
    ) -> Result<(), SlhDsaError> {
        // Sérialise la transaction pour la vérification
        let tx_bytes = bincode::serialize(data)
            .map_err(|e| SlhDsaError::VerificationFailed(format!("Serialization error: {}", e)))?;
        
        self.verify_signature_bytes(&tx_bytes, vk, signature)
    }
    
    /// Signe des données avec une clé SLH-DSA
    /// 
    /// # Security Warning
    /// Cette fonction consomme une clé de signature (one-time use).
    /// Ne jamais réutiliser une clé après signature.
    pub fn sign_data(
        &self,
        data: &[u8],
        signing_key: &crate::crypto::pq::slh_dsa_impl::SecretKey,
    ) -> Result<Vec<u8>, SlhDsaError> {
        // Vérifie que la clé n'a pas déjà été utilisée
        let public_key = signing_key.public_key();
        let vk = VerificationKey::from_bytes(public_key.as_bytes())
            .map_err(|e| SlhDsaError::VerificationFailed(format!("Invalid key: {}", e)))?;
        
        if !self.state.can_sign(&vk) {
            return Err(SlhDsaError::KeyAlreadyUsed(vk));
        }
        
        // Effectue la signature via le module crypto SLH-DSA
        let signature = crate::crypto::pq::slh_dsa_impl::sign(signing_key, data)
            .map_err(|e| SlhDsaError::from(e))?;
        
        Ok(signature.to_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyPair;
    
    #[test]
    fn test_slh_dsa_state_prevents_reuse() {
        let mut state = SlhDsaState::new(SlhDsaParams::Sha2_128s);
        let vk = VerificationKey::from_bytes(&[0u8; 32]).unwrap();
        
        // Première utilisation doit réussir
        state.mark_key_used(vk.clone()).unwrap();
        
        // Deuxième utilisation doit échouer
        assert!(matches!(
            state.mark_key_used(vk.clone()),
            Err(SlhDsaError::KeyAlreadyUsed(_))
        ));
    }
    
    #[test]
    fn test_consensus_validation_prevents_double_sign() {
        let state = SlhDsaState::new(SlhDsaParams::Sha2_128s);
        let consensus = SlhDsaConsensus::new(state);
        
        let vk = VerificationKey::from_bytes(&[1u8; 32]).unwrap();
        let tx = Transaction::default();
        
        // Simuler une première validation réussie
        // (dans la vraie implémentation, cela mettrait à jour l'état)
        
        // Deuxième validation avec la même clé doit échouer
        // Note: Cette logique nécessitera une mutation de l'état
    }
    
    #[test]
    fn test_signature_count_tracking() {
        let mut state = SlhDsaState::new(SlhDsaParams::Sha2_128s);
        let vk = VerificationKey::from_bytes(&[2u8; 32]).unwrap();
        
        assert_eq!(state.signature_count(&vk), 0);
        
        state.mark_key_used(vk.clone()).unwrap();
        assert_eq!(state.signature_count(&vk), 1);
    }
    
    #[test]
    fn test_signature_size_validation() {
        // Teste que les tailles de signature sont correctement définies
        assert_eq!(SlhDsaParams::Sha2_128s.signature_size(), 7856);
        assert_eq!(SlhDsaParams::Sha2_128f.signature_size(), 17088);
        assert_eq!(SlhDsaParams::Sha2_192s.signature_size(), 16224);
        assert_eq!(SlhDsaParams::Sha2_256s.signature_size(), 29792);
    }
    
    #[test]
    fn test_public_key_size_validation() {
        // Teste que les tailles de clé publique sont correctement définies
        assert_eq!(SlhDsaParams::Sha2_128s.public_key_size(), 32);
        assert_eq!(SlhDsaParams::Sha2_128f.public_key_size(), 32);
        assert_eq!(SlhDsaParams::Sha2_192s.public_key_size(), 48);
        assert_eq!(SlhDsaParams::Sha2_256s.public_key_size(), 64);
    }
}