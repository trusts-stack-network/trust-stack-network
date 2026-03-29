//! Abstraction des schémas de signature post-quantique
//! Support ML-DSA-65 (legacy) et SLH-DSA (nouveau) avec gouvernance configurable

use crate::crypto::pq::slh_dsa::{SlhDsaPublicKey, SlhDsaSecretKey, SlhDsaSignature};
use crate::crypto::pq::mldsa65::{Mldsa65PublicKey, Mldsa65SecretKey, Mldsa65Signature};
use crate::crypto::governance::{GovernanceManager, GovernanceConfig};
use serde::{Serialize, Deserialize};
use std::sync::{Arc, RwLock};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureVersion {
    /// ML-DSA-65 (FIPS 204) - version legacy
    V1Mldsa65,
    /// SLH-DSA (FIPS 205) - version actuelle
    V2SlhDsa,
}

impl SignatureVersion {
    /// Version actuelle recommandée
    pub fn current() -> Self {
        Self::V2SlhDsa
    }
    
    /// Versions acceptées lors de la période de transition (avec gouvernance)
    pub fn is_accepted_during_transition(&self, block_height: u64, governance_config: &GovernanceConfig) -> bool {
        match self {
            Self::V2SlhDsa => true, // Toujours accepté
            Self::V1Mldsa65 => {
                // Période de transition configurable via gouvernance
                block_height < governance_config.signature_transition_period
            }
        }
    }
    
    /// Version legacy pour compatibilité (utilise la valeur hardcodée)
    #[deprecated(note = "Utiliser is_accepted_during_transition avec GovernanceConfig")]
    pub fn is_accepted_during_transition_legacy(&self, block_height: u64) -> bool {
        match self {
            Self::V2SlhDsa => true,
            Self::V1Mldsa65 => block_height < 10_000, // Valeur hardcodée legacy
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublicKey {
    Mldsa65(Mldsa65PublicKey),
    SlhDsa(SlhDsaPublicKey),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Signature {
    Mldsa65(Mldsa65Signature),
    SlhDsa(SlhDsaSignature),
}

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("Signature invalide")]
    InvalidSignature,
    #[error("Version non supportée: {0:?}")]
    UnsupportedVersion(SignatureVersion),
    #[error("Clé publique incompatible avec la version")]
    IncompatibleKeyVersion,
    #[error("Signature expirée pour cette hauteur de bloc")]
    ExpiredSignatureVersion,
    #[error("Erreur de gouvernance: {0}")]
    GovernanceError(String),
}

/// Gestionnaire de schémas de signature avec gouvernance intégrée
#[derive(Debug)]
pub struct SignatureSchemeManager {
    /// Gestionnaire de gouvernance
    governance: Arc<RwLock<GovernanceManager>>,
}

impl SignatureSchemeManager {
    /// Crée un nouveau gestionnaire avec gouvernance
    pub fn new() -> Self {
        Self {
            governance: Arc::new(RwLock::new(GovernanceManager::new())),
        }
    }

    /// Crée un gestionnaire avec une configuration de gouvernance existante
    pub fn with_governance(governance: GovernanceManager) -> Self {
        Self {
            governance: Arc::new(RwLock::new(governance)),
        }
    }

    /// Vérifie si une version de signature est acceptée à une hauteur donnée
    pub fn is_version_accepted(&self, version: SignatureVersion, block_height: u64) -> Result<bool, SignatureError> {
        let governance = self.governance.read()
            .map_err(|e| SignatureError::GovernanceError(format!("Lock error: {}", e)))?;
        
        let config = governance.get_config();
        Ok(version.is_accepted_during_transition(block_height, config))
    }

    /// Retourne la configuration de gouvernance actuelle
    pub fn get_governance_config(&self) -> Result<GovernanceConfig, SignatureError> {
        let governance = self.governance.read()
            .map_err(|e| SignatureError::GovernanceError(format!("Lock error: {}", e)))?;
        
        Ok(governance.get_config().clone())
    }

    /// Accès au gestionnaire de gouvernance (lecture seule)
    pub fn governance_manager(&self) -> Arc<RwLock<GovernanceManager>> {
        self.governance.clone()
    }

    /// Met à jour la gouvernance (nettoyage des propositions expirées)
    pub fn update_governance(&self, current_height: u64) -> Result<(), SignatureError> {
        let mut governance = self.governance.write()
            .map_err(|e| SignatureError::GovernanceError(format!("Lock error: {}", e)))?;
        
        governance.cleanup_expired_proposals(current_height);
        Ok(())
    }
}

impl Default for SignatureSchemeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PublicKey {
    /// Vérifie une signature avec le gestionnaire de schémas
    pub fn verify_with_manager(
        &self, 
        message: &[u8], 
        signature: &Signature,
        manager: &SignatureSchemeManager,
        block_height: u64,
    ) -> Result<(), SignatureError> {
        // Vérification de la compatibilité version/hauteur
        let version = self.version();
        if !manager.is_version_accepted(version, block_height)? {
            return Err(SignatureError::ExpiredSignatureVersion);
        }

        // Vérification cryptographique standard
        self.verify(message, signature)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        match (self, signature) {
            (PublicKey::Mldsa65(pk), Signature::Mldsa65(sig)) => {
                pk.verify(message, sig)
                    .map_err(|_| SignatureError::InvalidSignature)
            }
            (PublicKey::SlhDsa(pk), Signature::SlhDsa(sig)) => {
                pk.verify(message, sig)
                    .map_err(|_| SignatureError::InvalidSignature)
            }
            _ => Err(SignatureError::IncompatibleKeyVersion),
        }
    }
    
    pub fn version(&self) -> SignatureVersion {
        match self {
            PublicKey::Mldsa65(_) => SignatureVersion::V1Mldsa65,
            PublicKey::SlhDsa(_) => SignatureVersion::V2SlhDsa,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::governance::{ConfigParameter, ProposalId};
    use rand::rngs::OsRng;

    #[test]
    fn test_version_transition_with_governance() {
        let manager = SignatureSchemeManager::new();
        
        // Test avec configuration par défaut (10_000 blocs)
        let version = SignatureVersion::V1Mldsa65;
        assert!(manager.is_version_accepted(version, 0).unwrap());
        assert!(manager.is_version_accepted(version, 9_999).unwrap());
        assert!(!manager.is_version_accepted(version, 10_000).unwrap());
        
        let version = SignatureVersion::V2SlhDsa;
        assert!(manager.is_version_accepted(version, 0).unwrap());
        assert!(manager.is_version_accepted(version, 10_000).unwrap());
        assert!(manager.is_version_accepted(version, u64::MAX).unwrap());
    }

    #[test]
    fn test_governance_config_modification() {
        let mut governance = GovernanceManager::new();
        
        // Créer une proposition pour étendre la période de transition
        let parameter = ConfigParameter::SignatureTransitionPeriod(20_000);
        let proposal_id = governance.create_proposal(parameter, 100, 1).unwrap();
        
        // Ajouter un membre au comité et voter
        let voter_key = crate::crypto::pq::slh_dsa::SlhDsaSecretKey::generate(&mut OsRng);
        let voter_pubkey = voter_key.public_key();
        governance.add_committee_member(voter_pubkey).unwrap();
        governance.submit_vote(proposal_id, &voter_key, true, 150, 1).unwrap();
        
        // Appliquer la proposition
        governance.apply_proposal(proposal_id, 200).unwrap();
        
        // Vérifier la nouvelle configuration
        let manager = SignatureSchemeManager::with_governance(governance);
        let config = manager.get_governance_config().unwrap();
        assert_eq!(config.signature_transition_period, 20_000);
        
        // Tester la nouvelle période
        let version = SignatureVersion::V1Mldsa65;
        assert!(manager.is_version_accepted(version, 19_999).unwrap());
        assert!(!manager.is_version_accepted(version, 20_000).unwrap());
    }

    #[test]
    fn test_legacy_compatibility() {
        let version = SignatureVersion::V1Mldsa65;
        
        // Test de la méthode legacy
        #[allow(deprecated)]
        {
            assert!(version.is_accepted_during_transition_legacy(0));
            assert!(version.is_accepted_during_transition_legacy(9_999));
            assert!(!version.is_accepted_during_transition_legacy(10_000));
        }
        
        let version = SignatureVersion::V2SlhDsa;
        #[allow(deprecated)]
        {
            assert!(version.is_accepted_during_transition_legacy(0));
            assert!(version.is_accepted_during_transition_legacy(10_000));
            assert!(version.is_accepted_during_transition_legacy(u64::MAX));
        }
    }

    #[test]
    fn test_signature_verification_with_manager() {
        let manager = SignatureSchemeManager::new();
        
        // Générer une clé SLH-DSA
        let secret_key = crate::crypto::pq::slh_dsa::SlhDsaSecretKey::generate(&mut OsRng);
        let public_key = PublicKey::SlhDsa(secret_key.public_key());
        
        let message = b"test message";
        let signature = Signature::SlhDsa(secret_key.sign(message));
        
        // Vérification avec le gestionnaire (SLH-DSA toujours accepté)
        assert!(public_key.verify_with_manager(message, &signature, &manager, 0).is_ok());
        assert!(public_key.verify_with_manager(message, &signature, &manager, 100_000).is_ok());
    }

    #[test]
    fn test_governance_update() {
        let manager = SignatureSchemeManager::new();
        
        // Test de mise à jour (nettoyage)
        assert!(manager.update_governance(1000).is_ok());
        
        // Vérifier que la configuration est toujours accessible
        let config = manager.get_governance_config().unwrap();
        assert_eq!(config.signature_transition_period, 10_000);
    }
}