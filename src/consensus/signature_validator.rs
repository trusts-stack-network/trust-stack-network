//! Validateur de signatures pour le consensus TSN
//!
//! Valide les signatures SLH-DSA (FIPS 205) et ML-DSA-65 (FIPS 204) dans les
//! blocs et transactions du consensus. Fournit un point d'entrée centralisé
//! avec métriques de performance et support de la transition de schéma.
//!
//! # Schémas supportés
//! - **SLH-DSA-SHA2-128s** (défaut) : 128 bits de sécurité, signatures ~7.8KB
//! - **ML-DSA-65** (legacy) : 192 bits classique / 128 bits post-quantique
//!
//! # Transition de schéma
//! Le validateur supporte une hauteur de transition configurable pour passer
//! de ML-DSA-65 à SLH-DSA à un block height donné.

use std::time::{Duration, Instant};
use thiserror::Error;

use crate::crypto::pq::slh_dsa::{
    self, PublicKey as SlhPublicKey, Signature as SlhSignature,
    SLH_PUBLIC_KEY_SIZE, SLH_SIGNATURE_SIZE,
};
use crate::crypto::signature::{verify as mldsa_verify, Signature as MlDsaSignature};
use crate::crypto::keys::PUBLIC_KEY_SIZE as MLDSA_PUBLIC_KEY_SIZE;
use crate::crypto::keys::SIGNATURE_SIZE as MLDSA_SIGNATURE_SIZE;

/// Schéma de signature utilisé par le consensus
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusSignatureScheme {
    /// ML-DSA-65 (FIPS 204) — Support legacy pendant la transition
    MLDsa65,
    /// SLH-DSA-SHA2-128s (FIPS 205) — Nouveau défaut
    SlhDsaSha2_128s,
}

impl ConsensusSignatureScheme {
    /// Taille attendue de la signature en octets
    pub fn signature_size(&self) -> usize {
        match self {
            Self::MLDsa65 => MLDSA_SIGNATURE_SIZE,
            Self::SlhDsaSha2_128s => SLH_SIGNATURE_SIZE,
        }
    }

    /// Taille attendue de la clé publique en octets
    pub fn public_key_size(&self) -> usize {
        match self {
            Self::MLDsa65 => MLDSA_PUBLIC_KEY_SIZE,
            Self::SlhDsaSha2_128s => SLH_PUBLIC_KEY_SIZE,
        }
    }
}

/// Erreurs de validation de signature dans le consensus
#[derive(Error, Debug)]
pub enum SignatureValidationError {
    #[error("Format de signature invalide: {0}")]
    InvalidFormat(String),

    #[error("Vérification de signature échouée: {0}")]
    VerificationFailed(String),

    #[error("Taille de signature incorrecte: attendu {expected}, reçu {actual}")]
    SizeMismatch { expected: usize, actual: usize },

    #[error("Taille de clé publique incorrecte: attendu {expected}, reçu {actual}")]
    PublicKeySizeMismatch { expected: usize, actual: usize },

    #[error("Erreur SLH-DSA: {0}")]
    SlhDsa(String),

    #[error("Erreur ML-DSA-65: {0}")]
    MlDsa(String),
}

/// Métriques de validation de signature
#[derive(Debug, Clone, Default)]
pub struct ValidationMetrics {
    /// Nombre total de validations
    pub total_validations: u64,
    /// Nombre de validations réussies
    pub successful_validations: u64,
    /// Nombre de validations échouées
    pub failed_validations: u64,
    /// Temps total de validation en microsecondes
    pub total_time_us: u64,
    /// Temps moyen de validation en microsecondes
    pub avg_time_us: u64,
}

/// Validateur de signatures pour le consensus
///
/// Valide les signatures dans les blocs et transactions selon les règles
/// du consensus, avec support de transition entre schémas de signature.
pub struct SignatureValidator {
    /// Schéma de signature actuel
    current_scheme: ConsensusSignatureScheme,
    /// Hauteur de bloc pour la transition vers SLH-DSA (None = pas de transition)
    transition_height: Option<u64>,
    /// Métriques de validation
    metrics: ValidationMetrics,
    /// Timeout de validation (défaut: 500ms)
    validation_timeout: Duration,
}

impl SignatureValidator {
    /// Crée un nouveau validateur avec le schéma spécifié
    pub fn new(scheme: ConsensusSignatureScheme) -> Self {
        Self {
            current_scheme: scheme,
            transition_height: None,
            metrics: ValidationMetrics::default(),
            validation_timeout: Duration::from_millis(500),
        }
    }

    /// Crée un validateur avec SLH-DSA par défaut
    pub fn new_slh_dsa() -> Self {
        Self::new(ConsensusSignatureScheme::SlhDsaSha2_128s)
    }

    /// Configure une transition vers SLH-DSA à une hauteur de bloc donnée
    pub fn with_transition(mut self, height: u64) -> Self {
        self.transition_height = Some(height);
        self
    }

    /// Configure le timeout de validation
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.validation_timeout = timeout;
        self
    }

    /// Détermine le schéma de signature pour une hauteur de bloc donnée
    fn scheme_for_height(&self, height: u64) -> ConsensusSignatureScheme {
        match self.transition_height {
            Some(transition_height) if height >= transition_height => {
                ConsensusSignatureScheme::SlhDsaSha2_128s
            }
            _ => self.current_scheme,
        }
    }

    /// Retourne les métriques actuelles
    pub fn metrics(&self) -> &ValidationMetrics {
        &self.metrics
    }

    /// Réinitialise les métriques
    pub fn reset_metrics(&mut self) {
        self.metrics = ValidationMetrics::default();
    }

    /// Valide une signature selon le schéma du consensus.
    ///
    /// Dispatch vers la bonne implémentation (SLH-DSA ou ML-DSA-65) en
    /// fonction du schéma configuré pour la hauteur de bloc donnée.
    ///
    /// # Arguments
    /// * `message` - Le message signé (hash du bloc ou de la transaction)
    /// * `signature_bytes` - La signature brute
    /// * `public_key_bytes` - La clé publique du signataire
    /// * `block_height` - La hauteur du bloc (pour déterminer le schéma)
    ///
    /// # Returns
    /// * `Ok(())` si la signature est valide
    /// * `Err(SignatureValidationError)` sinon
    pub fn validate_signature(
        &mut self,
        message: &[u8],
        signature_bytes: &[u8],
        public_key_bytes: &[u8],
        block_height: u64,
    ) -> Result<(), SignatureValidationError> {
        let scheme = self.scheme_for_height(block_height);
        let start = Instant::now();

        // Vérification de la taille de la signature
        let expected_sig_size = scheme.signature_size();
        if signature_bytes.len() != expected_sig_size {
            self.record_failure();
            return Err(SignatureValidationError::SizeMismatch {
                expected: expected_sig_size,
                actual: signature_bytes.len(),
            });
        }

        // Vérification de la taille de la clé publique
        let expected_pk_size = scheme.public_key_size();
        if public_key_bytes.len() != expected_pk_size {
            self.record_failure();
            return Err(SignatureValidationError::PublicKeySizeMismatch {
                expected: expected_pk_size,
                actual: public_key_bytes.len(),
            });
        }

        // Dispatch vers le bon schéma de vérification
        let result = match scheme {
            ConsensusSignatureScheme::SlhDsaSha2_128s => {
                self.verify_slh_dsa(message, signature_bytes, public_key_bytes)
            }
            ConsensusSignatureScheme::MLDsa65 => {
                self.verify_ml_dsa_65(message, signature_bytes, public_key_bytes)
            }
        };

        let elapsed = start.elapsed();

        // Vérification du timeout
        if elapsed > self.validation_timeout {
            self.record_failure();
            return Err(SignatureValidationError::VerificationFailed(
                format!("Timeout de validation dépassé: {}ms", elapsed.as_millis()),
            ));
        }

        // Mise à jour des métriques
        match &result {
            Ok(()) => self.record_success(elapsed),
            Err(_) => self.record_failure(),
        }

        result
    }

    /// Vérifie une signature SLH-DSA-SHA2-128s
    fn verify_slh_dsa(
        &self,
        message: &[u8],
        signature_bytes: &[u8],
        public_key_bytes: &[u8],
    ) -> Result<(), SignatureValidationError> {
        // Construire la clé publique SLH-DSA
        let pk = SlhPublicKey::from_bytes(public_key_bytes).ok_or_else(|| {
            SignatureValidationError::SlhDsa(format!(
                "Clé publique invalide ({} octets)",
                public_key_bytes.len()
            ))
        })?;

        // Construire la signature SLH-DSA
        let sig = SlhSignature::from_bytes(signature_bytes).ok_or_else(|| {
            SignatureValidationError::SlhDsa(format!(
                "Signature invalide ({} octets)",
                signature_bytes.len()
            ))
        })?;

        // Vérification cryptographique réelle
        if slh_dsa::verify(&pk, message, &sig) {
            Ok(())
        } else {
            Err(SignatureValidationError::VerificationFailed(
                "Vérification SLH-DSA échouée".to_string(),
            ))
        }
    }

    /// Vérifie une signature ML-DSA-65 (FIPS 204)
    fn verify_ml_dsa_65(
        &self,
        message: &[u8],
        signature_bytes: &[u8],
        public_key_bytes: &[u8],
    ) -> Result<(), SignatureValidationError> {
        let signature = MlDsaSignature::from_bytes(signature_bytes.to_vec());

        match mldsa_verify(message, &signature, public_key_bytes) {
            Ok(true) => Ok(()),
            Ok(false) => Err(SignatureValidationError::VerificationFailed(
                "Vérification ML-DSA-65 échouée".to_string(),
            )),
            Err(e) => Err(SignatureValidationError::MlDsa(e.to_string())),
        }
    }

    /// Enregistre une validation réussie dans les métriques
    fn record_success(&mut self, elapsed: Duration) {
        self.metrics.total_validations += 1;
        self.metrics.successful_validations += 1;
        self.metrics.total_time_us += elapsed.as_micros() as u64;
        self.update_avg();
    }

    /// Enregistre une validation échouée dans les métriques
    fn record_failure(&mut self) {
        self.metrics.total_validations += 1;
        self.metrics.failed_validations += 1;
        self.update_avg();
    }

    /// Met à jour le temps moyen
    fn update_avg(&mut self) {
        if self.metrics.total_validations > 0 {
            self.metrics.avg_time_us =
                self.metrics.total_time_us / self.metrics.total_validations;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::slh_dsa::{sign as slh_sign, SecretKey as SlhSecretKey};

    #[test]
    fn test_scheme_sizes() {
        let slh = ConsensusSignatureScheme::SlhDsaSha2_128s;
        assert_eq!(slh.signature_size(), SLH_SIGNATURE_SIZE);
        assert_eq!(slh.public_key_size(), SLH_PUBLIC_KEY_SIZE);

        let ml = ConsensusSignatureScheme::MLDsa65;
        assert_eq!(ml.signature_size(), MLDSA_SIGNATURE_SIZE);
        assert_eq!(ml.public_key_size(), MLDSA_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_scheme_for_height_no_transition() {
        let validator = SignatureValidator::new(ConsensusSignatureScheme::MLDsa65);
        assert_eq!(
            validator.scheme_for_height(0),
            ConsensusSignatureScheme::MLDsa65
        );
        assert_eq!(
            validator.scheme_for_height(1_000_000),
            ConsensusSignatureScheme::MLDsa65
        );
    }

    #[test]
    fn test_scheme_for_height_with_transition() {
        let validator = SignatureValidator::new(ConsensusSignatureScheme::MLDsa65)
            .with_transition(1000);
        assert_eq!(
            validator.scheme_for_height(999),
            ConsensusSignatureScheme::MLDsa65
        );
        assert_eq!(
            validator.scheme_for_height(1000),
            ConsensusSignatureScheme::SlhDsaSha2_128s
        );
        assert_eq!(
            validator.scheme_for_height(1001),
            ConsensusSignatureScheme::SlhDsaSha2_128s
        );
    }

    #[test]
    fn test_slh_dsa_validate_roundtrip() {
        let (sk, pk) = SlhSecretKey::generate();
        let message = b"Block hash for validation";

        let sig = slh_sign(&sk, message);

        let mut validator = SignatureValidator::new_slh_dsa();
        let result = validator.validate_signature(
            message,
            sig.to_bytes(),
            &pk.to_bytes(),
            0,
        );
        assert!(result.is_ok(), "Validation SLH-DSA a échoué: {:?}", result);

        let metrics = validator.metrics();
        assert_eq!(metrics.total_validations, 1);
        assert_eq!(metrics.successful_validations, 1);
        assert_eq!(metrics.failed_validations, 0);
    }

    #[test]
    fn test_slh_dsa_validate_wrong_message() {
        let (sk, pk) = SlhSecretKey::generate();
        let message = b"Original message";
        let wrong_message = b"Wrong message!!!";

        let sig = slh_sign(&sk, message);

        let mut validator = SignatureValidator::new_slh_dsa();
        let result = validator.validate_signature(
            wrong_message,
            sig.to_bytes(),
            &pk.to_bytes(),
            0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_mldsa65_validate_roundtrip() {
        let keypair = crate::crypto::keys::KeyPair::generate();
        let message = b"Transaction hash";

        let sig = crate::crypto::signature::sign(message, &keypair);

        let mut validator = SignatureValidator::new(ConsensusSignatureScheme::MLDsa65);
        let result = validator.validate_signature(
            message,
            sig.as_bytes(),
            &keypair.public_key_bytes(),
            0,
        );
        assert!(result.is_ok(), "Validation ML-DSA-65 a échoué: {:?}", result);
    }

    #[test]
    fn test_mldsa65_validate_wrong_message() {
        let keypair = crate::crypto::keys::KeyPair::generate();
        let message = b"Original transaction";
        let wrong = b"Forged transaction!";

        let sig = crate::crypto::signature::sign(message, &keypair);

        let mut validator = SignatureValidator::new(ConsensusSignatureScheme::MLDsa65);
        let result = validator.validate_signature(
            wrong,
            sig.as_bytes(),
            &keypair.public_key_bytes(),
            0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_size_mismatch() {
        let mut validator = SignatureValidator::new_slh_dsa();
        let result = validator.validate_signature(
            b"message",
            &[0u8; 100], // taille incorrecte
            &[0u8; SLH_PUBLIC_KEY_SIZE],
            0,
        );
        assert!(matches!(
            result,
            Err(SignatureValidationError::SizeMismatch { .. })
        ));
    }

    #[test]
    fn test_public_key_size_mismatch() {
        let mut validator = SignatureValidator::new_slh_dsa();
        let result = validator.validate_signature(
            b"message",
            &[0u8; SLH_SIGNATURE_SIZE],
            &[0u8; 10], // taille incorrecte
            0,
        );
        assert!(matches!(
            result,
            Err(SignatureValidationError::PublicKeySizeMismatch { .. })
        ));
    }

    #[test]
    fn test_metrics_tracking() {
        let mut validator = SignatureValidator::new_slh_dsa();

        // Faire une validation qui échoue (clé/sig invalides)
        let _ = validator.validate_signature(
            b"test",
            &[0u8; SLH_SIGNATURE_SIZE],
            &[0u8; SLH_PUBLIC_KEY_SIZE],
            0,
        );

        let metrics = validator.metrics();
        assert_eq!(metrics.total_validations, 1);
        assert_eq!(metrics.failed_validations, 1);
    }

    #[test]
    fn test_transition_slh_to_mldsa_at_height() {
        // Démarre en ML-DSA-65, transite vers SLH-DSA au bloc 500
        let mut validator = SignatureValidator::new(ConsensusSignatureScheme::MLDsa65)
            .with_transition(500);

        // Avant la transition: taille ML-DSA-65 attendue
        let result = validator.validate_signature(
            b"message",
            &[0u8; SLH_SIGNATURE_SIZE], // mauvaise taille pour ML-DSA-65
            &[0u8; MLDSA_PUBLIC_KEY_SIZE],
            100,
        );
        assert!(matches!(
            result,
            Err(SignatureValidationError::SizeMismatch { .. })
        ));

        // Après la transition: taille SLH-DSA attendue
        let result = validator.validate_signature(
            b"message",
            &[0u8; MLDSA_SIGNATURE_SIZE], // mauvaise taille pour SLH-DSA
            &[0u8; SLH_PUBLIC_KEY_SIZE],
            500,
        );
        assert!(matches!(
            result,
            Err(SignatureValidationError::SizeMismatch { .. })
        ));
    }
}
