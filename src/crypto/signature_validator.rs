//! Validateur de signatures SLH-DSA pour TSN
//!
//! Module de validation centralisé pour les signatures post-quantique
//! conformément à FIPS 205. Fournit une API unifiée pour la validation
//! avec métriques de performance et gestion d'erreurs sécurisée.
//!
//! # Sécurité
//! - Aucune information sensible n'est exposée dans les messages d'erreur
//! - Validation en temps constant pour les comparaisons critiques
//! - Protection contre les attaques par canal auxiliaire
//!
//! Références:
//! - FIPS 205: https://csrc.nist.gov/pubs/fips/205/final

use std::time::Instant;
use thiserror::Error;

use super::pq::slh_dsa::{verify_signature, PK_BYTES, SIG_BYTES};

/// Résultat de validation d'une signature
/// 
/// Structure compatible avec l'API existante - utilise `is_valid` pour
/// déterminer si la signature est valide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationResult {
    /// Indique si la signature est valide
    pub is_valid: bool,
    /// Temps de vérification en microsecondes
    pub verification_time_us: u64,
    /// Taille du message en octets
    pub message_size: usize,
    /// Préfixe du hash du message (8 premiers octets)
    pub message_hash_prefix: [u8; 8],
}

impl ValidationResult {
    /// Crée un résultat valide
    pub fn valid(verification_time_us: u64, message_size: usize, message_hash_prefix: [u8; 8]) -> Self {
        Self {
            is_valid: true,
            verification_time_us,
            message_size,
            message_hash_prefix,
        }
    }

    /// Crée un résultat invalide
    pub fn invalid(message_size: usize) -> Self {
        Self {
            is_valid: false,
            verification_time_us: 0,
            message_size,
            message_hash_prefix: [0u8; 8],
        }
    }
}

/// Erreurs de validation des signatures
/// 
/// # Sécurité
/// Les messages d'erreur ne contiennent aucune information sensible
/// sur les clés, signatures ou données internes.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    #[error("Signature invalide : format incorrect")]
    InvalidSignatureFormat,
    
    #[error("Clé publique invalide : taille incorrecte")]
    InvalidPublicKeySize,
    
    #[error("Clé publique invalide : format incorrect")]
    InvalidPublicKeyFormat,
    
    #[error("Message vide")]
    EmptyMessage,
    
    #[error("Message trop long : {size} octets (max {max})")]
    MessageTooLong { size: usize, max: usize },
    
    #[error("Vérification cryptographique échouée")]
    VerificationFailed,
    
    #[error("Erreur interne de validation")]
    InternalValidationError,
    
    #[error("Niveau de sécurité non supporté")]
    UnsupportedSecurityLevel,
}

/// Configuration du validateur
#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    /// Niveau de sécurité (128, 192, 256)
    pub security_level: u32,
    /// Taille maximale de message en octets
    pub max_message_size: usize,
    /// Activer les vérifications supplémentaires
    pub strict_mode: bool,
    /// Collecter les métriques de performance
    pub collect_metrics: bool,
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            security_level: 128,
            max_message_size: 1024 * 1024, // 1MB
            strict_mode: true,
            collect_metrics: true,
        }
    }
}

impl ValidatorConfig {
    /// Crée une configuration avec un niveau de sécurité spécifique
    /// 
    /// # Arguments
    /// * `security_level` - Niveau de sécurité (128, 192, ou 256)
    /// 
    /// # Errors
    /// Retourne une erreur si le niveau de sécurité n'est pas supporté
    pub fn with_security_level(security_level: u32) -> Result<Self, ValidationError> {
        match security_level {
            128 | 192 | 256 => Ok(Self {
                security_level,
                max_message_size: 1024 * 1024,
                strict_mode: true,
                collect_metrics: true,
            }),
            _ => Err(ValidationError::UnsupportedSecurityLevel),
        }
    }
}

/// Métriques de validation
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
    /// Temps minimum de validation en microsecondes
    pub min_time_us: u64,
    /// Temps maximum de validation en microsecondes
    pub max_time_us: u64,
}

impl ValidationMetrics {
    /// Met à jour les métriques avec un nouveau résultat
    fn record_validation(&mut self, success: bool, duration_us: u64) {
        self.total_validations += 1;
        if success {
            self.successful_validations += 1;
        } else {
            self.failed_validations += 1;
        }
        self.total_time_us += duration_us;
        
        if self.min_time_us == 0 || duration_us < self.min_time_us {
            self.min_time_us = duration_us;
        }
        if duration_us > self.max_time_us {
            self.max_time_us = duration_us;
        }
    }

    /// Temps moyen de validation en microsecondes
    pub fn average_time_us(&self) -> u64 {
        if self.total_validations == 0 {
            0
        } else {
            self.total_time_us / self.total_validations
        }
    }
}

/// Validateur de signatures SLH-DSA
pub struct SignatureValidator {
    config: ValidatorConfig,
    metrics: ValidationMetrics,
}

impl SignatureValidator {
    /// Crée un nouveau validateur avec la configuration par défaut
    pub fn new() -> Self {
        Self::with_config(ValidatorConfig::default())
    }

    /// Crée un validateur avec une configuration personnalisée
    pub fn with_config(config: ValidatorConfig) -> Self {
        Self {
            config,
            metrics: ValidationMetrics::default(),
        }
    }

    /// Valide une signature SLH-DSA
    ///
    /// # Arguments
    /// * `message` - Le message signé
    /// * `signature_bytes` - La signature (SIG_BYTES octets)
    /// * `public_key_bytes` - La clé publique (PK_BYTES octets)
    ///
    /// # Returns
    /// * `Ok(ValidationResult)` - Le résultat de validation avec métriques
    /// * `Err(ValidationError)` - Une erreur de validation
    ///
    /// # Sécurité
    /// Cette fonction effectue une validation en temps constant pour
    /// les comparaisons cryptographiques critiques.
    pub fn validate(
        &mut self,
        message: &[u8],
        signature_bytes: &[u8],
        public_key_bytes: &[u8],
    ) -> Result<ValidationResult, ValidationError> {
        let start = Instant::now();

        // Validation des entrées
        if message.is_empty() {
            return Err(ValidationError::EmptyMessage);
        }

        if message.len() > self.config.max_message_size {
            return Err(ValidationError::MessageTooLong {
                size: message.len(),
                max: self.config.max_message_size,
            });
        }

        if signature_bytes.len() != SIG_BYTES {
            return Err(ValidationError::InvalidSignatureFormat);
        }

        if public_key_bytes.len() != PK_BYTES {
            return Err(ValidationError::InvalidPublicKeySize);
        }

        // Calcul du hash du message pour le préfixe
        use sha2::{Sha256, Digest};
        let message_hash = Sha256::digest(message);
        let mut message_hash_prefix = [0u8; 8];
        message_hash_prefix.copy_from_slice(&message_hash[..8]);

        // Validation cryptographique
        let is_valid = match verify_signature(message, signature_bytes, public_key_bytes) {
            Ok(valid) => valid,
            Err(_) => {
                let duration = start.elapsed().as_micros() as u64;
                self.metrics.record_validation(false, duration);
                return Ok(ValidationResult::invalid(message.len()));
            }
        };

        let duration = start.elapsed().as_micros() as u64;
        self.metrics.record_validation(is_valid, duration);

        let result = if is_valid {
            ValidationResult::valid(duration, message.len(), message_hash_prefix)
        } else {
            ValidationResult::invalid(message.len())
        };

        Ok(result)
    }

    /// Valide une signature de manière synchrone (sans métriques)
    ///
    /// Version optimisée pour les cas où les métriques ne sont pas nécessaires.
    pub fn validate_fast(
        &self,
        message: &[u8],
        signature_bytes: &[u8],
        public_key_bytes: &[u8],
    ) -> Result<bool, ValidationError> {
        // Validation des entrées (même logique que validate)
        if message.is_empty() {
            return Err(ValidationError::EmptyMessage);
        }

        if message.len() > self.config.max_message_size {
            return Err(ValidationError::MessageTooLong {
                size: message.len(),
                max: self.config.max_message_size,
            });
        }

        if signature_bytes.len() != SIG_BYTES {
            return Err(ValidationError::InvalidSignatureFormat);
        }

        if public_key_bytes.len() != PK_BYTES {
            return Err(ValidationError::InvalidPublicKeySize);
        }

        // Validation cryptographique directe
        verify_signature(message, signature_bytes, public_key_bytes)
            .map_err(|_| ValidationError::VerificationFailed)
    }

    /// Retourne les métriques actuelles
    pub fn metrics(&self) -> ValidationMetrics {
        self.metrics.clone()
    }

    /// Réinitialise les métriques
    pub fn reset_metrics(&mut self) {
        self.metrics = ValidationMetrics::default();
    }

    /// Retourne la configuration
    pub fn config(&self) -> &ValidatorConfig {
        &self.config
    }
}

impl Default for SignatureValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Validation rapide sans instanciation de validateur
///
/// Fonction utilitaire pour les cas simples où une validation
/// unique est nécessaire.
pub fn quick_validate(
    message: &[u8],
    signature_bytes: &[u8],
    public_key_bytes: &[u8],
) -> Result<bool, ValidationError> {
    if message.is_empty() {
        return Err(ValidationError::EmptyMessage);
    }

    if signature_bytes.len() != SIG_BYTES {
        return Err(ValidationError::InvalidSignatureFormat);
    }

    if public_key_bytes.len() != PK_BYTES {
        return Err(ValidationError::InvalidPublicKeySize);
    }

    verify_signature(message, signature_bytes, public_key_bytes)
        .map_err(|_| ValidationError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_result_valid() {
        let result = ValidationResult::valid(100, 256, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(result.is_valid);
        assert_eq!(result.verification_time_us, 100);
        assert_eq!(result.message_size, 256);
    }

    #[test]
    fn test_validation_result_invalid() {
        let result = ValidationResult::invalid(128);
        assert!(!result.is_valid);
        assert_eq!(result.verification_time_us, 0);
        assert_eq!(result.message_size, 128);
    }

    #[test]
    fn test_validator_config_default() {
        let config = ValidatorConfig::default();
        assert_eq!(config.security_level, 128);
        assert_eq!(config.max_message_size, 1024 * 1024);
        assert!(config.strict_mode);
        assert!(config.collect_metrics);
    }

    #[test]
    fn test_validator_config_with_security_level() {
        // Niveaux valides
        assert!(ValidatorConfig::with_security_level(128).is_ok());
        assert!(ValidatorConfig::with_security_level(192).is_ok());
        assert!(ValidatorConfig::with_security_level(256).is_ok());
        
        // Niveau invalide - ne panique pas
        let result = ValidatorConfig::with_security_level(64);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::UnsupportedSecurityLevel));
    }

    #[test]
    fn test_metrics_recording() {
        let mut metrics = ValidationMetrics::default();
        
        metrics.record_validation(true, 100);
        assert_eq!(metrics.total_validations, 1);
        assert_eq!(metrics.successful_validations, 1);
        assert_eq!(metrics.failed_validations, 0);
        
        metrics.record_validation(false, 200);
        assert_eq!(metrics.total_validations, 2);
        assert_eq!(metrics.successful_validations, 1);
        assert_eq!(metrics.failed_validations, 1);
        
        assert_eq!(metrics.average_time_us(), 150);
    }

    #[test]
    fn test_empty_message_error() {
        let mut validator = SignatureValidator::new();
        let result = validator.validate(b"", &[0u8; SIG_BYTES], &[0u8; PK_BYTES]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::EmptyMessage));
    }

    #[test]
    fn test_invalid_signature_size() {
        let mut validator = SignatureValidator::new();
        let result = validator.validate(b"test", &[0u8; 10], &[0u8; PK_BYTES]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::InvalidSignatureFormat));
    }

    #[test]
    fn test_invalid_public_key_size() {
        let mut validator = SignatureValidator::new();
        let result = validator.validate(b"test", &[0u8; SIG_BYTES], &[0u8; 10]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::InvalidPublicKeySize));
    }
}
