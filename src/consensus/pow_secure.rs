//! Proof-of-work sécurisé - VERSION SANS PANIC
//!
//! Ce module remplace src/consensus/pow.rs avec une gestion d'erreur robuste.
//! Aucun unwrap() ou expect() sur SystemTime ou autres opérations système.
//!
//! # Sécurité
//! - Gestion des erreurs d'horloge système
//! - Validation des timestamps
//! - Pas de panic sur entrées malformées

use std::time::{SystemTime, UNIX_EPOCH, Duration};
use tracing::{info, debug, warn};
use thiserror::Error;

use crate::core::ShieldedBlock;
use crate::crypto::hash::Hash;

/// Erreurs du module PoW
#[derive(Error, Debug, Clone)]
pub enum PowError {
    #[error("Erreur d'horloge système: {0}")]
    SystemTimeError(String),
    #[error("Timestamp invalide: {0}")]
    InvalidTimestamp(u64),
    #[error("Difficulté invalide: {0}")]
    InvalidDifficulty(u32),
    #[error("Nonce overflow")]
    NonceOverflow,
    #[error("Calcul de hash échoué")]
    HashCalculationFailed,
    #[error("Cible invalide")]
    InvalidTarget,
}

/// Configuration du minage PoW
pub struct PowConfig {
    pub target_difficulty: u32,
    pub max_nonce: u64,
    pub timestamp_tolerance: u64, // secondes
}

impl Default for PowConfig {
    fn default() -> Self {
        Self {
            target_difficulty: 4,
            max_nonce: u64::MAX,
            timestamp_tolerance: 300, // 5 minutes
        }
    }
}

/// Mineur PoW sécurisé
pub struct SecureMiner {
    config: PowConfig,
}

impl SecureMiner {
    /// Crée un nouveau mineur avec la configuration par défaut
    pub fn new() -> Self {
        Self {
            config: PowConfig::default(),
        }
    }

    /// Crée un mineur avec une configuration personnalisée
    pub fn with_config(config: PowConfig) -> Self {
        Self { config }
    }

    /// Obtient le timestamp actuel de manière sécurisée
    /// 
    /// # Sécurité
    /// Retourne une erreur si l'horloge système est invalide
    /// plutôt que de paniquer avec unwrap()
    pub fn current_timestamp(&self) -> Result<u64, PowError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| PowError::SystemTimeError(format!("Clock before epoch: {:?}", e)))
    }

    /// Valide un timestamp
    /// 
    /// # Sécurité
    /// Vérifie que le timestamp est raisonnable
    fn validate_timestamp(&self, timestamp: u64) -> Result<(), PowError> {
        let current = self.current_timestamp()?;
        
        // Pas dans le futur (avec tolérance)
        if timestamp > current + self.config.timestamp_tolerance {
            return Err(PowError::InvalidTimestamp(timestamp));
        }
        
        // Pas trop vieux (24h)
        if timestamp + 86400 < current {
            warn!("Very old timestamp detected: {} (current: {})", timestamp, current);
        }
        
        Ok(())
    }

    /// Mine un bloc avec gestion d'erreur sécurisée
    /// 
    /// # Sécurité
    /// Jamais de panic, toutes les erreurs sont propagées
    pub fn mine_block(&self,
        mut block: ShieldedBlock,
        coinbase_address: &[u8; 32],
    ) -> Result<ShieldedBlock, PowError> {
        
        // Obtention sécurisée du timestamp
        let timestamp = self.current_timestamp()?;
        block.header.timestamp = timestamp;
        
        // Validation du timestamp
        self.validate_timestamp(timestamp)?;
        
        info!("Mining block at height {} with difficulty {}", 
            block.header.height, 
            self.config.target_difficulty
        );
        
        let mut nonce: u64 = 0;
        
        loop {
            // Vérification du overflow
            if nonce >= self.config.max_nonce {
                return Err(PowError::NonceOverflow);
            }
            
            block.header.nonce = nonce;
            
            // Calcul du hash (simulé - à remplacer par Poseidon)
            let hash = block.hash();
            
            // Vérification de la difficulté
            if self.meets_difficulty(&hash, self.config.target_difficulty) {
                info!("Block mined! Nonce: {}, Hash: {:?}", nonce, hash);
                return Ok(block);
            }
            
            nonce += 1;
            
            // Log périodique
            if nonce % 10000 == 0 {
                debug!("Mining... nonce: {}", nonce);
            }
        }
    }

    /// Vérifie si un hash satisfait la difficulté cible
    fn meets_difficulty(&self, hash: &Hash, difficulty: u32) -> bool {
        let hash_bytes = hash.as_bytes();
        let leading_zeros = hash_bytes.iter()
            .take_while(|&&b| b == 0)
            .count();
        
        leading_zeros >= difficulty as usize
    }

    /// Vérifie la preuve de travail d'un bloc
    /// 
    /// # Sécurité
    /// Validation complète sans panic
    pub fn verify_pow(&self, block: &ShieldedBlock) -> Result<bool, PowError> {
        // Validation du timestamp
        self.validate_timestamp(block.header.timestamp)?;
        
        // Vérification de la difficulté
        let hash = block.hash();
        let valid = self.meets_difficulty(&hash, self.config.target_difficulty);
        
        Ok(valid)
    }

    /// Ajuste la difficulté en fonction du temps écoulé
    /// 
    /// # Sécurité
    /// Gestion des erreurs de calcul
    pub fn adjust_difficulty(
        &self,
        current_difficulty: u32,
        actual_time: u64,
        target_time: u64,
    ) -> Result<u32, PowError> {
        if target_time == 0 {
            return Err(PowError::InvalidTarget);
        }
        
        let ratio = actual_time as f64 / target_time as f64;
        
        // Limites d'ajustement (×4 ou ÷4 max)
        let adjusted = if ratio > 4.0 {
            current_difficulty.saturating_sub(1)
        } else if ratio < 0.25 {
            current_difficulty.saturating_add(1)
        } else {
            current_difficulty
        };
        
        // Limites de difficulté
        let clamped = adjusted.clamp(1, 32);
        
        Ok(clamped)
    }
}

impl Default for SecureMiner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_timestamp_success() {
        let miner = SecureMiner::new();
        let ts = miner.current_timestamp();
        assert!(ts.is_ok());
        assert!(ts.unwrap() > 1600000000); // Après 2020
    }

    #[test]
    fn test_validate_timestamp_future() {
        let miner = SecureMiner::new();
        let future_ts = u64::MAX;
        let result = miner.validate_timestamp(future_ts);
        assert!(result.is_err());
    }

    #[test]
    fn test_adjust_difficulty_bounds() {
        let miner = SecureMiner::new();
        
        // Test augmentation
        let diff = miner.adjust_difficulty(10, 1, 100).unwrap();
        assert_eq!(diff, 11);
        
        // Test diminution
        let diff = miner.adjust_difficulty(10, 400, 100).unwrap();
        assert_eq!(diff, 9);
        
        // Test limite inférieure
        let diff = miner.adjust_difficulty(1, 400, 100).unwrap();
        assert_eq!(diff, 1);
        
        // Test limite supérieure
        let diff = miner.adjust_difficulty(32, 1, 100).unwrap();
        assert_eq!(diff, 32);
    }

    #[test]
    fn test_adjust_difficulty_invalid_target() {
        let miner = SecureMiner::new();
        let result = miner.adjust_difficulty(10, 100, 0);
        assert!(matches!(result, Err(PowError::InvalidTarget)));
    }
}
