//! Instrumentation spécialisée pour le consensus TSN
//!
//! Ce module fournit des wrappers et utilitaires pour instrumenter
//! facilement les opérations critiques du consensus.

use crate::metrics::{CONSENSUS_METRICS, measure_duration, inc_counter, set_gauge};
use crate::core::{Block, BlockHeader};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, warn, error, debug};

/// Wrapper pour instrumenter la validation d'un bloc
pub struct InstrumentedBlockValidator;

impl InstrumentedBlockValidator {
    /// Valide un bloc avec instrumentation complète
    pub async fn validate_block<F, R, E>(
        block: &Block,
        validator_fn: F,
    ) -> Result<R, E>
    where
        F: FnOnce(&Block) -> Result<R, E>,
        E: std::fmt::Debug,
    {
        let start_time = Instant::now();
        
        // Incrémenter le compteur de blocs en cours de validation
        CONSENSUS_METRICS.blocks_validating_current.inc();
        
        debug!(
            block_hash = %hex::encode(&block.header.hash),
            block_height = block.header.height,
            "Début validation bloc"
        );
        
        // Exécuter la validation avec mesure de durée
        let result = measure_duration!(
            CONSENSUS_METRICS.block_validation_duration,
            validator_fn(block)
        );
        
        // Décrémenter le compteur de blocs en cours
        CONSENSUS_METRICS.blocks_validating_current.dec();
        
        // Enregistrer le résultat
        match &result {
            Ok(_) => {
                CONSENSUS_METRICS.blocks_validated_total.inc();
                info!(
                    block_hash = %hex::encode(&block.header.hash),
                    block_height = block.header.height,
                    duration_ms = start_time.elapsed().as_millis(),
                    "Bloc validé avec succès"
                );
            }
            Err(e) => {
                CONSENSUS_METRICS.blocks_rejected_total.inc();
                warn!(
                    block_hash = %hex::encode(&block.header.hash),
                    block_height = block.header.height,
                    duration_ms = start_time.elapsed().as_millis(),
                    error = ?e,
                    "Bloc rejeté lors de la validation"
                );
            }
        }
        
        result
    }
    
    /// Instrumente spécifiquement la validation des commitments
    pub async fn validate_commitment_root<F, R, E>(
        block: &Block,
        commitment_root: &[u8],
        validator_fn: F,
    ) -> Result<R, E>
    where
        F: FnOnce(&Block, &[u8]) -> Result<R, E>,
        E: std::fmt::Debug,
    {
        let result = measure_duration!(
            CONSENSUS_METRICS.commitment_validation_duration,
            validator_fn(block, commitment_root)
        );
        
        match &result {
            Ok(_) => {
                debug!(
                    block_hash = %hex::encode(&block.header.hash),
                    commitment_root = %hex::encode(commitment_root),
                    "Commitment root validé"
                );
            }
            Err(e) => {
                CONSENSUS_METRICS.invalid_commitment_root_errors.inc();
                error!(
                    block_hash = %hex::encode(&block.header.hash),
                    commitment_root = %hex::encode(commitment_root),
                    error = ?e,
                    "ERREUR: Invalid commitment root détectée"
                );
            }
        }
        
        result
    }
}

/// Wrapper pour instrumenter les opérations Proof of Work
pub struct InstrumentedPoWValidator;

impl InstrumentedPoWValidator {
    /// Valide un PoW avec instrumentation
    pub fn validate_pow<F, R, E>(
        block_header: &BlockHeader,
        validator_fn: F,
    ) -> Result<R, E>
    where
        F: FnOnce(&BlockHeader) -> Result<R, E>,
        E: std::fmt::Debug,
    {
        let result = measure_duration!(
            CONSENSUS_METRICS.pow_validation_duration,
            validator_fn(block_header)
        );
        
        match &result {
            Ok(_) => {
                debug!(
                    block_hash = %hex::encode(&block_header.hash),
                    difficulty = block_header.difficulty,
                    "PoW validé"
                );
            }
            Err(e) => {
                CONSENSUS_METRICS.pow_validation_failures.inc();
                warn!(
                    block_hash = %hex::encode(&block_header.hash),
                    difficulty = block_header.difficulty,
                    error = ?e,
                    "Échec validation PoW"
                );
            }
        }
        
        result
    }
    
    /// Met à jour la difficulté du réseau
    pub fn update_network_difficulty(new_difficulty: f64) {
        CONSENSUS_METRICS.network_difficulty.set(new_difficulty);
        info!(difficulty = new_difficulty, "Difficulté réseau mise à jour");
    }
}

/// Wrapper pour instrumenter les opérations de chaîne
pub struct InstrumentedChainManager;

impl InstrumentedChainManager {
    /// Met à jour la hauteur de la chaîne
    pub fn update_chain_height(height: u64) {
        CONSENSUS_METRICS.chain_height.set(height as i64);
        debug!(height = height, "Hauteur de chaîne mise à jour");
    }
    
    /// Met à jour le travail cumulatif
    pub fn update_cumulative_work(work: f64) {
        CONSENSUS_METRICS.cumulative_work.set(work);
        debug!(work = work, "Travail cumulatif mis à jour");
    }
    
    /// Enregistre une réorganisation de chaîne
    pub fn record_chain_reorg(depth: u64) {
        CONSENSUS_METRICS.chain_reorgs_total.inc();
        CONSENSUS_METRICS.last_reorg_depth.set(depth as i64);
        warn!(
            depth = depth,
            "Réorganisation de chaîne détectée"
        );
    }
    
    /// Enregistre la détection d'un fork
    pub fn record_fork_detected() {
        CONSENSUS_METRICS.forks_detected_total.inc();
        info!("Fork détecté dans la chaîne");
    }
    
    /// Met à jour le nombre de blocs orphelins
    pub fn update_orphan_blocks_count(count: u64) {
        CONSENSUS_METRICS.orphan_blocks_count.set(count as i64);
        debug!(count = count, "Nombre de blocs orphelins mis à jour");
    }
    
    /// Enregistre l'intervalle entre blocs
    pub fn record_block_interval(previous_timestamp: u64, current_timestamp: u64) {
        if current_timestamp > previous_timestamp {
            let interval = (current_timestamp - previous_timestamp) as f64;
            CONSENSUS_METRICS.block_interval.observe(interval);
            debug!(
                interval_seconds = interval,
                "Intervalle entre blocs enregistré"
            );
        }
    }
}

/// Wrapper pour instrumenter les preuves ZK
pub struct InstrumentedZKValidator;

impl InstrumentedZKValidator {
    /// Valide une preuve ZK avec instrumentation
    pub async fn validate_zk_proof<F, R, E>(
        proof_data: &[u8],
        validator_fn: F,
    ) -> Result<R, E>
    where
        F: FnOnce(&[u8]) -> Result<R, E>,
        E: std::fmt::Debug,
    {
        let result = measure_duration!(
            CONSENSUS_METRICS.zk_proof_validation_duration,
            validator_fn(proof_data)
        );
        
        match &result {
            Ok(_) => {
                CONSENSUS_METRICS.zk_proofs_validated_total.inc();
                debug!(
                    proof_size = proof_data.len(),
                    "Preuve ZK validée avec succès"
                );
            }
            Err(e) => {
                warn!(
                    proof_size = proof_data.len(),
                    error = ?e,
                    "Échec validation preuve ZK"
                );
            }
        }
        
        result
    }
}

/// Wrapper pour instrumenter le mempool
pub struct InstrumentedMempool;

impl InstrumentedMempool {
    /// Met à jour la taille du mempool
    pub fn update_mempool_size(size: usize) {
        CONSENSUS_METRICS.mempool_size.set(size as i64);
        debug!(size = size, "Taille mempool mise à jour");
    }
}

/// Collecteur de métriques système
pub struct SystemMetricsCollector;

impl SystemMetricsCollector {
    /// Met à jour l'utilisation mémoire du consensus
    pub fn update_consensus_memory_usage() {
        // Estimation basique - à améliorer avec des mesures réelles
        let memory_usage = Self::estimate_memory_usage();
        CONSENSUS_METRICS.consensus_memory_usage.set(memory_usage);
        debug!(memory_bytes = memory_usage, "Utilisation mémoire mise à jour");
    }
    
    /// Estime l'utilisation mémoire (placeholder)
    fn estimate_memory_usage() -> f64 {
        // TODO: Implémenter une mesure réelle de la mémoire
        // Pour l'instant, retourne une valeur factice
        1024.0 * 1024.0 // 1MB
    }
}

/// Utilitaires pour le debugging du bug "Invalid commitment root"
pub struct CommitmentRootDebugger;

impl CommitmentRootDebugger {
    /// Log détaillé pour diagnostiquer les erreurs de commitment root
    pub fn log_commitment_validation_details(
        block_hash: &[u8],
        expected_root: &[u8],
        actual_root: &[u8],
        merkle_path: &[Vec<u8>],
    ) {
        error!(
            block_hash = %hex::encode(block_hash),
            expected_root = %hex::encode(expected_root),
            actual_root = %hex::encode(actual_root),
            merkle_path_length = merkle_path.len(),
            "DIAGNOSTIC: Détails de l'erreur commitment root"
        );
        
        // Log chaque élément du chemin Merkle pour debug
        for (i, path_element) in merkle_path.iter().enumerate() {
            debug!(
                path_index = i,
                path_element = %hex::encode(path_element),
                "Élément chemin Merkle"
            );
        }
        
        // Incrémenter le compteur d'erreurs spécialisé
        CONSENSUS_METRICS.invalid_commitment_root_errors.inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Block, BlockHeader, Transaction};
    
    #[tokio::test]
    async fn test_instrumented_block_validation() {
        let block = create_test_block();
        
        let result = InstrumentedBlockValidator::validate_block(
            &block,
            |_block| -> Result<(), &'static str> {
                Ok(())
            }
        ).await;
        
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_pow_validation_instrumentation() {
        let header = create_test_header();
        
        let result = InstrumentedPoWValidator::validate_pow(
            &header,
            |_header| -> Result<(), &'static str> {
                Ok(())
            }
        );
        
        assert!(result.is_ok());
    }
    
    fn create_test_block() -> Block {
        Block {
            header: create_test_header(),
            transactions: vec![],
        }
    }
    
    fn create_test_header() -> BlockHeader {
        BlockHeader {
            height: 1,
            previous_hash: vec![0; 32],
            merkle_root: vec![0; 32],
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            difficulty: 1000.0,
            nonce: 0,
            hash: vec![0; 32],
        }
    }
}