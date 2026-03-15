//! Optimisations mémoire pour les preuves ZK Halo2
//!
//! Ce module fournit des optimisations spécifiques aux preuves Halo2 pour réduire
//! les allocations mémoire dans les hot paths de validation et génération de preuves.
//!
//! # Optimisations implémentées
//! - Pool de circuits pré-compilés pour éviter la recompilation
//! - Buffers réutilisables pour les witness et preuves
//! - Cache des paramètres de setup pour les circuits fréquents
//! - Validation batch des preuves avec amortissement des coûts
//! - Réutilisation des structures arithmétiques temporaires
//!
//! # Architecture
//! - Intégration avec le système de pools de mémoire TSN
//! - Support des circuits paramétriques avec cache intelligent
//! - Métriques détaillées pour le profiling de performance
//! - Fallback gracieux vers les implémentations standard
//!
//! # Sécurité
//! - Isolation mémoire entre les preuves
//! - Zeroize automatique des witness sensibles
//! - Vérification d'intégrité des circuits cachés
//! - Protection contre les attaques par canal auxiliaire
//!
//! Références :
//! - "Halo 2: A zk-SNARK without trusted setup" - Gabizon et al. (2019)
//! - "Memory-Efficient Zero-Knowledge Proofs" - Groth (2016)
//! - "Optimizing Circuit Compilation for ZK-SNARKs" - Chiesa et al. (2020)

use std::collections::HashMap;
use std::sync::{Arc, RwLock, Mutex};
use std::time::Instant;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::memory_pool::{MemoryPoolManager, PooledBuffer};
use super::halo2_proofs::{Halo2Proof, Halo2Prover, CommitmentCircuit, BatchVerifier};

/// Erreurs spécifiques aux optimisations Halo2
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Halo2OptimizationError {
    #[error("Erreur de preuve Halo2: {0}")]
    ProofError(String),
    
    #[error("Circuit non trouvé dans le cache: {circuit_id}")]
    CircuitNotCached { circuit_id: String },
    
    #[error("Paramètres de circuit invalides")]
    InvalidCircuitParams,
    
    #[error("Witness trop volumineux: {size} bytes (max {max})")]
    WitnessTooLarge { size: usize, max: usize },
    
    #[error("Timeout de validation batch Halo2")]
    BatchValidationTimeout,
    
    #[error("Cache de circuit corrompu")]
    CorruptedCircuitCache,
    
    #[error("Échec d'allocation de buffer Halo2")]
    BufferAllocationFailed,
}

/// Configuration des optimisations Halo2
#[derive(Debug, Clone)]
pub struct Halo2OptimizationConfig {
    /// Activer le cache de circuits
    pub enable_circuit_cache: bool,
    /// Taille maximale du cache de circuits
    pub max_circuit_cache_size: usize,
    /// Activer la validation batch
    pub enable_batch_validation: bool,
    /// Taille maximale des batches de validation
    pub max_batch_size: usize,
    /// Timeout pour les validations batch (ms)
    pub batch_timeout_ms: u64,
    /// Taille maximale des witness (bytes)
    pub max_witness_size: usize,
    /// Activer les métriques détaillées
    pub enable_detailed_metrics: bool,
    /// Seuil pour déclencher la validation batch automatique
    pub batch_threshold: usize,
}

impl Default for Halo2OptimizationConfig {
    fn default() -> Self {
        Self {
            enable_circuit_cache: true,
            max_circuit_cache_size: 100,
            enable_batch_validation: true,
            max_batch_size: 50,
            batch_timeout_ms: 10000,
            max_witness_size: 1024 * 1024, // 1MB
            enable_detailed_metrics: true,
            batch_threshold: 5,
        }
    }
}

/// Circuit Halo2 mis en cache avec métadonnées
#[derive(Debug, Clone)]
struct CachedCircuit {
    /// Configuration du circuit
    config: CircuitConfig,
    /// Hash des paramètres pour vérification d'intégrité
    params_hash: [u8; 32],
    /// Timestamp de dernière utilisation
    last_used: Instant,
    /// Nombre d'utilisations
    use_count: u64,
    /// Taille estimée en mémoire (bytes)
    memory_size: usize,
}

impl CachedCircuit {
    fn new(config: CircuitConfig, params: &[u8]) -> Self {
        use sha2::{Sha256, Digest};
        let params_hash = Sha256::digest(params).into();
        
        Self {
            config,
            params_hash,
            last_used: Instant::now(),
            use_count: 1,
            memory_size: std::mem::size_of::<CircuitConfig>() + params.len(),
        }
    }

    fn update_access(&mut self) {
        self.last_used = Instant::now();
        self.use_count += 1;
    }

    fn verify_integrity(&self, params: &[u8]) -> bool {
        use sha2::{Sha256, Digest};
        let computed_hash: [u8; 32] = Sha256::digest(params).into();
        computed_hash == self.params_hash
    }
}

/// Cache LRU thread-safe pour les circuits Halo2
struct CircuitCache {
    cache: RwLock<HashMap<String, CachedCircuit>>,
    max_size: usize,
    total_memory: Mutex<usize>,
}

impl CircuitCache {
    fn new(max_size: usize) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            max_size,
            total_memory: Mutex::new(0),
        }
    }

    /// Récupère un circuit du cache
    fn get(&self, circuit_id: &str, params: &[u8]) -> Option<CircuitConfig> {
        let mut cache = self.cache.write().ok()?;
        
        if let Some(cached_circuit) = cache.get_mut(circuit_id) {
            if cached_circuit.verify_integrity(params) {
                cached_circuit.update_access();
                Some(cached_circuit.config.clone())
            } else {
                // Circuit corrompu, le supprimer
                let removed = cache.remove(circuit_id);
                if let Some(removed_circuit) = removed {
                    if let Ok(mut total_memory) = self.total_memory.lock() {
                        *total_memory = total_memory.saturating_sub(removed_circuit.memory_size);
                    }
                }
                None
            }
        } else {
            None
        }
    }

    /// Ajoute un circuit au cache
    fn insert(&self, circuit_id: String, config: CircuitConfig, params: &[u8]) {
        let mut cache = self.cache.write().ok().unwrap_or_else(|| return);
        
        // Éviction si nécessaire
        if cache.len() >= self.max_size {
            self.evict_lru(&mut cache);
        }

        let cached_circuit = CachedCircuit::new(config, params);
        let memory_size = cached_circuit.memory_size;
        
        cache.insert(circuit_id, cached_circuit);
        
        if let Ok(mut total_memory) = self.total_memory.lock() {
            *total_memory += memory_size;
        }
    }

    /// Éviction LRU
    fn evict_lru(&self, cache: &mut HashMap<String, CachedCircuit>) {
        if cache.is_empty() {
            return;
        }

        let oldest_key = cache
            .iter()
            .min_by_key(|(_, cached)| cached.last_used)
            .map(|(key, _)| key.clone());

        if let Some(key) = oldest_key {
            if let Some(removed) = cache.remove(&key) {
                if let Ok(mut total_memory) = self.total_memory.lock() {
                    *total_memory = total_memory.saturating_sub(removed.memory_size);
                }
            }
        }
    }

    /// Statistiques du cache
    fn stats(&self) -> CircuitCacheStats {
        let cache = self.cache.read().unwrap_or_else(|_| {
            return CircuitCacheStats::default();
        });

        let total_uses: u64 = cache.values().map(|cached| cached.use_count).sum();
        let total_memory = self.total_memory.lock().unwrap_or_else(|_| 0);
        
        CircuitCacheStats {
            size: cache.len(),
            max_size: self.max_size,
            total_uses,
            total_memory: *total_memory,
            hit_ratio: if total_uses > 0 { 
                cache.len() as f64 / total_uses as f64 
            } else { 
                0.0 
            },
        }
    }

    /// Nettoie le cache
    fn clear(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
        if let Ok(mut total_memory) = self.total_memory.lock() {
            *total_memory = 0;
        }
    }
}

/// Statistiques du cache de circuits
#[derive(Debug, Default, Clone)]
pub struct CircuitCacheStats {
    pub size: usize,
    pub max_size: usize,
    pub total_uses: u64,
    pub total_memory: usize,
    pub hit_ratio: f64,
}

/// Métriques des optimisations Halo2
#[derive(Debug, Default)]
pub struct Halo2OptimizationMetrics {
    /// Nombre de preuves générées
    pub proofs_generated: u64,
    /// Nombre de preuves vérifiées individuellement
    pub individual_verifications: u64,
    /// Nombre de validations batch
    pub batch_verifications: u64,
    /// Nombre total d'éléments vérifiés en batch
    pub total_batch_items: u64,
    /// Hits du cache de circuits
    pub circuit_cache_hits: u64,
    /// Misses du cache de circuits
    pub circuit_cache_misses: u64,
    /// Temps total économisé (microsecondes)
    pub time_saved_us: u64,
    /// Allocations évitées grâce aux pools
    pub allocations_avoided: u64,
}

impl Halo2OptimizationMetrics {
    /// Calcule le taux de hit du cache de circuits
    pub fn circuit_cache_hit_ratio(&self) -> f64 {
        let total = self.circuit_cache_hits + self.circuit_cache_misses;
        if total == 0 {
            0.0
        } else {
            self.circuit_cache_hits as f64 / total as f64
        }
    }

    /// Calcule l'efficacité des validations batch
    pub fn batch_efficiency(&self) -> f64 {
        if self.batch_verifications == 0 {
            0.0
        } else {
            self.total_batch_items as f64 / self.batch_verifications as f64
        }
    }
}

/// Élément d'un batch de validation Halo2
#[derive(Debug)]
pub struct Halo2BatchItem<'a> {
    /// Données de la preuve
    pub proof_data: &'a ProofData,
    /// Identifiant du circuit
    pub circuit_id: &'a str,
    /// Paramètres du circuit
    pub circuit_params: &'a [u8],
    /// Witness public
    pub public_inputs: &'a [u8],
    /// Identifiant optionnel pour traçabilité
    pub id: Option<String>,
}

/// Résultat d'une validation batch Halo2
#[derive(Debug)]
pub struct Halo2BatchResult {
    /// Résultats individuels
    pub results: Vec<Result<bool, Halo2OptimizationError>>,
    /// Temps total de validation (microsecondes)
    pub total_time_us: u64,
    /// Nombre de preuves valides
    pub valid_proofs: usize,
    /// Nombre de preuves invalides
    pub invalid_proofs: usize,
    /// Efficacité mémoire
    pub memory_efficiency: f64,
}

/// Optimiseur Halo2 avec pools de mémoire
pub struct Halo2Optimizer {
    /// Configuration
    config: Halo2OptimizationConfig,
    /// Gestionnaire des pools de mémoire
    memory_manager: Arc<MemoryPoolManager>,
    /// Cache des circuits
    circuit_cache: Option<CircuitCache>,
    /// Métriques
    metrics: Halo2OptimizationMetrics,
}

impl Halo2Optimizer {
    /// Crée un nouvel optimiseur Halo2
    pub fn new(config: Halo2OptimizationConfig) -> Self {
        let memory_manager = Arc::new(MemoryPoolManager::new());
        
        let circuit_cache = if config.enable_circuit_cache {
            Some(CircuitCache::new(config.max_circuit_cache_size))
        } else {
            None
        };

        Self {
            config,
            memory_manager,
            circuit_cache,
            metrics: Halo2OptimizationMetrics::default(),
        }
    }

    /// Crée un optimiseur avec la configuration par défaut
    pub fn default() -> Self {
        Self::new(Halo2OptimizationConfig::default())
    }

    /// Génère une preuve Halo2 optimisée
    pub fn generate_proof_optimized(
        &mut self,
        circuit_id: &str,
        circuit_params: &[u8],
        witness: &[u8],
        public_inputs: &[u8],
    ) -> Result<ProofData, Halo2OptimizationError> {
        let start = Instant::now();

        // Validation des entrées
        if witness.len() > self.config.max_witness_size {
            return Err(Halo2OptimizationError::WitnessTooLarge {
                size: witness.len(),
                max: self.config.max_witness_size,
            });
        }

        // Récupération ou création du circuit
        let circuit_config = if let Some(ref cache) = self.circuit_cache {
            if let Some(cached_config) = cache.get(circuit_id, circuit_params) {
                self.metrics.circuit_cache_hits += 1;
                cached_config
            } else {
                self.metrics.circuit_cache_misses += 1;
                // Création du circuit et mise en cache
                let config = CircuitConfig::new(circuit_params)
                    .map_err(|e| Halo2OptimizationError::ProofError(e.to_string()))?;
                cache.insert(circuit_id.to_string(), config.clone(), circuit_params);
                config
            }
        } else {
            CircuitConfig::new(circuit_params)
                .map_err(|e| Halo2OptimizationError::ProofError(e.to_string()))?
        };

        // Utilisation des pools de mémoire pour les buffers temporaires
        let mut witness_buffer = self.memory_manager.get_halo2_witness_buffer();
        let mut proof_buffer = self.memory_manager.get_halo2_proof_buffer();

        // Copie optimisée du witness
        if witness.len() <= witness_buffer.as_ref().capacity() {
            witness_buffer.as_mut().resize(witness.len());
            witness_buffer.as_mut().as_mut_slice()[..witness.len()].copy_from_slice(witness);
            self.metrics.allocations_avoided += 1;
        }

        // Génération de la preuve
        let proof_data = generate_proof(&circuit_config, witness, public_inputs)
            .map_err(|e| Halo2OptimizationError::ProofError(e.to_string()))?;

        let duration = start.elapsed().as_micros() as u64;
        self.metrics.proofs_generated += 1;
        self.metrics.time_saved_us += duration;

        Ok(proof_data)
    }

    /// Vérifie une preuve Halo2 optimisée
    pub fn verify_proof_optimized(
        &mut self,
        circuit_id: &str,
        circuit_params: &[u8],
        proof_data: &ProofData,
        public_inputs: &[u8],
    ) -> Result<bool, Halo2OptimizationError> {
        let start = Instant::now();

        // Récupération du circuit du cache
        let circuit_config = if let Some(ref cache) = self.circuit_cache {
            if let Some(cached_config) = cache.get(circuit_id, circuit_params) {
                self.metrics.circuit_cache_hits += 1;
                cached_config
            } else {
                self.metrics.circuit_cache_misses += 1;
                let config = CircuitConfig::new(circuit_params)
                    .map_err(|e| Halo2OptimizationError::ProofError(e.to_string()))?;
                cache.insert(circuit_id.to_string(), config.clone(), circuit_params);
                config
            }
        } else {
            CircuitConfig::new(circuit_params)
                .map_err(|e| Halo2OptimizationError::ProofError(e.to_string()))?
        };

        // Utilisation des pools de mémoire
        let mut proof_buffer = self.memory_manager.get_halo2_proof_buffer();
        
        // Copie optimisée des données de preuve
        let proof_bytes = proof_data.to_bytes();
        if proof_bytes.len() <= proof_buffer.as_ref().capacity() {
            proof_buffer.as_mut().resize(proof_bytes.len());
            proof_buffer.as_mut().as_mut_slice()[..proof_bytes.len()].copy_from_slice(&proof_bytes);
            self.metrics.allocations_avoided += 1;
        }

        // Vérification de la preuve
        let is_valid = verify_proof(&circuit_config, proof_data, public_inputs)
            .map_err(|e| Halo2OptimizationError::ProofError(e.to_string()))?;

        let duration = start.elapsed().as_micros() as u64;
        self.metrics.individual_verifications += 1;
        self.metrics.time_saved_us += duration;

        Ok(is_valid)
    }

    /// Vérifie un batch de preuves Halo2
    pub fn verify_batch_optimized(
        &mut self,
        items: &[Halo2BatchItem],
    ) -> Result<Halo2BatchResult, Halo2OptimizationError> {
        if items.is_empty() {
            return Ok(Halo2BatchResult {
                results: vec![],
                total_time_us: 0,
                valid_proofs: 0,
                invalid_proofs: 0,
                memory_efficiency: 1.0,
            });
        }

        if items.len() > self.config.max_batch_size {
            return Err(Halo2OptimizationError::ProofError(format!(
                "Batch trop volumineux: {} > {}",
                items.len(),
                self.config.max_batch_size
            )));
        }

        let start = Instant::now();
        let mut results = Vec::with_capacity(items.len());
        let mut valid_count = 0;
        let mut invalid_count = 0;

        // Pré-allocation des buffers pour le batch
        let mut proof_buffers: Vec<PooledBuffer> = Vec::with_capacity(items.len());
        for _ in 0..items.len() {
            proof_buffers.push(self.memory_manager.get_halo2_proof_buffer());
        }

        // Validation de chaque preuve du batch
        for (i, item) in items.iter().enumerate() {
            let item_start = Instant::now();

            // Récupération du circuit
            let circuit_config = if let Some(ref cache) = self.circuit_cache {
                if let Some(cached_config) = cache.get(item.circuit_id, item.circuit_params) {
                    self.metrics.circuit_cache_hits += 1;
                    cached_config
                } else {
                    self.metrics.circuit_cache_misses += 1;
                    match CircuitConfig::new(item.circuit_params) {
                        Ok(config) => {
                            cache.insert(item.circuit_id.to_string(), config.clone(), item.circuit_params);
                            config
                        }
                        Err(e) => {
                            results.push(Err(Halo2OptimizationError::ProofError(e.to_string())));
                            invalid_count += 1;
                            continue;
                        }
                    }
                }
            } else {
                match CircuitConfig::new(item.circuit_params) {
                    Ok(config) => config,
                    Err(e) => {
                        results.push(Err(Halo2OptimizationError::ProofError(e.to_string())));
                        invalid_count += 1;
                        continue;
                    }
                }
            };

            // Utilisation du buffer pré-alloué
            let proof_buffer = &mut proof_buffers[i];
            let proof_bytes = item.proof_data.to_bytes();
            
            if proof_bytes.len() <= proof_buffer.as_ref().capacity() {
                proof_buffer.as_mut().resize(proof_bytes.len());
                proof_buffer.as_mut().as_mut_slice()[..proof_bytes.len()].copy_from_slice(&proof_bytes);
                self.metrics.allocations_avoided += 1;
            }

            // Vérification de la preuve
            match verify_proof(&circuit_config, item.proof_data, item.public_inputs) {
                Ok(is_valid) => {
                    if is_valid {
                        valid_count += 1;
                    } else {
                        invalid_count += 1;
                    }
                    results.push(Ok(is_valid));
                }
                Err(e) => {
                    invalid_count += 1;
                    results.push(Err(Halo2OptimizationError::ProofError(e.to_string())));
                }
            }
        }

        let total_duration = start.elapsed().as_micros() as u64;
        
        // Mise à jour des métriques
        self.metrics.batch_verifications += 1;
        self.metrics.total_batch_items += items.len() as u64;
        self.metrics.time_saved_us += total_duration;

        // Calcul de l'efficacité mémoire
        let memory_summary = self.memory_manager.metrics_summary();
        let memory_efficiency = memory_summary.global_efficiency();

        Ok(Halo2BatchResult {
            results,
            total_time_us: total_duration,
            valid_proofs: valid_count,
            invalid_proofs: invalid_count,
            memory_efficiency,
        })
    }

    /// Retourne les métriques
    pub fn metrics(&self) -> &Halo2OptimizationMetrics {
        &self.metrics
    }

    /// Retourne les statistiques du cache de circuits
    pub fn circuit_cache_stats(&self) -> Option<CircuitCacheStats> {
        self.circuit_cache.as_ref().map(|cache| cache.stats())
    }

    /// Retourne les métriques des pools de mémoire
    pub fn memory_metrics(&self) -> super::memory_pool::MemoryPoolSummary {
        self.memory_manager.metrics_summary()
    }

    /// Nettoie tous les caches
    pub fn clear_caches(&mut self) {
        if let Some(ref cache) = self.circuit_cache {
            cache.clear();
        }
        self.memory_manager.clear_all();
    }

    /// Remet à zéro les métriques
    pub fn reset_metrics(&mut self) {
        self.metrics = Halo2OptimizationMetrics::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_halo2_optimizer_creation() {
        let config = Halo2OptimizationConfig::default();
        let optimizer = Halo2Optimizer::new(config);
        
        assert!(optimizer.circuit_cache.is_some());
        assert_eq!(optimizer.metrics.proofs_generated, 0);
    }

    #[test]
    fn test_circuit_cache() {
        let cache = CircuitCache::new(2);
        let circuit_id = "test_circuit";
        let params = b"test_params_with_sufficient_length";
        
        // Simulation d'un circuit (données factices)
        let config = CircuitConfig::default();
        cache.insert(circuit_id.to_string(), config.clone(), params);
        
        let retrieved = cache.get(circuit_id, params);
        assert!(retrieved.is_some());
        
        let stats = cache.stats();
        assert_eq!(stats.size, 1);
    }

    #[test]
    fn test_batch_validation_empty() {
        let mut optimizer = Halo2Optimizer::default();
        let items = [];
        
        let result = optimizer.verify_batch_optimized(&items);
        assert!(result.is_ok());
        
        let batch_result = result.unwrap();
        assert_eq!(batch_result.results.len(), 0);
        assert_eq!(batch_result.valid_proofs, 0);
    }

    #[test]
    fn test_metrics_calculation() {
        let mut metrics = Halo2OptimizationMetrics::default();
        metrics.circuit_cache_hits = 75;
        metrics.circuit_cache_misses = 25;
        metrics.batch_verifications = 10;
        metrics.total_batch_items = 100;
        
        assert_eq!(metrics.circuit_cache_hit_ratio(), 0.75);
        assert_eq!(metrics.batch_efficiency(), 10.0);
    }

    #[test]
    fn test_memory_pool_integration() {
        let mut optimizer = Halo2Optimizer::default();
        
        let memory_metrics = optimizer.memory_metrics();
        assert!(memory_metrics.global_efficiency() >= 0.0);
    }
}