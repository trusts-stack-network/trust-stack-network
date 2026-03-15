//! Circuit breaker pour opérations cryptographiques coûteuses
//!
//! Protège contre les attaques DoS cryptographiques en limitant automatiquement
//! les opérations intensives (génération de preuves ZK, vérification de signatures,
//! construction d'arbres de Merkle).
//!
//! Références:
//! - Martin Fowler, "CircuitBreaker" (2014)
//! - Release It! Design Patterns for Stability (Michael Nygard)
//! - OWASP Application Security Verification Standard v4.0

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Types d'opérations cryptographiques surveillées
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CryptoOperation {
    /// Génération de preuve ZK Halo2 (très coûteuse)
    Halo2ProofGeneration,
    /// Vérification de preuve ZK Halo2 (coûteuse)
    Halo2ProofVerification,
    /// Signature ML-DSA-65 (modérément coûteuse)
    MlDsaSignature,
    /// Vérification signature ML-DSA-65 (modérément coûteuse)
    MlDsaVerification,
    /// Construction arbre de Merkle (coûteuse pour gros arbres)
    MerkleTreeConstruction,
    /// Génération de path Merkle (modérément coûteuse)
    MerklePathGeneration,
    /// Hash Poseidon2 (peu coûteuse mais peut être spammée)
    Poseidon2Hash,
}

impl CryptoOperation {
    /// Coût relatif de l'opération (1-10, 10 = très coûteux)
    pub fn cost_weight(&self) -> u32 {
        match self {
            Self::Halo2ProofGeneration => 10,
            Self::Halo2ProofVerification => 6,
            Self::MlDsaSignature => 4,
            Self::MlDsaVerification => 3,
            Self::MerkleTreeConstruction => 5,
            Self::MerklePathGeneration => 2,
            Self::Poseidon2Hash => 1,
        }
    }

    /// Timeout maximum recommandé pour cette opération
    pub fn max_timeout(&self) -> Duration {
        match self {
            Self::Halo2ProofGeneration => Duration::from_secs(30),
            Self::Halo2ProofVerification => Duration::from_secs(5),
            Self::MlDsaSignature => Duration::from_millis(500),
            Self::MlDsaVerification => Duration::from_millis(200),
            Self::MerkleTreeConstruction => Duration::from_secs(2),
            Self::MerklePathGeneration => Duration::from_millis(100),
            Self::Poseidon2Hash => Duration::from_millis(10),
        }
    }
}

/// État du circuit breaker
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitState {
    /// Circuit fermé - opérations autorisées
    Closed,
    /// Circuit ouvert - opérations bloquées
    Open,
    /// Circuit semi-ouvert - test de récupération
    HalfOpen,
}

/// Statistiques d'une opération cryptographique
#[derive(Debug, Clone)]
struct OperationStats {
    /// Nombre total d'opérations tentées
    total_attempts: u64,
    /// Nombre d'échecs (timeout, erreur)
    failures: u64,
    /// Temps de réponse récents (sliding window)
    recent_times: VecDeque<Duration>,
    /// Dernière tentative
    last_attempt: Option<Instant>,
    /// Dernière réussite
    last_success: Option<Instant>,
}

impl Default for OperationStats {
    fn default() -> Self {
        Self {
            total_attempts: 0,
            failures: 0,
            recent_times: VecDeque::with_capacity(100),
            last_attempt: None,
            last_success: None,
        }
    }
}

impl OperationStats {
    /// Taux d'échec récent (sur les 100 dernières opérations)
    fn failure_rate(&self) -> f64 {
        if self.total_attempts == 0 {
            return 0.0;
        }
        
        let recent_count = self.recent_times.len() as u64;
        if recent_count == 0 {
            return 0.0;
        }
        
        // Approximation: on considère que les échecs sont distribués uniformément
        let recent_failures = (self.failures * recent_count) / self.total_attempts.max(1);
        recent_failures as f64 / recent_count as f64
    }

    /// Temps de réponse moyen récent
    fn avg_response_time(&self) -> Duration {
        if self.recent_times.is_empty() {
            return Duration::from_millis(0);
        }
        
        let total: Duration = self.recent_times.iter().sum();
        total / self.recent_times.len() as u32
    }

    /// Enregistrer une tentative d'opération
    fn record_attempt(&mut self, duration: Duration, success: bool) {
        self.total_attempts += 1;
        self.last_attempt = Some(Instant::now());
        
        if success {
            self.last_success = Some(Instant::now());
        } else {
            self.failures += 1;
        }
        
        // Sliding window des temps de réponse
        self.recent_times.push_back(duration);
        if self.recent_times.len() > 100 {
            self.recent_times.pop_front();
        }
    }
}

/// Configuration du circuit breaker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Seuil de taux d'échec pour ouvrir le circuit (0.0-1.0)
    pub failure_threshold: f64,
    /// Nombre minimum d'opérations avant d'évaluer le taux d'échec
    pub min_operations: u32,
    /// Durée d'ouverture du circuit avant test de récupération
    pub recovery_timeout: Duration,
    /// Nombre d'opérations de test en mode HalfOpen
    pub test_operations: u32,
    /// Limite de charge globale (opérations/seconde)
    pub global_rate_limit: u32,
    /// Fenêtre de temps pour le rate limiting
    pub rate_window: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 0.5, // 50% d'échecs
            min_operations: 10,
            recovery_timeout: Duration::from_secs(60),
            test_operations: 5,
            global_rate_limit: 100, // 100 ops/sec max
            rate_window: Duration::from_secs(1),
        }
    }
}

/// Circuit breaker pour opérations cryptographiques
pub struct CryptoCircuitBreaker {
    /// Configuration
    config: CircuitBreakerConfig,
    /// État global du circuit
    state: Arc<RwLock<CircuitState>>,
    /// Statistiques par type d'opération
    stats: Arc<Mutex<std::collections::HashMap<CryptoOperation, OperationStats>>>,
    /// Timestamp de la dernière ouverture du circuit
    last_opened: Arc<Mutex<Option<Instant>>>,
    /// Compteur d'opérations de test en mode HalfOpen
    test_count: Arc<Mutex<u32>>,
    /// Rate limiter global
    rate_limiter: Arc<Mutex<VecDeque<Instant>>>,
}

impl Default for CryptoCircuitBreaker {
    fn default() -> Self {
        Self::new(CircuitBreakerConfig::default())
    }
}

impl CryptoCircuitBreaker {
    /// Créer un nouveau circuit breaker avec la configuration donnée
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CircuitState::Closed)),
            stats: Arc::new(Mutex::new(std::collections::HashMap::new())),
            last_opened: Arc::new(Mutex::new(None)),
            test_count: Arc::new(Mutex::new(0)),
            rate_limiter: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Vérifier si une opération est autorisée
    pub async fn check_operation(&self, op: CryptoOperation) -> Result<OperationGuard<'_>, CircuitBreakerError> {
        // 1. Vérifier le rate limiting global
        self.check_rate_limit().await?;
        
        // 2. Vérifier l'état du circuit
        let state = *self.state.read().unwrap();
        
        match state {
            CircuitState::Closed => {
                // Circuit fermé - autoriser l'opération
                Ok(OperationGuard::new(self, op))
            }
            
            CircuitState::Open => {
                // Vérifier si on peut passer en mode HalfOpen
                let last_opened = self.last_opened.lock().unwrap();
                if let Some(opened_time) = *last_opened {
                    if opened_time.elapsed() >= self.config.recovery_timeout {
                        drop(last_opened);
                        self.transition_to_half_open();
                        return Ok(OperationGuard::new(self, op));
                    }
                }
                
                Err(CircuitBreakerError::CircuitOpen {
                    operation: op,
                    retry_after: self.config.recovery_timeout,
                })
            }
            
            CircuitState::HalfOpen => {
                // Mode test - autoriser un nombre limité d'opérations
                let mut test_count = self.test_count.lock().unwrap();
                if *test_count < self.config.test_operations {
                    *test_count += 1;
                    Ok(OperationGuard::new(self, op))
                } else {
                    Err(CircuitBreakerError::CircuitOpen {
                        operation: op,
                        retry_after: Duration::from_secs(1),
                    })
                }
            }
        }
    }

    /// Vérifier le rate limiting global
    async fn check_rate_limit(&self) -> Result<(), CircuitBreakerError> {
        let mut limiter = self.rate_limiter.lock().unwrap();
        let now = Instant::now();
        
        // Nettoyer les entrées anciennes
        while let Some(&front) = limiter.front() {
            if now.duration_since(front) > self.config.rate_window {
                limiter.pop_front();
            } else {
                break;
            }
        }
        
        // Vérifier la limite
        if limiter.len() >= self.config.global_rate_limit as usize {
            return Err(CircuitBreakerError::RateLimitExceeded {
                current_rate: limiter.len() as u32,
                limit: self.config.global_rate_limit,
            });
        }
        
        // Enregistrer cette opération
        limiter.push_back(now);
        Ok(())
    }

    /// Transition vers l'état HalfOpen
    fn transition_to_half_open(&self) {
        *self.state.write().unwrap() = CircuitState::HalfOpen;
        *self.test_count.lock().unwrap() = 0;
    }

    /// Enregistrer le résultat d'une opération
    fn record_operation(&self, op: CryptoOperation, duration: Duration, success: bool) {
        let mut stats = self.stats.lock().unwrap();
        let op_stats = stats.entry(op).or_default();
        op_stats.record_attempt(duration, success);
        
        // Évaluer si le circuit doit changer d'état
        self.evaluate_circuit_state(op, op_stats);
    }

    /// Évaluer si le circuit doit changer d'état
    fn evaluate_circuit_state(&self, _op: CryptoOperation, stats: &OperationStats) {
        let current_state = *self.state.read().unwrap();
        
        match current_state {
            CircuitState::Closed => {
                // Vérifier si on doit ouvrir le circuit
                if stats.total_attempts >= self.config.min_operations as u64 {
                    if stats.failure_rate() >= self.config.failure_threshold {
                        self.open_circuit();
                    }
                }
            }
            
            CircuitState::HalfOpen => {
                let test_count = *self.test_count.lock().unwrap();
                
                if test_count >= self.config.test_operations {
                    // Évaluer les résultats du test
                    if stats.failure_rate() < self.config.failure_threshold {
                        // Récupération réussie - fermer le circuit
                        *self.state.write().unwrap() = CircuitState::Closed;
                    } else {
                        // Échec de récupération - rouvrir le circuit
                        self.open_circuit();
                    }
                }
            }
            
            CircuitState::Open => {
                // Rien à faire - le circuit s'ouvrira automatiquement après timeout
            }
        }
    }

    /// Ouvrir le circuit
    fn open_circuit(&self) {
        *self.state.write().unwrap() = CircuitState::Open;
        *self.last_opened.lock().unwrap() = Some(Instant::now());
        *self.test_count.lock().unwrap() = 0;
    }

    /// Obtenir l'état actuel du circuit
    pub fn state(&self) -> CircuitState {
        *self.state.read().unwrap()
    }

    /// Obtenir les statistiques d'une opération
    pub fn operation_stats(&self, op: CryptoOperation) -> Option<(f64, Duration, u64)> {
        let stats = self.stats.lock().unwrap();
        stats.get(&op).map(|s| (s.failure_rate(), s.avg_response_time(), s.total_attempts))
    }

    /// Réinitialiser le circuit breaker
    pub fn reset(&self) {
        *self.state.write().unwrap() = CircuitState::Closed;
        *self.last_opened.lock().unwrap() = None;
        *self.test_count.lock().unwrap() = 0;
        self.stats.lock().unwrap().clear();
        self.rate_limiter.lock().unwrap().clear();
    }
}

/// Guard pour une opération cryptographique
/// Enregistre automatiquement le résultat à la fin
pub struct OperationGuard<'a> {
    breaker: &'a CryptoCircuitBreaker,
    operation: CryptoOperation,
    start_time: Instant,
}

impl<'a> OperationGuard<'a> {
    fn new(breaker: &'a CryptoCircuitBreaker, operation: CryptoOperation) -> Self {
        Self {
            breaker,
            operation,
            start_time: Instant::now(),
        }
    }

    /// Marquer l'opération comme réussie
    pub fn success(self) {
        let duration = self.start_time.elapsed();
        self.breaker.record_operation(self.operation, duration, true);
    }

    /// Marquer l'opération comme échouée
    pub fn failure(self) {
        let duration = self.start_time.elapsed();
        self.breaker.record_operation(self.operation, duration, false);
    }
}

impl<'a> Drop for OperationGuard<'a> {
    fn drop(&mut self) {
        // Par défaut, considérer comme un échec si pas explicitement marqué
        let duration = self.start_time.elapsed();
        self.breaker.record_operation(self.operation, duration, false);
    }
}

/// Erreurs du circuit breaker
#[derive(Debug, Error)]
pub enum CircuitBreakerError {
    #[error("Circuit ouvert pour l'opération {operation:?}, réessayer dans {retry_after:?}")]
    CircuitOpen {
        operation: CryptoOperation,
        retry_after: Duration,
    },
    
    #[error("Rate limit dépassé: {current_rate}/s > {limit}/s")]
    RateLimitExceeded {
        current_rate: u32,
        limit: u32,
    },
    
    #[error("Opération timeout après {timeout:?}")]
    OperationTimeout {
        timeout: Duration,
    },
}

// Instance globale du circuit breaker (singleton)
lazy_static::lazy_static! {
    static ref GLOBAL_CIRCUIT_BREAKER: CryptoCircuitBreaker = {
        CryptoCircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 0.3, // 30% d'échecs pour ouvrir
            min_operations: 5,
            recovery_timeout: Duration::from_secs(30),
            test_operations: 3,
            global_rate_limit: 50, // 50 ops/sec max
            rate_window: Duration::from_secs(1),
        })
    };
}

/// Obtenir l'instance globale du circuit breaker
pub fn global_circuit_breaker() -> &'static CryptoCircuitBreaker {
    &GLOBAL_CIRCUIT_BREAKER
}

/// Macro pour protéger une opération cryptographique
#[macro_export]
macro_rules! protected_crypto_op {
    ($op:expr, $code:block) => {{
        let guard = $crate::crypto::circuit_breaker::global_circuit_breaker()
            .check_operation($op)
            .await?;
        
        let result = $code;
        
        match &result {
            Ok(_) => guard.success(),
            Err(_) => guard.failure(),
        }
        
        result
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_circuit_breaker_basic() {
        let breaker = CryptoCircuitBreaker::default();
        
        // Circuit doit être fermé initialement
        assert_eq!(breaker.state(), CircuitState::Closed);
        
        // Opération autorisée
        let guard = breaker.check_operation(CryptoOperation::Poseidon2Hash).await.unwrap();
        guard.success();
    }

    #[tokio::test]
    async fn test_circuit_opens_on_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 0.5,
            min_operations: 3,
            ..Default::default()
        };
        let breaker = CryptoCircuitBreaker::new(config);
        
        // Simuler des échecs
        for _ in 0..5 {
            let guard = breaker.check_operation(CryptoOperation::Halo2ProofGeneration).await.unwrap();
            guard.failure();
        }
        
        // Circuit doit être ouvert
        assert_eq!(breaker.state(), CircuitState::Open);
        
        // Nouvelle opération doit être rejetée
        let result = breaker.check_operation(CryptoOperation::Halo2ProofGeneration).await;
        assert!(matches!(result, Err(CircuitBreakerError::CircuitOpen { .. })));
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let config = CircuitBreakerConfig {
            global_rate_limit: 2,
            rate_window: Duration::from_millis(100),
            ..Default::default()
        };
        let breaker = CryptoCircuitBreaker::new(config);
        
        // Première opération OK
        let _guard1 = breaker.check_operation(CryptoOperation::Poseidon2Hash).await.unwrap();
        
        // Deuxième opération OK
        let _guard2 = breaker.check_operation(CryptoOperation::Poseidon2Hash).await.unwrap();
        
        // Troisième opération doit être rejetée
        let result = breaker.check_operation(CryptoOperation::Poseidon2Hash).await;
        assert!(matches!(result, Err(CircuitBreakerError::RateLimitExceeded { .. })));
        
        // Attendre et réessayer
        sleep(Duration::from_millis(150)).await;
        let _guard3 = breaker.check_operation(CryptoOperation::Poseidon2Hash).await.unwrap();
    }

    #[tokio::test]
    async fn test_recovery_cycle() {
        let config = CircuitBreakerConfig {
            failure_threshold: 0.5,
            min_operations: 2,
            recovery_timeout: Duration::from_millis(50),
            test_operations: 2,
            ..Default::default()
        };
        let breaker = CryptoCircuitBreaker::new(config);
        
        // Provoquer l'ouverture du circuit
        for _ in 0..3 {
            let guard = breaker.check_operation(CryptoOperation::MlDsaSignature).await.unwrap();
            guard.failure();
        }
        assert_eq!(breaker.state(), CircuitState::Open);
        
        // Attendre le timeout de récupération
        sleep(Duration::from_millis(60)).await;
        
        // Première opération après timeout doit passer en HalfOpen
        let guard = breaker.check_operation(CryptoOperation::MlDsaSignature).await.unwrap();
        assert_eq!(breaker.state(), CircuitState::HalfOpen);
        guard.success();
        
        // Deuxième opération de test
        let guard = breaker.check_operation(CryptoOperation::MlDsaSignature).await.unwrap();
        guard.success();
        
        // Circuit doit être fermé après succès des tests
        assert_eq!(breaker.state(), CircuitState::Closed);
    }
}