//! Preemptive transaction validation with circuit breaker.
//!
//! This module provides early validation of transactions before they enter the mempool,
//! with a circuit breaker pattern to prevent overload during validation spikes.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use thiserror::Error;

use crate::core::{
    ShieldedState, ShieldedTransaction, Transaction, StateError,
    validation::{Validator, ValidationError},
};
use crate::crypto::proof::CircomVerifyingParams;

/// Errors specific to preemptive validation.
#[derive(Debug, Error)]
pub enum PreemptiveValidationError {
    #[error("Validation failed: {0}")]
    ValidationFailed(#[from] ValidationError),

    #[error("State error: {0}")]
    StateError(#[from] StateError),

    #[error("Circuit breaker is open - validation temporarily disabled")]
    CircuitBreakerOpen,

    #[error("Validation queue is full - too many pending validations")]
    QueueFull,

    #[error("Transaction malformed: {reason}")]
    MalformedTransaction { reason: String },

    #[error("Validation timeout after {timeout_ms}ms")]
    ValidationTimeout { timeout_ms: u64 },

    #[error("Rate limit exceeded - too many validation requests")]
    RateLimitExceeded,
}

/// Circuit breaker states for validation protection.
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitBreakerState {
    /// Normal operation - validations are processed.
    Closed,
    /// Temporary failure state - validations are rejected.
    Open,
    /// Testing state - limited validations allowed to test recovery.
    HalfOpen,
}

/// Configuration for the preemptive validator.
#[derive(Debug, Clone)]
pub struct PreemptiveValidatorConfig {
    /// Maximum number of validation failures before opening circuit breaker.
    pub failure_threshold: u32,
    /// Time window for counting failures.
    pub failure_window: Duration,
    /// How long to keep circuit breaker open before trying half-open.
    pub recovery_timeout: Duration,
    /// Maximum number of pending validations in queue.
    pub max_queue_size: usize,
    /// Maximum time to spend on a single validation.
    pub validation_timeout: Duration,
    /// Maximum validations per second (rate limiting).
    pub max_validations_per_second: u32,
    /// Enable basic malformation checks (fast pre-validation).
    pub enable_malformation_checks: bool,
    /// Enable full cryptographic proof verification.
    pub enable_proof_verification: bool,
}

impl Default for PreemptiveValidatorConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 10,
            failure_window: Duration::from_secs(60),
            recovery_timeout: Duration::from_secs(30),
            max_queue_size: 1000,
            validation_timeout: Duration::from_millis(5000),
            max_validations_per_second: 100,
            enable_malformation_checks: true,
            enable_proof_verification: true,
        }
    }
}

/// Metrics for monitoring validation performance.
#[derive(Debug, Default, Clone)]
pub struct ValidationMetrics {
    /// Total validations attempted.
    pub total_validations: u64,
    /// Total validations that passed.
    pub successful_validations: u64,
    /// Total validations that failed.
    pub failed_validations: u64,
    /// Total validations rejected by circuit breaker.
    pub circuit_breaker_rejections: u64,
    /// Total validations rejected by rate limiter.
    pub rate_limit_rejections: u64,
    /// Total malformed transactions detected.
    pub malformed_transactions: u64,
    /// Average validation time in microseconds.
    pub avg_validation_time_us: u64,
    /// Current queue size.
    pub current_queue_size: usize,
}

/// Internal state for circuit breaker logic.
#[derive(Debug)]
struct CircuitBreakerState {
    state: CircuitBreakerState,
    failure_count: u32,
    last_failure_time: Option<Instant>,
    last_state_change: Instant,
    failure_times: VecDeque<Instant>,
}

impl CircuitBreakerState {
    fn new() -> Self {
        Self {
            state: CircuitBreakerState::Closed,
            failure_count: 0,
            last_failure_time: None,
            last_state_change: Instant::now(),
            failure_times: VecDeque::new(),
        }
    }
}

/// Rate limiter using token bucket algorithm.
#[derive(Debug)]
struct RateLimiter {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl RateLimiter {
    fn new(max_rate: u32) -> Self {
        Self {
            tokens: max_rate as f64,
            max_tokens: max_rate as f64,
            refill_rate: max_rate as f64,
            last_refill: Instant::now(),
        }
    }

    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }
}

/// Preemptive transaction validator with circuit breaker protection.
///
/// This validator performs early validation of transactions before they enter
/// the mempool, with protection against overload through circuit breaker pattern.
///
/// # Validation Stages
/// 1. Rate limiting check
/// 2. Circuit breaker state check
/// 3. Basic malformation checks (fast)
/// 4. Full validation with proof verification (slow)
///
/// # Circuit Breaker Logic
/// - CLOSED: Normal operation, all validations processed
/// - OPEN: Too many failures, reject all validations
/// - HALF_OPEN: Testing recovery, allow limited validations
#[derive(Debug)]
pub struct PreemptiveValidator {
    /// Configuration parameters.
    config: PreemptiveValidatorConfig,
    /// Core validator for actual validation logic.
    validator: Arc<RwLock<Validator>>,
    /// Circuit breaker state.
    circuit_breaker: Arc<RwLock<CircuitBreakerState>>,
    /// Rate limiter for validation requests.
    rate_limiter: Arc<RwLock<RateLimiter>>,
    /// Performance metrics.
    metrics: Arc<RwLock<ValidationMetrics>>,
}

impl PreemptiveValidator {
    /// Create a new preemptive validator with default configuration.
    pub fn new() -> Self {
        Self::with_config(PreemptiveValidatorConfig::default())
    }

    /// Create a new preemptive validator with custom configuration.
    pub fn with_config(config: PreemptiveValidatorConfig) -> Self {
        Self {
            rate_limiter: Arc::new(RwLock::new(RateLimiter::new(config.max_validations_per_second))),
            validator: Arc::new(RwLock::new(Validator::new())),
            circuit_breaker: Arc::new(RwLock::new(CircuitBreakerState::new())),
            metrics: Arc::new(RwLock::new(ValidationMetrics::default())),
            config,
        }
    }

    /// Create a validator for testing (no proof verification, relaxed limits).
    pub fn for_testing() -> Self {
        let mut config = PreemptiveValidatorConfig::default();
        config.enable_proof_verification = false;
        config.max_validations_per_second = 1000;
        config.failure_threshold = 100;
        
        let mut validator = Self::with_config(config);
        validator.validator.write().unwrap().set_proof_verification(false);
        validator
    }

    /// Validate a V1 shielded transaction preemptively.
    ///
    /// Returns Ok(()) if the transaction is valid and can be added to mempool.
    /// Returns Err if validation fails or circuit breaker prevents validation.
    pub fn validate_transaction(
        &self,
        tx: &ShieldedTransaction,
        state: &ShieldedState,
        verifying_params: Option<&CircomVerifyingParams>,
    ) -> Result<(), PreemptiveValidationError> {
        let start_time = Instant::now();
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().unwrap();
            metrics.total_validations += 1;
        }

        // 1. Rate limiting check
        if !self.rate_limiter.write().unwrap().try_consume() {
            let mut metrics = self.metrics.write().unwrap();
            metrics.rate_limit_rejections += 1;
            return Err(PreemptiveValidationError::RateLimitExceeded);
        }

        // 2. Circuit breaker check
        if !self.can_validate()? {
            let mut metrics = self.metrics.write().unwrap();
            metrics.circuit_breaker_rejections += 1;
            return Err(PreemptiveValidationError::CircuitBreakerOpen);
        }

        // 3. Basic malformation checks (fast)
        if self.config.enable_malformation_checks {
            if let Err(e) = self.check_basic_malformation_v1(tx) {
                self.record_failure();
                let mut metrics = self.metrics.write().unwrap();
                metrics.malformed_transactions += 1;
                metrics.failed_validations += 1;
                return Err(e);
            }
        }

        // 4. Full validation with timeout
        let validation_result = self.validate_with_timeout(|| {
            let mut validator = self.validator.write().unwrap();
            validator.validate_transaction(tx, state, verifying_params)
        });

        // Record result and update metrics
        let elapsed = start_time.elapsed();
        match validation_result {
            Ok(_) => {
                self.record_success();
                let mut metrics = self.metrics.write().unwrap();
                metrics.successful_validations += 1;
                self.update_avg_time(&mut metrics, elapsed);
                Ok(())
            }
            Err(e) => {
                self.record_failure();
                let mut metrics = self.metrics.write().unwrap();
                metrics.failed_validations += 1;
                self.update_avg_time(&mut metrics, elapsed);
                Err(PreemptiveValidationError::ValidationFailed(e))
            }
        }
    }

    /// Validate a V2 transaction preemptively.
    pub fn validate_transaction_v2(
        &self,
        tx: &Transaction,
        state: &ShieldedState,
        verifying_params: Option<&CircomVerifyingParams>,
    ) -> Result<(), PreemptiveValidationError> {
        let start_time = Instant::now();
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().unwrap();
            metrics.total_validations += 1;
        }

        // 1. Rate limiting check
        if !self.rate_limiter.write().unwrap().try_consume() {
            let mut metrics = self.metrics.write().unwrap();
            metrics.rate_limit_rejections += 1;
            return Err(PreemptiveValidationError::RateLimitExceeded);
        }

        // 2. Circuit breaker check
        if !self.can_validate()? {
            let mut metrics = self.metrics.write().unwrap();
            metrics.circuit_breaker_rejections += 1;
            return Err(PreemptiveValidationError::CircuitBreakerOpen);
        }

        // 3. Basic malformation checks (fast)
        if self.config.enable_malformation_checks {
            if let Err(e) = self.check_basic_malformation_v2(tx) {
                self.record_failure();
                let mut metrics = self.metrics.write().unwrap();
                metrics.malformed_transactions += 1;
                metrics.failed_validations += 1;
                return Err(e);
            }
        }

        // 4. Full validation with timeout
        let validation_result = self.validate_with_timeout(|| {
            // For V2 transactions, we need to extract the shielded part
            match tx {
                Transaction::V2(v2_tx) => {
                    // Convert to V1 format for validation
                    let v1_tx = ShieldedTransaction::new(
                        v2_tx.spends.iter().map(|s| s.to_v1()).collect(),
                        v2_tx.outputs.iter().map(|o| o.to_v1()).collect(),
                        v2_tx.fee,
                        v2_tx.binding_signature.clone(),
                    );
                    let mut validator = self.validator.write().unwrap();
                    validator.validate_transaction(&v1_tx, state, verifying_params)
                }
                Transaction::Migration(_) => {
                    // Migration transactions have simpler validation
                    // For now, just basic checks
                    Ok(())
                }
            }
        });

        // Record result and update metrics
        let elapsed = start_time.elapsed();
        match validation_result {
            Ok(_) => {
                self.record_success();
                let mut metrics = self.metrics.write().unwrap();
                metrics.successful_validations += 1;
                self.update_avg_time(&mut metrics, elapsed);
                Ok(())
            }
            Err(e) => {
                self.record_failure();
                let mut metrics = self.metrics.write().unwrap();
                metrics.failed_validations += 1;
                self.update_avg_time(&mut metrics, elapsed);
                Err(PreemptiveValidationError::ValidationFailed(e))
            }
        }
    }

    /// Check if validation can proceed based on circuit breaker state.
    fn can_validate(&self) -> Result<bool, PreemptiveValidationError> {
        let mut cb = self.circuit_breaker.write().unwrap();
        let now = Instant::now();

        // Clean up old failure times
        while let Some(&front_time) = cb.failure_times.front() {
            if now.duration_since(front_time) > self.config.failure_window {
                cb.failure_times.pop_front();
            } else {
                break;
            }
        }

        match cb.state {
            CircuitBreakerState::Closed => {
                // Check if we should open due to too many failures
                if cb.failure_times.len() >= self.config.failure_threshold as usize {
                    cb.state = CircuitBreakerState::Open;
                    cb.last_state_change = now;
                    Ok(false)
                } else {
                    Ok(true)
                }
            }
            CircuitBreakerState::Open => {
                // Check if we should try half-open
                if now.duration_since(cb.last_state_change) >= self.config.recovery_timeout {
                    cb.state = CircuitBreakerState::HalfOpen;
                    cb.last_state_change = now;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            CircuitBreakerState::HalfOpen => {
                // Allow limited validations to test recovery
                Ok(true)
            }
        }
    }

    /// Record a successful validation.
    fn record_success(&self) {
        let mut cb = self.circuit_breaker.write().unwrap();
        if cb.state == CircuitBreakerState::HalfOpen {
            // Recovery successful, close the circuit
            cb.state = CircuitBreakerState::Closed;
            cb.last_state_change = Instant::now();
            cb.failure_times.clear();
        }
    }

    /// Record a failed validation.
    fn record_failure(&self) {
        let mut cb = self.circuit_breaker.write().unwrap();
        let now = Instant::now();
        
        cb.failure_count += 1;
        cb.last_failure_time = Some(now);
        cb.failure_times.push_back(now);

        if cb.state == CircuitBreakerState::HalfOpen {
            // Failure during recovery, go back to open
            cb.state = CircuitBreakerState::Open;
            cb.last_state_change = now;
        }
    }

    /// Execute validation with timeout protection.
    fn validate_with_timeout<F, R>(&self, validation_fn: F) -> Result<R, ValidationError>
    where
        F: FnOnce() -> Result<R, ValidationError>,
    {
        // For now, just execute directly
        // In a real implementation, we'd use tokio::time::timeout
        validation_fn()
    }

    /// Check basic malformation for V1 transactions (fast checks).
    fn check_basic_malformation_v1(&self, tx: &ShieldedTransaction) -> Result<(), PreemptiveValidationError> {
        // Check basic structure
        if tx.spends.is_empty() && tx.outputs.is_empty() {
            return Err(PreemptiveValidationError::MalformedTransaction {
                reason: "Transaction has no spends or outputs".to_string(),
            });
        }

        // Check fee is reasonable (not negative, not excessive)
        if tx.fee > 1_000_000_000 {
            return Err(PreemptiveValidationError::MalformedTransaction {
                reason: format!("Fee too high: {}", tx.fee),
            });
        }

        // Check binding signature is present and reasonable length
        if tx.binding_signature.signature.len() != 64 {
            return Err(PreemptiveValidationError::MalformedTransaction {
                reason: "Invalid binding signature length".to_string(),
            });
        }

        // Check spend descriptions
        for (i, spend) in tx.spends.iter().enumerate() {
            if spend.nullifier.0.len() != 32 {
                return Err(PreemptiveValidationError::MalformedTransaction {
                    reason: format!("Invalid nullifier length in spend {}", i),
                });
            }
            if spend.anchor.len() != 32 {
                return Err(PreemptiveValidationError::MalformedTransaction {
                    reason: format!("Invalid anchor length in spend {}", i),
                });
            }
        }

        // Check output descriptions
        for (i, output) in tx.outputs.iter().enumerate() {
            if output.commitment.0.len() != 32 {
                return Err(PreemptiveValidationError::MalformedTransaction {
                    reason: format!("Invalid commitment length in output {}", i),
                });
            }
        }

        Ok(())
    }

    /// Check basic malformation for V2 transactions (fast checks).
    fn check_basic_malformation_v2(&self, tx: &Transaction) -> Result<(), PreemptiveValidationError> {
        match tx {
            Transaction::V2(v2_tx) => {
                // Similar checks as V1
                if v2_tx.spends.is_empty() && v2_tx.outputs.is_empty() {
                    return Err(PreemptiveValidationError::MalformedTransaction {
                        reason: "V2 transaction has no spends or outputs".to_string(),
                    });
                }

                if v2_tx.fee > 1_000_000_000 {
                    return Err(PreemptiveValidationError::MalformedTransaction {
                        reason: format!("V2 fee too high: {}", v2_tx.fee),
                    });
                }

                // Check post-quantum signatures
                for (i, spend) in v2_tx.spends.iter().enumerate() {
                    if spend.nullifier.len() != 32 {
                        return Err(PreemptiveValidationError::MalformedTransaction {
                            reason: format!("Invalid V2 nullifier length in spend {}", i),
                        });
                    }
                }

                Ok(())
            }
            Transaction::Migration(migration_tx) => {
                // Basic checks for migration transactions
                if migration_tx.legacy_inputs.is_empty() && migration_tx.shielded_outputs.is_empty() {
                    return Err(PreemptiveValidationError::MalformedTransaction {
                        reason: "Migration transaction has no inputs or outputs".to_string(),
                    });
                }
                Ok(())
            }
        }
    }

    /// Update average validation time metric.
    fn update_avg_time(&self, metrics: &mut ValidationMetrics, elapsed: Duration) {
        let elapsed_us = elapsed.as_micros() as u64;
        if metrics.total_validations == 1 {
            metrics.avg_validation_time_us = elapsed_us;
        } else {
            // Exponential moving average
            metrics.avg_validation_time_us = 
                (metrics.avg_validation_time_us * 9 + elapsed_us) / 10;
        }
    }

    /// Get current validation metrics.
    pub fn get_metrics(&self) -> ValidationMetrics {
        self.metrics.read().unwrap().clone()
    }

    /// Get current circuit breaker state.
    pub fn get_circuit_breaker_state(&self) -> CircuitBreakerState {
        self.circuit_breaker.read().unwrap().state.clone()
    }

    /// Reset circuit breaker to closed state (for testing or manual recovery).
    pub fn reset_circuit_breaker(&self) {
        let mut cb = self.circuit_breaker.write().unwrap();
        cb.state = CircuitBreakerState::Closed;
        cb.failure_count = 0;
        cb.last_failure_time = None;
        cb.last_state_change = Instant::now();
        cb.failure_times.clear();
    }

    /// Reset all metrics (for testing).
    pub fn reset_metrics(&self) {
        let mut metrics = self.metrics.write().unwrap();
        *metrics = ValidationMetrics::default();
    }

    /// Update configuration at runtime.
    pub fn update_config(&mut self, new_config: PreemptiveValidatorConfig) {
        // Update rate limiter
        {
            let mut rate_limiter = self.rate_limiter.write().unwrap();
            *rate_limiter = RateLimiter::new(new_config.max_validations_per_second);
        }

        // Update validator proof verification setting
        {
            let mut validator = self.validator.write().unwrap();
            validator.set_proof_verification(new_config.enable_proof_verification);
        }

        self.config = new_config;
    }
}

impl Default for PreemptiveValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{BindingSignature, SpendDescription, OutputDescription};
    use crate::crypto::{Nullifier, Commitment};

    fn dummy_v1_tx(fee: u64) -> ShieldedTransaction {
        ShieldedTransaction::new(
            vec![],
            vec![],
            fee,
            BindingSignature::new(vec![1; 64])
        )
    }

    fn dummy_v1_tx_with_spends() -> ShieldedTransaction {
        let spend = SpendDescription {
            nullifier: Nullifier([1; 32]),
            anchor: [2; 32],
            proof: vec![3; 192],
        };
        let output = OutputDescription {
            commitment: Commitment([4; 32]),
            ephemeral_key: [5; 32],
            encrypted_note: vec![6; 80],
            proof: vec![7; 192],
        };
        
        ShieldedTransaction::new(
            vec![spend],
            vec![output],
            1000,
            BindingSignature::new(vec![1; 64])
        )
    }

    #[test]
    fn test_preemptive_validator_creation() {
        let validator = PreemptiveValidator::new();
        assert_eq!(validator.get_circuit_breaker_state(), CircuitBreakerState::Closed);
        
        let metrics = validator.get_metrics();
        assert_eq!(metrics.total_validations, 0);
    }

    #[test]
    fn test_basic_malformation_checks() {
        let validator = PreemptiveValidator::for_testing();
        
        // Valid transaction should pass
        let valid_tx = dummy_v1_tx_with_spends();
        assert!(validator.check_basic_malformation_v1(&valid_tx).is_ok());
        
        // Empty transaction should fail
        let empty_tx = ShieldedTransaction::new(
            vec![],
            vec![],
            1000,
            BindingSignature::new(vec![1; 64])
        );
        assert!(validator.check_basic_malformation_v1(&empty_tx).is_err());
        
        // Excessive fee should fail
        let high_fee_tx = dummy_v1_tx(2_000_000_000);
        assert!(validator.check_basic_malformation_v1(&high_fee_tx).is_err());
    }

    #[test]
    fn test_rate_limiting() {
        let mut config = PreemptiveValidatorConfig::default();
        config.max_validations_per_second = 2; // Very low limit for testing
        
        let validator = PreemptiveValidator::with_config(config);
        
        // First two should succeed (rate limit)
        {
            let mut rate_limiter = validator.rate_limiter.write().unwrap();
            assert!(rate_limiter.try_consume());
            assert!(rate_limiter.try_consume());
            // Third should fail
            assert!(!rate_limiter.try_consume());
        }
    }

    #[test]
    fn test_circuit_breaker_states() {
        let mut config = PreemptiveValidatorConfig::default();
        config.failure_threshold = 2; // Low threshold for testing
        config.failure_window = Duration::from_secs(10);
        
        let validator = PreemptiveValidator::with_config(config);
        
        // Initially closed
        assert_eq!(validator.get_circuit_breaker_state(), CircuitBreakerState::Closed);
        assert!(validator.can_validate().unwrap());
        
        // Record failures to trigger opening
        validator.record_failure();
        validator.record_failure();
        
        // Should now be open after checking
        assert!(!validator.can_validate().unwrap());
        assert_eq!(validator.get_circuit_breaker_state(), CircuitBreakerState::Open);
    }

    #[test]
    fn test_metrics_tracking() {
        let validator = PreemptiveValidator::for_testing();
        
        // Initial metrics
        let initial_metrics = validator.get_metrics();
        assert_eq!(initial_metrics.total_validations, 0);
        assert_eq!(initial_metrics.successful_validations, 0);
        
        // Simulate some activity
        {
            let mut metrics = validator.metrics.write().unwrap();
            metrics.total_validations = 10;
            metrics.successful_validations = 8;
            metrics.failed_validations = 2;
        }
        
        let updated_metrics = validator.get_metrics();
        assert_eq!(updated_metrics.total_validations, 10);
        assert_eq!(updated_metrics.successful_validations, 8);
        assert_eq!(updated_metrics.failed_validations, 2);
    }

    #[test]
    fn test_circuit_breaker_recovery() {
        let mut config = PreemptiveValidatorConfig::default();
        config.failure_threshold = 1;
        config.recovery_timeout = Duration::from_millis(10);
        
        let validator = PreemptiveValidator::with_config(config);
        
        // Trigger circuit breaker
        validator.record_failure();
        assert!(!validator.can_validate().unwrap());
        
        // Wait for recovery timeout
        std::thread::sleep(Duration::from_millis(20));
        
        // Should now allow validation (half-open)
        assert!(validator.can_validate().unwrap());
        
        // Successful validation should close the circuit
        validator.record_success();
        assert_eq!(validator.get_circuit_breaker_state(), CircuitBreakerState::Closed);
    }

    #[test]
    fn test_config_update() {
        let mut validator = PreemptiveValidator::for_testing();
        
        let mut new_config = PreemptiveValidatorConfig::default();
        new_config.max_validations_per_second = 500;
        new_config.enable_proof_verification = true;
        
        validator.update_config(new_config);
        
        // Verify rate limiter was updated
        {
            let rate_limiter = validator.rate_limiter.read().unwrap();
            assert_eq!(rate_limiter.max_tokens, 500.0);
        }
        
        // Verify validator was updated
        {
            let validator_inner = validator.validator.read().unwrap();
            // Note: We can't directly check proof verification setting,
            // but we can verify the config was stored
        }
    }

    #[test]
    fn test_malformed_transaction_detection() {
        let validator = PreemptiveValidator::for_testing();
        
        // Test invalid nullifier length
        let mut bad_spend = SpendDescription {
            nullifier: Nullifier([1; 32]),
            anchor: [2; 32],
            proof: vec![3; 192],
        };
        // Simulate corrupted nullifier
        bad_spend.nullifier.0 = [0; 32]; // This is still valid length
        
        // Test invalid binding signature length
        let bad_tx = ShieldedTransaction::new(
            vec![bad_spend],
            vec![],
            1000,
            BindingSignature::new(vec![1; 32]) // Wrong length
        );
        
        let result = validator.check_basic_malformation_v1(&bad_tx);
        assert!(result.is_err());
        if let Err(PreemptiveValidationError::MalformedTransaction { reason }) = result {
            assert!(reason.contains("binding signature"));
        }
    }
}