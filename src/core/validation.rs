//! Comprehensive validation module for TSN blockchain.
//!
//! This module provides validation functions for blocks, transactions,
//! and state consistency. It integrates balance validation, cryptographic
//! proof verification, and state transition validation.

use thiserror::Error;

use crate::core::{
    block::Block,
    state::{ShieldedState, StateError},
    transaction::{Transaction, ShieldedTransaction, CoinbaseTransaction},
    balance_validation::{BalanceValidator, BalanceValidationError},
};
use crate::crypto::proof::CircomVerifyingParams;
use crate::error::TsnError;

/// Comprehensive validation errors.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Balance validation failed: {0}")]
    BalanceValidation(#[from] BalanceValidationError),

    #[error("State validation failed: {0}")]
    StateValidation(#[from] StateError),

    #[error("TSN error: {0}")]
    TsnError(#[from] TsnError),

    #[error("Block validation failed: {reason}")]
    BlockValidation { reason: String },

    #[error("Transaction validation failed: {reason}")]
    TransactionValidation { reason: String },

    #[error("Proof verification failed")]
    ProofVerification,

    #[error("Invalid block header: {reason}")]
    InvalidBlockHeader { reason: String },

    #[error("Invalid timestamp: {timestamp}")]
    InvalidTimestamp { timestamp: u64 },

    #[error("Invalid difficulty: expected={expected}, got={got}")]
    InvalidDifficulty { expected: u32, got: u32 },

    #[error("Invalid previous block hash")]
    InvalidPreviousHash,
}

/// Comprehensive validator that combines all validation logic.
///
/// This validator ensures that:
/// 1. All cryptographic proofs are valid
/// 2. Balance and value conservation rules are followed
/// 3. State transitions are valid
/// 4. Block structure is correct
/// 5. All consensus rules are enforced
#[derive(Debug, Clone)]
pub struct Validator {
    /// Balance and state coherence validator.
    balance_validator: BalanceValidator,
    /// Whether to verify cryptographic proofs (can be disabled for testing).
    verify_proofs: bool,
}

impl Default for Validator {
    fn default() -> Self {
        Self::new()
    }
}

impl Validator {
    /// Create a new validator with default settings.
    pub fn new() -> Self {
        Self {
            balance_validator: BalanceValidator::new(),
            verify_proofs: true,
        }
    }

    /// Create a validator with custom balance limits.
    pub fn with_limits(max_tree_size: u64, max_supply: u64) -> Self {
        Self {
            balance_validator: BalanceValidator::with_limits(max_tree_size, max_supply),
            verify_proofs: true,
        }
    }

    /// Create a validator for testing (proofs disabled).
    pub fn for_testing() -> Self {
        Self {
            balance_validator: BalanceValidator::new(),
            verify_proofs: false,
        }
    }

    /// Enable or disable proof verification.
    pub fn set_proof_verification(&mut self, enabled: bool) {
        self.verify_proofs = enabled;
    }

    /// Get the current balance validator.
    pub fn balance_validator(&self) -> &BalanceValidator {
        &self.balance_validator
    }

    /// Get a mutable reference to the balance validator.
    pub fn balance_validator_mut(&mut self) -> &mut BalanceValidator {
        &mut self.balance_validator
    }

    /// Validate a complete block against the current state.
    ///
    /// This performs comprehensive validation including:
    /// - Block header validation
    /// - Transaction validation
    /// - Balance and state coherence
    /// - Cryptographic proof verification
    pub fn validate_block(
        &mut self,
        block: &Block,
        state: &ShieldedState,
        expected_height: u64,
        verifying_params: Option<&CircomVerifyingParams>,
    ) -> Result<(), ValidationError> {
        // 1. Validate block header
        self.validate_block_header(block, expected_height)?;

        // 2. Validate using balance validator (includes state consistency)
        self.balance_validator.validate_block(block, state, expected_height)?;

        // 3. If proof verification is enabled, verify all cryptographic proofs
        if self.verify_proofs {
            if let Some(params) = verifying_params {
                self.validate_block_proofs(block, state, params)?;
            } else {
                return Err(ValidationError::ProofVerification);
            }
        }

        Ok(())
    }

    /// Validate block header structure and basic properties.
    fn validate_block_header(
        &self,
        block: &Block,
        expected_height: u64,
    ) -> Result<(), ValidationError> {
        // Validate height
        if block.header.height != expected_height {
            return Err(ValidationError::InvalidBlockHeader {
                reason: format!(
                    "Invalid height: expected {}, got {}",
                    expected_height, block.header.height
                ),
            });
        }

        // Validate timestamp (should be reasonable)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Block timestamp should not be more than 2 hours in the future
        if block.header.timestamp > now + 7200 {
            return Err(ValidationError::InvalidTimestamp {
                timestamp: block.header.timestamp,
            });
        }

        // Block timestamp should not be zero
        if block.header.timestamp == 0 {
            return Err(ValidationError::InvalidTimestamp {
                timestamp: 0,
            });
        }

        // Validate difficulty (basic check - should be non-zero)
        if block.header.difficulty == 0 {
            return Err(ValidationError::InvalidDifficulty {
                expected: 1,
                got: 0,
            });
        }

        Ok(())
    }

    /// Validate all cryptographic proofs in a block.
    fn validate_block_proofs(
        &self,
        block: &Block,
        state: &ShieldedState,
        verifying_params: &CircomVerifyingParams,
    ) -> Result<(), ValidationError> {
        // Validate coinbase (no proofs to verify)
        if let Some(coinbase) = &block.coinbase {
            state.validate_coinbase(coinbase, coinbase.reward, block.header.height)?;
        }

        // Validate all shielded transactions with full proof verification
        for tx in &block.transactions {
            state.validate_transaction(tx, verifying_params)?;
        }

        Ok(())
    }

    /// Validate a single transaction against the current state.
    pub fn validate_transaction(
        &mut self,
        tx: &ShieldedTransaction,
        state: &ShieldedState,
        verifying_params: Option<&CircomVerifyingParams>,
    ) -> Result<(), ValidationError> {
        // 1. Balance and state validation
        self.balance_validator.validate_shielded_transaction(tx, state)?;

        // 2. Cryptographic proof verification (if enabled)
        if self.verify_proofs {
            if let Some(params) = verifying_params {
                state.validate_transaction(tx, params)?;
            } else {
                return Err(ValidationError::ProofVerification);
            }
        } else {
            // Basic validation without proofs
            state.validate_transaction_basic(tx)?;
        }

        Ok(())
    }

    /// Validate a coinbase transaction.
    pub fn validate_coinbase(
        &mut self,
        coinbase: &CoinbaseTransaction,
        state: &ShieldedState,
        expected_height: u64,
        expected_reward: u64,
    ) -> Result<(), ValidationError> {
        // Validate reward amount
        if coinbase.reward != expected_reward {
            return Err(ValidationError::TransactionValidation {
                reason: format!(
                    "Invalid coinbase reward: expected {}, got {}",
                    expected_reward, coinbase.reward
                ),
            });
        }

        // Use balance validator
        self.balance_validator.validate_coinbase(coinbase, state, expected_height)?;

        Ok(())
    }

    /// Apply a validated block to update internal validator state.
    ///
    /// This should only be called after successful validation.
    pub fn apply_block(
        &mut self,
        block: &Block,
        state: &mut ShieldedState,
    ) -> Result<(), ValidationError> {
        // Apply coinbase
        if let Some(coinbase) = &block.coinbase {
            self.balance_validator.apply_coinbase(coinbase, state)?;
        }

        // Apply all transactions
        for tx in &block.transactions {
            self.balance_validator.apply_shielded_transaction(tx, state)?;
        }

        Ok(())
    }

    /// Validate state consistency invariants.
    ///
    /// This performs deep validation to ensure the state is internally consistent.
    pub fn validate_state_invariants(
        &self,
        state: &ShieldedState,
    ) -> Result<(), ValidationError> {
        self.balance_validator.validate_state_invariants(state)?;
        Ok(())
    }

    /// Reset validator state (for testing or reorg handling).
    pub fn reset(&mut self) {
        self.balance_validator.reset();
    }

    /// Get current estimated supply.
    pub fn estimated_supply(&self) -> u64 {
        self.balance_validator.estimated_supply()
    }

    /// Set estimated supply (for initialization).
    pub fn set_estimated_supply(&mut self, supply: u64) {
        self.balance_validator.set_estimated_supply(supply);
    }
}

// Legacy functions for backward compatibility
// TODO: These should be deprecated in favor of the new Validator struct

/// Validate a block using the legacy interface.
///
/// # Deprecated
/// Use `Validator::validate_block` instead.
pub fn validate_block(block: &Block, state: &ShieldedState) -> Result<(), TsnError> {
    let mut validator = Validator::for_testing(); // Disable proofs for legacy compatibility
    
    validator.validate_block(block, state, block.header.height, None)
        .map_err(|e| TsnError::ValidationError(e.to_string()))
}

/// Validate a transaction using the legacy interface.
///
/// # Deprecated
/// Use `Validator::validate_transaction` instead.
pub fn validate_transaction(tx: &Transaction) -> Result<(), TsnError> {
    // This is a placeholder for the legacy interface
    // In practice, we need more context (state, verifying params) for proper validation
    match tx {
        Transaction::Shielded(_) => {
            // Cannot properly validate without state context
            tracing::warn!("Legacy transaction validation called - use Validator::validate_transaction instead");
            Ok(())
        }
        Transaction::Coinbase(_) => {
            // Cannot properly validate without state context
            tracing::warn!("Legacy coinbase validation called - use Validator::validate_coinbase instead");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::state::ShieldedState;
    use crate::crypto::{
        commitment::NoteCommitment,
        nullifier::Nullifier,
    };

    #[test]
    fn test_validator_creation() {
        let validator = Validator::new();
        assert!(validator.verify_proofs);
        assert_eq!(validator.estimated_supply(), 0);
    }

    #[test]
    fn test_validator_for_testing() {
        let validator = Validator::for_testing();
        assert!(!validator.verify_proofs);
    }

    #[test]
    fn test_proof_verification_toggle() {
        let mut validator = Validator::new();
        assert!(validator.verify_proofs);
        
        validator.set_proof_verification(false);
        assert!(!validator.verify_proofs);
        
        validator.set_proof_verification(true);
        assert!(validator.verify_proofs);
    }

    #[test]
    fn test_state_invariants_validation() {
        let validator = Validator::new();
        let state = ShieldedState::new();

        let result = validator.validate_state_invariants(&state);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_timestamp_validation() {
        let validator = Validator::new();
        
        // Create a block with timestamp far in the future
        let future_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + 10000; // 10000 seconds in the future

        let mut block = Block::default();
        block.header.timestamp = future_time;
        block.header.height = 1;

        let result = validator.validate_block_header(&block, 1);
        assert!(matches!(
            result,
            Err(ValidationError::InvalidTimestamp { .. })
        ));
    }

    #[test]
    fn test_invalid_difficulty_validation() {
        let validator = Validator::new();
        
        let mut block = Block::default();
        block.header.difficulty = 0; // Invalid
        block.header.height = 1;
        block.header.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let result = validator.validate_block_header(&block, 1);
        assert!(matches!(
            result,
            Err(ValidationError::InvalidDifficulty { expected: 1, got: 0 })
        ));
    }

    #[test]
    fn test_validator_reset() {
        let mut validator = Validator::new();
        validator.set_estimated_supply(1000);
        assert_eq!(validator.estimated_supply(), 1000);
        
        validator.reset();
        assert_eq!(validator.estimated_supply(), 0);
    }

    #[test]
    fn test_custom_limits() {
        let validator = Validator::with_limits(1000, 5000);
        // The limits are internal to the balance validator
        // We can't directly test them here, but they're tested in balance_validation tests
        assert_eq!(validator.estimated_supply(), 0);
    }
}