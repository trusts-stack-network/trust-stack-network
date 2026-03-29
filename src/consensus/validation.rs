//! Validation logic for blocks and transactions
//! 
//! This module contains the core validation rules for TSN, including
//! signature verification using SLH-DSA (FIPS 205) post-quantum signatures
//! and comprehensive timestamp validation to prevent temporal attacks.
//!
//! # Timestamp Validation Rules
//! 1. Block timestamp must be after parent block timestamp
//! 2. Block timestamp cannot be more than 2 hours old (prevents stale blocks)
//! 3. Block timestamp cannot be more than 15 minutes in the future (prevents time drift attacks)
//! 4. Timestamp must be consistent with difficulty adjustment expectations
//!
//! # Security Notes
//! - All time operations use checked arithmetic to prevent panics
//! - No unwrap() or expect() in validation hot paths
//! - All signature operations return Result instead of panicking
//! - Temporal attack prevention through strict timestamp bounds

use crate::core::{Block, Transaction, BlockHeader};
use crate::crypto::hash::Hash;
use crate::crypto::signature::{SignatureScheme, SignatureError};
use crate::crypto::pq::slh_dsa::{SlhDsaVerifier, SlhDsaSignature, SLH_DSA_SHA2_128S};
use crate::consensus::difficulty::{TARGET_BLOCK_TIME_SECS, should_adjust_difficulty};
use crate::state::StateView;
use std::time::{SystemTime, UNIX_EPOCH, SystemTimeError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid block signature")]
    InvalidBlockSignature,
    #[error("Invalid transaction signature")]
    InvalidTransactionSignature,
    #[error("Block timestamp is too far in the future (max 15 minutes)")]
    TimestampTooFarInFuture,
    #[error("Block timestamp is too old (max 2 hours)")]
    TimestampTooOld,
    #[error("Block timestamp is before parent block")]
    TimestampBeforeParent,
    #[error("Block timestamp violates minimum interval")]
    TimestampTooSoon,
    #[error("Invalid proof of work")]
    InvalidProofOfWork,
    #[error("Merkle root mismatch")]
    MerkleRootMismatch,
    #[error("State root mismatch")]
    StateRootMismatch,
    #[error("Signature verification error: {0}")]
    SignatureVerification(#[from] SignatureError),
    #[error("System time error: {0}")]
    SystemTimeError(#[from] SystemTimeError),
    #[error("Timestamp overflow")]
    TimestampOverflow,
    #[error("Invalid block height")]
    InvalidBlockHeight,
}

/// Maximum allowed time drift in the future (2 minutes).
/// M3 audit fix: reduced from 15min to 2min — 15min was 90x the 10s block time.
const MAX_FUTURE_TIME_DRIFT: u64 = 2 * 60; // 2 minutes in seconds

/// Maximum allowed age for a block (2 hours)
const MAX_BLOCK_AGE: u64 = 2 * 60 * 60; // 2 hours in seconds

/// Minimum time between blocks (prevents spam)
/// Set to 1/10th of target time to allow some variance
const MIN_BLOCK_INTERVAL: u64 = TARGET_BLOCK_TIME_SECS / 10;

/// Validator for blocks and transactions
pub struct Validator {
    slh_dsa_verifier: SlhDsaVerifier,
}

impl Validator {
    pub fn new() -> Self {
        Self {
            slh_dsa_verifier: SlhDsaVerifier::new(SLH_DSA_SHA2_128S),
        }
    }

    /// Validate a complete block including all transactions
    pub fn validate_block(&self, block: &Block, parent_header: Option<&BlockHeader>, state_view: &dyn StateView) -> Result<(), ValidationError> {
        // Validate block header (includes timestamp validation)
        self.validate_block_header(&block.header, parent_header)?;

        // Validate all transactions
        for tx in &block.transactions {
            self.validate_transaction(tx)?;
        }

        // Verify merkle root
        let computed_merkle_root = block.compute_merkle_root();
        if computed_merkle_root != block.header.merkle_root {
            return Err(ValidationError::MerkleRootMismatch);
        }

        // Verify state root
        let computed_state_root = state_view.compute_state_root(&block.transactions)?;
        if computed_state_root != block.header.state_root {
            return Err(ValidationError::StateRootMismatch);
        }

        Ok(())
    }

    /// Validate block header with comprehensive timestamp checks
    fn validate_block_header(&self, header: &BlockHeader, parent_header: Option<&BlockHeader>) -> Result<(), ValidationError> {
        // Validate timestamp against current time
        self.validate_timestamp_bounds(header.timestamp)?;

        // Validate timestamp against parent block
        if let Some(parent) = parent_header {
            self.validate_timestamp_ordering(header, parent)?;
        }

        // Validate proof of work
        if !header.verify_proof_of_work() {
            return Err(ValidationError::InvalidProofOfWork);
        }

        // Validate block signature using SLH-DSA
        self.validate_block_signature(header)?;

        Ok(())
    }

    /// Validate timestamp bounds against current time
    /// 
    /// # Security Invariants
    /// - Block cannot be more than 15 minutes in the future (prevents time drift attacks)
    /// - Block cannot be more than 2 hours old (prevents stale block attacks)
    /// - All arithmetic is checked to prevent overflow panics
    fn validate_timestamp_bounds(&self, block_timestamp: u64) -> Result<(), ValidationError> {
        // Get current time - SECURE: proper error handling, no unwrap()
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(ValidationError::SystemTimeError)?
            .as_secs();

        // Check if block is too far in the future
        // SECURE: checked_add to prevent overflow
        let max_allowed_future_time = current_time
            .checked_add(MAX_FUTURE_TIME_DRIFT)
            .ok_or(ValidationError::TimestampOverflow)?;

        if block_timestamp > max_allowed_future_time {
            return Err(ValidationError::TimestampTooFarInFuture);
        }

        // Check if block is too old
        // SECURE: checked_sub to prevent underflow
        let min_allowed_time = current_time
            .checked_sub(MAX_BLOCK_AGE)
            .unwrap_or(0); // If current_time < MAX_BLOCK_AGE, accept any timestamp

        if block_timestamp < min_allowed_time {
            return Err(ValidationError::TimestampTooOld);
        }

        Ok(())
    }

    /// Validate timestamp ordering relative to parent block
    /// 
    /// # Security Invariants
    /// - Block timestamp must be strictly after parent timestamp
    /// - Block timestamp must respect minimum interval to prevent spam
    /// - Timestamp progression must be reasonable for difficulty adjustment
    fn validate_timestamp_ordering(&self, header: &BlockHeader, parent: &BlockHeader) -> Result<(), ValidationError> {
        // Block must come after parent
        if header.timestamp <= parent.timestamp {
            return Err(ValidationError::TimestampBeforeParent);
        }

        // Enforce minimum interval between blocks to prevent spam
        // SECURE: checked_add to prevent overflow
        let min_allowed_timestamp = parent.timestamp
            .checked_add(MIN_BLOCK_INTERVAL)
            .ok_or(ValidationError::TimestampOverflow)?;

        if header.timestamp < min_allowed_timestamp {
            return Err(ValidationError::TimestampTooSoon);
        }

        // Additional validation for difficulty adjustment periods
        if should_adjust_difficulty(header.height) {
            self.validate_difficulty_adjustment_timestamp(header, parent)?;
        }

        Ok(())
    }

    /// Validate timestamp during difficulty adjustment periods
    /// 
    /// Ensures that timestamp progression is reasonable and not manipulated
    /// to game the difficulty adjustment algorithm.
    fn validate_difficulty_adjustment_timestamp(&self, header: &BlockHeader, parent: &BlockHeader) -> Result<(), ValidationError> {
        let time_diff = header.timestamp.saturating_sub(parent.timestamp);
        
        // Ensure timestamp progression is reasonable (anti-manipulation).
        // Allow up to 60× target (600s = 10 min) — generous enough for hashrate drops
        // while still preventing extreme timestamp gaming for difficulty manipulation.
        let max_reasonable_interval = TARGET_BLOCK_TIME_SECS
            .checked_mul(60)
            .ok_or(ValidationError::TimestampOverflow)?;

        if time_diff > max_reasonable_interval {
            // This could indicate timestamp manipulation
            return Err(ValidationError::TimestampTooOld);
        }

        Ok(())
    }

    /// Validate block signature using SLH-DSA
    fn validate_block_signature(&self, header: &BlockHeader) -> Result<(), ValidationError> {
        let message = header.signature_message();
        
        let signature = SlhDsaSignature::from_bytes(&header.signature)
            .map_err(|_| ValidationError::InvalidBlockSignature)?;

        self.slh_dsa_verifier
            .verify(&header.producer_public_key, &message, &signature)
            .map_err(|e| match e {
                SignatureError::InvalidSignature => ValidationError::InvalidBlockSignature,
                other => ValidationError::SignatureVerification(other),
            })?;

        Ok(())
    }

    /// Validate individual transaction
    pub fn validate_transaction(&self, tx: &Transaction) -> Result<(), ValidationError> {
        // Basic transaction validation
        if tx.inputs.is_empty() || tx.outputs.is_empty() {
            return Err(ValidationError::InvalidTransactionSignature);
        }

        // Validate transaction signature using SLH-DSA
        self.validate_transaction_signature(tx)?;

        // Additional validation rules would go here
        // - Input/output balance validation
        // - Double spend prevention
        // - Script validation if applicable

        Ok(())
    }

    /// Validate transaction signature using SLH-DSA
    fn validate_transaction_signature(&self, tx: &Transaction) -> Result<(), ValidationError> {
        let message = tx.signature_message();
        
        let signature = SlhDsaSignature::from_bytes(&tx.signature)
            .map_err(|_| ValidationError::InvalidTransactionSignature)?;

        self.slh_dsa_verifier
            .verify(&tx.sender_public_key, &message, &signature)
            .map_err(|e| match e {
                SignatureError::InvalidSignature => ValidationError::InvalidTransactionSignature,
                other => ValidationError::SignatureVerification(other),
            })?;

        Ok(())
    }

    /// Get timestamp validation constants for external use
    pub fn get_timestamp_constants() -> TimestampConstants {
        TimestampConstants {
            max_future_drift: MAX_FUTURE_TIME_DRIFT,
            max_block_age: MAX_BLOCK_AGE,
            min_block_interval: MIN_BLOCK_INTERVAL,
            target_block_time: TARGET_BLOCK_TIME_SECS,
        }
    }
}

impl Default for Validator {
    fn default() -> Self {
        Self::new()
    }
}

/// Timestamp validation constants for external reference
#[derive(Debug, Clone, Copy)]
pub struct TimestampConstants {
    pub max_future_drift: u64,
    pub max_block_age: u64,
    pub min_block_interval: u64,
    pub target_block_time: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn test_timestamp_bounds_validation() {
        let validator = Validator::new();
        let current_time = current_timestamp();

        // Valid timestamp (current time)
        assert!(validator.validate_timestamp_bounds(current_time).is_ok());

        // Valid timestamp (5 minutes in future)
        let future_valid = current_time + 5 * 60;
        assert!(validator.validate_timestamp_bounds(future_valid).is_ok());

        // Invalid timestamp (too far in future)
        let future_invalid = current_time + MAX_FUTURE_TIME_DRIFT + 1;
        assert!(matches!(
            validator.validate_timestamp_bounds(future_invalid),
            Err(ValidationError::TimestampTooFarInFuture)
        ));

        // Valid timestamp (1 hour old)
        let past_valid = current_time - 60 * 60;
        assert!(validator.validate_timestamp_bounds(past_valid).is_ok());

        // Invalid timestamp (too old)
        let past_invalid = current_time - MAX_BLOCK_AGE - 1;
        assert!(matches!(
            validator.validate_timestamp_bounds(past_invalid),
            Err(ValidationError::TimestampTooOld)
        ));
    }

    #[test]
    fn test_timestamp_ordering_validation() {
        let validator = Validator::new();
        let base_time = current_timestamp();

        // Create mock headers
        let parent_header = BlockHeader {
            height: 100,
            timestamp: base_time,
            previous_hash: Hash::default(),
            merkle_root: Hash::default(),
            state_root: Hash::default(),
            difficulty: 16,
            nonce: 0,
            signature: vec![],
            producer_public_key: vec![],
        };

        let valid_child = BlockHeader {
            height: 101,
            timestamp: base_time + TARGET_BLOCK_TIME_SECS,
            previous_hash: Hash::default(),
            merkle_root: Hash::default(),
            state_root: Hash::default(),
            difficulty: 16,
            nonce: 0,
            signature: vec![],
            producer_public_key: vec![],
        };

        // Valid ordering
        assert!(validator.validate_timestamp_ordering(&valid_child, &parent_header).is_ok());

        // Invalid: same timestamp
        let invalid_same = BlockHeader {
            timestamp: base_time,
            ..valid_child.clone()
        };
        assert!(matches!(
            validator.validate_timestamp_ordering(&invalid_same, &parent_header),
            Err(ValidationError::TimestampBeforeParent)
        ));

        // Invalid: before parent
        let invalid_before = BlockHeader {
            timestamp: base_time - 1,
            ..valid_child.clone()
        };
        assert!(matches!(
            validator.validate_timestamp_ordering(&invalid_before, &parent_header),
            Err(ValidationError::TimestampBeforeParent)
        ));

        // Invalid: too soon after parent
        let invalid_too_soon = BlockHeader {
            timestamp: base_time + MIN_BLOCK_INTERVAL - 1,
            ..valid_child.clone()
        };
        assert!(matches!(
            validator.validate_timestamp_ordering(&invalid_too_soon, &parent_header),
            Err(ValidationError::TimestampTooSoon)
        ));
    }

    #[test]
    fn test_difficulty_adjustment_timestamp_validation() {
        let validator = Validator::new();
        let base_time = current_timestamp();

        let parent_header = BlockHeader {
            height: 9, // Next block will trigger difficulty adjustment
            timestamp: base_time,
            previous_hash: Hash::default(),
            merkle_root: Hash::default(),
            state_root: Hash::default(),
            difficulty: 16,
            nonce: 0,
            signature: vec![],
            producer_public_key: vec![],
        };

        // Valid difficulty adjustment block
        let valid_adjustment = BlockHeader {
            height: 10, // Triggers difficulty adjustment
            timestamp: base_time + TARGET_BLOCK_TIME_SECS,
            previous_hash: Hash::default(),
            merkle_root: Hash::default(),
            state_root: Hash::default(),
            difficulty: 16,
            nonce: 0,
            signature: vec![],
            producer_public_key: vec![],
        };

        assert!(validator.validate_difficulty_adjustment_timestamp(&valid_adjustment, &parent_header).is_ok());

        // Invalid: timestamp gap too large (potential manipulation)
        let invalid_large_gap = BlockHeader {
            timestamp: base_time + TARGET_BLOCK_TIME_SECS * 11, // More than 10x target
            ..valid_adjustment.clone()
        };
        assert!(matches!(
            validator.validate_difficulty_adjustment_timestamp(&invalid_large_gap, &parent_header),
            Err(ValidationError::TimestampTooOld)
        ));
    }

    #[test]
    fn test_timestamp_constants() {
        let constants = Validator::get_timestamp_constants();
        
        assert_eq!(constants.max_future_drift, 15 * 60);
        assert_eq!(constants.max_block_age, 2 * 60 * 60);
        assert_eq!(constants.min_block_interval, TARGET_BLOCK_TIME_SECS / 10);
        assert_eq!(constants.target_block_time, TARGET_BLOCK_TIME_SECS);
    }

    #[test]
    fn test_no_panic_on_timestamp_overflow() {
        let validator = Validator::new();
        
        // Test that overflow conditions return errors instead of panicking
        let max_timestamp = u64::MAX;
        
        // This should handle overflow gracefully
        let result = validator.validate_timestamp_bounds(max_timestamp);
        assert!(result.is_err());
    }

    #[test]
    fn test_timestamp_validation_edge_cases() {
        let validator = Validator::new();
        let current_time = current_timestamp();

        // Edge case: exactly at the boundary
        let exactly_max_future = current_time + MAX_FUTURE_TIME_DRIFT;
        assert!(validator.validate_timestamp_bounds(exactly_max_future).is_ok());

        let exactly_max_past = current_time - MAX_BLOCK_AGE;
        assert!(validator.validate_timestamp_bounds(exactly_max_past).is_ok());

        // Edge case: one second over the boundary
        let one_second_over_future = current_time + MAX_FUTURE_TIME_DRIFT + 1;
        assert!(matches!(
            validator.validate_timestamp_bounds(one_second_over_future),
            Err(ValidationError::TimestampTooFarInFuture)
        ));

        let one_second_over_past = current_time - MAX_BLOCK_AGE - 1;
        assert!(matches!(
            validator.validate_timestamp_bounds(one_second_over_past),
            Err(ValidationError::TimestampTooOld)
        ));
    }
}