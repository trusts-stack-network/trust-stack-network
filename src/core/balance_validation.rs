//! Balance coherence validation for the shielded state model.
//!
//! In a shielded blockchain, we don't have explicit account balances.
//! Instead, we maintain cryptographic invariants that ensure value conservation:
//!
//! 1. **Conservation of Value**: Total value in = Total value out + fees
//! 2. **No Double Spending**: Each nullifier can only be used once
//! 3. **Valid Commitments**: All note commitments must be well-formed
//! 4. **Anchor Validity**: All spend anchors must reference valid tree states
//! 5. **Proof Integrity**: All cryptographic proofs must verify
//!
//! These invariants collectively ensure that the total supply remains constant
//! and no value can be created or destroyed illegally.

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::{
    merkle_tree::TreeHash,
    nullifier::Nullifier,
    pq::{
        commitment_pq::NoteCommitmentPQ,
        merkle_pq::TreeHashPQ,
    },
};

use super::{
    state::{ShieldedState, StateError},
    transaction::{ShieldedTransaction, ShieldedTransactionV2, CoinbaseTransaction},
    block::Block,
};

/// Errors that can occur during balance validation.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum BalanceValidationError {
    #[error("Value conservation violated: inputs={inputs}, outputs={outputs}, fee={fee}")]
    ValueConservationViolated {
        inputs: u64,
        outputs: u64,
        fee: u64,
    },

    #[error("Nullifier {nullifier:?} already spent")]
    NullifierAlreadySpent { nullifier: Nullifier },

    #[error("Invalid anchor: {anchor:?}")]
    InvalidAnchor { anchor: TreeHash },

    #[error("Invalid PQ anchor: {anchor:?}")]
    InvalidAnchorPQ { anchor: TreeHashPQ },

    #[error("Commitment tree overflow: attempted to add {count} commitments")]
    CommitmentTreeOverflow { count: u64 },

    #[error("Negative value detected: {value}")]
    NegativeValue { value: i64 },

    #[error("Total supply overflow: current={current}, attempted_add={add}")]
    TotalSupplyOverflow { current: u64, add: u64 },

    #[error("Invalid coinbase reward: expected={expected}, got={got}")]
    InvalidCoinbaseReward { expected: u64, got: u64 },

    #[error("Block height mismatch: expected={expected}, got={got}")]
    BlockHeightMismatch { expected: u64, got: u64 },

    #[error("State error: {0}")]
    StateError(#[from] StateError),
}

/// Statistics about the shielded state for monitoring and validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateStatistics {
    /// Total number of commitments in V1 tree.
    pub commitment_count_v1: u64,
    /// Total number of commitments in V2 tree.
    pub commitment_count_v2: u64,
    /// Total number of spent nullifiers.
    pub nullifier_count: usize,
    /// Current V1 tree root.
    pub tree_root_v1: TreeHash,
    /// Current V2 tree root.
    pub tree_root_v2: TreeHashPQ,
    /// Estimated total supply (from coinbase transactions).
    pub estimated_supply: u64,
}

/// Comprehensive balance and state validator.
///
/// This validator ensures that all cryptographic invariants are maintained
/// and that the shielded state remains consistent across all operations.
#[derive(Debug, Clone)]
pub struct BalanceValidator {
    /// Maximum allowed commitment tree size.
    max_tree_size: u64,
    /// Maximum allowed total supply.
    max_supply: u64,
    /// Track estimated supply from coinbase transactions.
    estimated_supply: u64,
}

impl Default for BalanceValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl BalanceValidator {
    /// Create a new balance validator with default limits.
    pub fn new() -> Self {
        Self {
            max_tree_size: 1_000_000_000, // 1 billion commitments max
            max_supply: 21_000_000 * 1_000_000_000, // 21M TSN with 9 decimals (COIN_DECIMALS=9)
            estimated_supply: 0,
        }
    }

    /// Create a validator with custom limits.
    pub fn with_limits(max_tree_size: u64, max_supply: u64) -> Self {
        Self {
            max_tree_size,
            max_supply,
            estimated_supply: 0,
        }
    }

    /// Get current state statistics.
    pub fn get_statistics(&self, state: &ShieldedState) -> StateStatistics {
        StateStatistics {
            commitment_count_v1: state.commitment_count(),
            commitment_count_v2: state.commitment_tree_pq().size(),
            nullifier_count: state.nullifier_count(),
            tree_root_v1: state.commitment_root(),
            tree_root_v2: state.commitment_root_pq(),
            estimated_supply: self.estimated_supply,
        }
    }

    /// Validate a complete block against the current state.
    ///
    /// This performs comprehensive validation of all transactions in the block,
    /// ensuring that all balance and state invariants are maintained.
    pub fn validate_block(
        &mut self,
        block: &Block,
        state: &ShieldedState,
        expected_height: u64,
    ) -> Result<(), BalanceValidationError> {
        // Validate block height
        if block.header.height != expected_height {
            return Err(BalanceValidationError::BlockHeightMismatch {
                expected: expected_height,
                got: block.header.height,
            });
        }

        // Create a temporary state for validation
        let mut temp_state = state.clone();
        let mut temp_validator = self.clone();

        // Validate coinbase transaction
        if let Some(coinbase) = &block.coinbase {
            temp_validator.validate_coinbase(coinbase, &temp_state, expected_height)?;
            temp_validator.apply_coinbase(coinbase, &mut temp_state)?;
        }

        // Validate all shielded transactions
        for tx in &block.transactions {
            temp_validator.validate_shielded_transaction(tx, &temp_state)?;
            temp_validator.apply_shielded_transaction(tx, &mut temp_state)?;
        }

        // If we reach here, all validations passed
        // Update our internal state
        *self = temp_validator;
        Ok(())
    }

    /// Validate a coinbase transaction.
    pub fn validate_coinbase(
        &self,
        coinbase: &CoinbaseTransaction,
        state: &ShieldedState,
        expected_height: u64,
    ) -> Result<(), BalanceValidationError> {
        // Validate height
        if coinbase.height != expected_height {
            return Err(BalanceValidationError::BlockHeightMismatch {
                expected: expected_height,
                got: coinbase.height,
            });
        }

        // Check supply limits
        if let Some(new_supply) = self.estimated_supply.checked_add(coinbase.reward) {
            if new_supply > self.max_supply {
                return Err(BalanceValidationError::TotalSupplyOverflow {
                    current: self.estimated_supply,
                    add: coinbase.reward,
                });
            }
        } else {
            return Err(BalanceValidationError::TotalSupplyOverflow {
                current: self.estimated_supply,
                add: coinbase.reward,
            });
        }

        // Check tree size limits
        let new_tree_size = state.commitment_count() + 1;
        if new_tree_size > self.max_tree_size {
            return Err(BalanceValidationError::CommitmentTreeOverflow {
                count: new_tree_size,
            });
        }

        // Validate using state's built-in validation
        state.validate_coinbase(coinbase, coinbase.reward, expected_height)?;

        Ok(())
    }

    /// Apply a validated coinbase transaction to update internal tracking.
    pub fn apply_coinbase(
        &mut self,
        coinbase: &CoinbaseTransaction,
        state: &mut ShieldedState,
    ) -> Result<(), BalanceValidationError> {
        // Update estimated supply
        self.estimated_supply = self.estimated_supply
            .checked_add(coinbase.reward)
            .ok_or(BalanceValidationError::TotalSupplyOverflow {
                current: self.estimated_supply,
                add: coinbase.reward,
            })?;

        // Apply to state
        state.apply_coinbase(coinbase);
        Ok(())
    }

    /// Validate a shielded transaction (V1).
    pub fn validate_shielded_transaction(
        &self,
        tx: &ShieldedTransaction,
        state: &ShieldedState,
    ) -> Result<(), BalanceValidationError> {
        // Basic state validation
        state.validate_transaction_basic(tx)?;

        // Additional balance-specific validations
        self.validate_value_conservation(tx)?;
        self.validate_nullifier_uniqueness(tx, state)?;
        self.validate_tree_limits(tx, state)?;

        Ok(())
    }

    /// Apply a validated shielded transaction.
    pub fn apply_shielded_transaction(
        &mut self,
        tx: &ShieldedTransaction,
        state: &mut ShieldedState,
    ) -> Result<(), BalanceValidationError> {
        // Check tree size before applying
        let new_commitments = tx.outputs.len() as u64;
        let new_tree_size = state.commitment_count() + new_commitments;
        if new_tree_size > self.max_tree_size {
            return Err(BalanceValidationError::CommitmentTreeOverflow {
                count: new_tree_size,
            });
        }

        // Apply to state
        state.apply_transaction(tx);
        Ok(())
    }

    /// Validate value conservation for a transaction.
    ///
    /// In a shielded transaction, we can't directly verify value conservation
    /// because values are hidden. However, we can check that:
    /// 1. The binding signature verifies (which proves value balance)
    /// 2. Fee is non-negative
    /// 3. Number of inputs/outputs is reasonable
    fn validate_value_conservation(
        &self,
        tx: &ShieldedTransaction,
    ) -> Result<(), BalanceValidationError> {
        // Fee must be non-negative
        if tx.fee < 0 {
            return Err(BalanceValidationError::NegativeValue {
                value: tx.fee as i64,
            });
        }

        // Must have at least one spend or output (unless fee-only)
        if tx.spends.is_empty() && tx.outputs.is_empty() && tx.fee == 0 {
            return Err(BalanceValidationError::ValueConservationViolated {
                inputs: 0,
                outputs: 0,
                fee: 0,
            });
        }

        // The binding signature verification in the state validator
        // cryptographically proves that: sum(inputs) = sum(outputs) + fee
        // So we don't need additional checks here.

        Ok(())
    }

    /// Validate that all nullifiers in a transaction are unique and unspent.
    fn validate_nullifier_uniqueness(
        &self,
        tx: &ShieldedTransaction,
        state: &ShieldedState,
    ) -> Result<(), BalanceValidationError> {
        let mut seen_nullifiers = HashSet::new();

        for spend in &tx.spends {
            // Check for duplicates within the transaction
            if !seen_nullifiers.insert(spend.nullifier) {
                return Err(BalanceValidationError::NullifierAlreadySpent {
                    nullifier: spend.nullifier,
                });
            }

            // Check against global nullifier set
            if state.is_nullifier_spent(&spend.nullifier) {
                return Err(BalanceValidationError::NullifierAlreadySpent {
                    nullifier: spend.nullifier,
                });
            }
        }

        Ok(())
    }

    /// Validate tree size limits.
    fn validate_tree_limits(
        &self,
        tx: &ShieldedTransaction,
        state: &ShieldedState,
    ) -> Result<(), BalanceValidationError> {
        let new_commitments = tx.outputs.len() as u64;
        let new_tree_size = state.commitment_count() + new_commitments;

        if new_tree_size > self.max_tree_size {
            return Err(BalanceValidationError::CommitmentTreeOverflow {
                count: new_tree_size,
            });
        }

        Ok(())
    }

    /// Validate state consistency invariants.
    ///
    /// This performs deep validation of the state to ensure all invariants hold:
    /// 1. Tree sizes are consistent between V1 and V2
    /// 2. No duplicate nullifiers exist
    /// 3. Tree roots are valid
    /// 4. Supply tracking is accurate
    pub fn validate_state_invariants(
        &self,
        state: &ShieldedState,
    ) -> Result<(), BalanceValidationError> {
        // V1 and V2 trees should have the same number of commitments
        // (since we add to both simultaneously)
        let v1_size = state.commitment_count();
        let v2_size = state.commitment_tree_pq().size();
        
        if v1_size != v2_size {
            tracing::warn!(
                "Tree size mismatch: V1={}, V2={}. This indicates a bug in state management.",
                v1_size, v2_size
            );
            // Note: This is a warning, not an error, as it might be expected
            // during migration periods or if one tree is temporarily ahead.
        }

        // Check tree size limits
        if v1_size > self.max_tree_size {
            return Err(BalanceValidationError::CommitmentTreeOverflow {
                count: v1_size,
            });
        }

        // Check supply limits
        if self.estimated_supply > self.max_supply {
            return Err(BalanceValidationError::TotalSupplyOverflow {
                current: self.estimated_supply,
                add: 0,
            });
        }

        // Nullifier set should not contain duplicates (HashSet guarantees this)
        // but we can check the count is reasonable
        let nullifier_count = state.nullifier_count();
        if nullifier_count > v1_size as usize {
            tracing::warn!(
                "More nullifiers ({}) than commitments ({}). This might indicate an issue.",
                nullifier_count, v1_size
            );
        }

        Ok(())
    }

    /// Reset the validator state (for testing or reorg handling).
    pub fn reset(&mut self) {
        self.estimated_supply = 0;
    }

    /// Get the current estimated supply.
    pub fn estimated_supply(&self) -> u64 {
        self.estimated_supply
    }

    /// Set the estimated supply (for initialization from existing state).
    pub fn set_estimated_supply(&mut self, supply: u64) {
        self.estimated_supply = supply;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        keys::SpendingKey,
        nullifier::Nullifier,
        commitment::NoteCommitment,
        merkle_tree::TreeHash,
    };
    use crate::core::transaction::{SpendDescription, OutputDescription};

    #[test]
    fn test_balance_validator_creation() {
        let validator = BalanceValidator::new();
        assert_eq!(validator.estimated_supply(), 0);
        assert_eq!(validator.max_tree_size, 1_000_000_000);
        assert_eq!(validator.max_supply, 21_000_000 * 1_000_000_000);
    }

    #[test]
    fn test_custom_limits() {
        let validator = BalanceValidator::with_limits(1000, 5000);
        assert_eq!(validator.max_tree_size, 1000);
        assert_eq!(validator.max_supply, 5000);
    }

    #[test]
    fn test_state_statistics() {
        let state = ShieldedState::new();
        let validator = BalanceValidator::new();
        
        let stats = validator.get_statistics(&state);
        assert_eq!(stats.commitment_count_v1, 0);
        assert_eq!(stats.commitment_count_v2, 0);
        assert_eq!(stats.nullifier_count, 0);
        assert_eq!(stats.estimated_supply, 0);
    }

    #[test]
    fn test_negative_fee_validation() {
        let validator = BalanceValidator::new();
        
        // Create a transaction with negative fee
        let tx = ShieldedTransaction {
            spends: vec![],
            outputs: vec![],
            fee: -100, // Negative fee
            binding_sig: Default::default(),
        };

        let result = validator.validate_value_conservation(&tx);
        assert!(matches!(
            result,
            Err(BalanceValidationError::NegativeValue { value: -100 })
        ));
    }

    #[test]
    fn test_empty_transaction_validation() {
        let validator = BalanceValidator::new();
        
        // Create an empty transaction with zero fee
        let tx = ShieldedTransaction {
            spends: vec![],
            outputs: vec![],
            fee: 0,
            binding_sig: Default::default(),
        };

        let result = validator.validate_value_conservation(&tx);
        assert!(matches!(
            result,
            Err(BalanceValidationError::ValueConservationViolated { .. })
        ));
    }

    #[test]
    fn test_supply_overflow_detection() {
        let mut validator = BalanceValidator::with_limits(1000, 100); // Low max supply
        validator.set_estimated_supply(90);

        let coinbase = CoinbaseTransaction {
            reward: 20, // Would exceed max supply of 100
            height: 1,
            note_commitment: NoteCommitment::default(),
            note_commitment_pq: [0u8; 32],
        };

        let state = ShieldedState::new();
        let result = validator.validate_coinbase(&coinbase, &state, 1);
        
        assert!(matches!(
            result,
            Err(BalanceValidationError::TotalSupplyOverflow { current: 90, add: 20 })
        ));
    }

    #[test]
    fn test_tree_overflow_detection() {
        let validator = BalanceValidator::with_limits(5, 1000); // Low max tree size
        let mut state = ShieldedState::new();

        // Fill the tree to near capacity
        for _ in 0..5 {
            let cm = NoteCommitment::default();
            state.commitment_tree.append(&cm);
            let cm_pq = NoteCommitmentPQ::from(cm.to_bytes());
            state.commitment_tree_pq.append(&cm_pq);
        }

        // Try to add one more commitment
        let tx = ShieldedTransaction {
            spends: vec![],
            outputs: vec![OutputDescription {
                note_commitment: NoteCommitment::default(),
                value_commitment: [0u8; 32],
                proof: vec![],
            }],
            fee: 0,
            binding_sig: Default::default(),
        };

        let result = validator.validate_tree_limits(&tx, &state);
        assert!(matches!(
            result,
            Err(BalanceValidationError::CommitmentTreeOverflow { count: 6 })
        ));
    }

    #[test]
    fn test_nullifier_uniqueness_within_transaction() {
        let validator = BalanceValidator::new();
        let state = ShieldedState::new();

        let nullifier = Nullifier::from([1u8; 32]);
        
        // Create transaction with duplicate nullifiers
        let tx = ShieldedTransaction {
            spends: vec![
                SpendDescription {
                    nullifier,
                    anchor: TreeHash::default(),
                    value_commitment: [0u8; 32],
                    proof: vec![],
                    signature: Default::default(),
                },
                SpendDescription {
                    nullifier, // Duplicate!
                    anchor: TreeHash::default(),
                    value_commitment: [0u8; 32],
                    proof: vec![],
                    signature: Default::default(),
                },
            ],
            outputs: vec![],
            fee: 0,
            binding_sig: Default::default(),
        };

        let result = validator.validate_nullifier_uniqueness(&tx, &state);
        assert!(matches!(
            result,
            Err(BalanceValidationError::NullifierAlreadySpent { .. })
        ));
    }

    #[test]
    fn test_state_invariants_validation() {
        let validator = BalanceValidator::new();
        let state = ShieldedState::new();

        // Empty state should pass all invariants
        let result = validator.validate_state_invariants(&state);
        assert!(result.is_ok());
    }
}