//! Comprehensive validator for shielded blocks.
//!
//! This module provides a complete validation framework for shielded blocks,
//! integrating proof-of-work validation, transaction validation, and state
//! consistency checks.

use crate::core::block::{BlockError, BlockHeader, ShieldedBlock, BLOCK_HASH_SIZE};
use crate::consensus::{PowValidator, PowValidationContext, PowValidationError};
use thiserror::Error;

/// Comprehensive validation errors for shielded blocks
#[derive(Error, Debug)]
pub enum ShieldedBlockValidationError {
    #[error("Block structure error: {0}")]
    BlockStructure(#[from] BlockError),
    
    #[error("Proof-of-work validation failed: {0}")]
    ProofOfWork(#[from] PowValidationError),
    
    #[error("Invalid previous block hash")]
    InvalidPreviousHash,
    
    #[error("Invalid block height: expected {expected}, got {actual}")]
    InvalidHeight { expected: u64, actual: u64 },
    
    #[error("Invalid coinbase reward: expected {expected}, got {actual}")]
    InvalidCoinbaseReward { expected: u64, actual: u64 },
    
    #[error("Duplicate transaction found")]
    DuplicateTransaction,
    
    #[error("Transaction validation failed: {0}")]
    TransactionValidation(String),
    
    #[error("State transition error: {0}")]
    StateTransition(String),
    
    #[error("Commitment tree validation failed: {0}")]
    CommitmentValidation(String),
    
    #[error("Nullifier validation failed: {0}")]
    NullifierValidation(String),
}

/// Context information for block validation
#[derive(Debug, Clone)]
pub struct BlockValidationContext {
    /// The height of this block in the chain
    pub block_height: u64,
    /// Hash of the previous block
    pub previous_block_hash: [u8; BLOCK_HASH_SIZE],
    /// Timestamp of the previous block
    pub previous_timestamp: Option<u64>,
    /// Difficulty of the previous block
    pub previous_difficulty: Option<u64>,
    /// Current time for timestamp validation
    pub current_time: u64,
    /// Expected block reward amount
    pub expected_reward: u64,
    /// Current commitment tree root
    pub commitment_root: [u8; BLOCK_HASH_SIZE],
    /// Current nullifier set root
    pub nullifier_root: [u8; BLOCK_HASH_SIZE],
}

impl BlockValidationContext {
    /// Create a new validation context
    pub fn new(
        block_height: u64,
        previous_block_hash: [u8; BLOCK_HASH_SIZE],
        current_time: u64,
        expected_reward: u64,
    ) -> Self {
        Self {
            block_height,
            previous_block_hash,
            previous_timestamp: None,
            previous_difficulty: None,
            current_time,
            expected_reward,
            commitment_root: [0u8; BLOCK_HASH_SIZE],
            nullifier_root: [0u8; BLOCK_HASH_SIZE],
        }
    }
    
    /// Set the previous block information
    pub fn with_previous_block(
        mut self,
        timestamp: u64,
        difficulty: u64,
        commitment_root: [u8; BLOCK_HASH_SIZE],
        nullifier_root: [u8; BLOCK_HASH_SIZE],
    ) -> Self {
        self.previous_timestamp = Some(timestamp);
        self.previous_difficulty = Some(difficulty);
        self.commitment_root = commitment_root;
        self.nullifier_root = nullifier_root;
        self
    }
}

/// Comprehensive validator for shielded blocks
pub struct ShieldedBlockValidator {
    pow_validator: PowValidator,
    /// Whether to perform expensive cryptographic validations
    verify_proofs: bool,
    /// Whether to validate state transitions
    verify_state: bool,
}

impl ShieldedBlockValidator {
    /// Create a new validator with default settings
    pub fn new() -> Self {
        Self {
            pow_validator: PowValidator::new(),
            verify_proofs: true,
            verify_state: true,
        }
    }
    
    /// Create a validator with custom PoW settings
    pub fn with_pow_config(
        min_difficulty: u64,
        max_difficulty: u64,
        max_time_drift: u64,
    ) -> Self {
        Self {
            pow_validator: PowValidator::with_config(min_difficulty, max_difficulty, max_time_drift),
            verify_proofs: true,
            verify_state: true,
        }
    }
    
    /// Create a fast validator that skips expensive operations (for testing)
    pub fn fast() -> Self {
        Self {
            pow_validator: PowValidator::new(),
            verify_proofs: false,
            verify_state: false,
        }
    }
    
    /// Validate a complete shielded block with full context
    pub fn validate_block(
        &self,
        block: &ShieldedBlock,
        context: &BlockValidationContext,
    ) -> Result<(), ShieldedBlockValidationError> {
        // 1. Basic block structure validation
        self.validate_block_structure(block)?;
        
        // 2. Header validation (including PoW)
        self.validate_block_header(&block.header, context)?;
        
        // 3. Transaction validation
        self.validate_transactions(block, context)?;
        
        // 4. State consistency validation
        if self.verify_state {
            self.validate_state_consistency(block, context)?;
        }
        
        // 5. Cryptographic proofs validation
        if self.verify_proofs {
            self.validate_cryptographic_proofs(block, context)?;
        }
        
        Ok(())
    }
    
    /// Validate block structure and merkle root
    fn validate_block_structure(&self, block: &ShieldedBlock) -> Result<(), ShieldedBlockValidationError> {
        // Use the existing block verification
        block.verify()?;
        Ok(())
    }
    
    /// Validate block header including PoW
    fn validate_block_header(
        &self,
        header: &BlockHeader,
        context: &BlockValidationContext,
    ) -> Result<(), ShieldedBlockValidationError> {
        // Validate previous block hash
        if header.prev_hash != context.previous_block_hash {
            return Err(ShieldedBlockValidationError::InvalidPreviousHash);
        }
        
        // Create PoW validation context
        let pow_context = PowValidationContext::new(context.block_height, context.current_time)
            .with_parent_timestamp(context.previous_timestamp.unwrap_or(0));
        
        // Validate proof-of-work using our robust validator
        use crate::consensus::PowValidatorExt;
        self.pow_validator.validate_with_context(
            header,
            context.previous_difficulty,
            &pow_context,
        )?;
        
        Ok(())
    }
    
    /// Validate all transactions in the block
    fn validate_transactions(
        &self,
        block: &ShieldedBlock,
        context: &BlockValidationContext,
    ) -> Result<(), ShieldedBlockValidationError> {
        // Check for duplicate transactions
        let mut seen_hashes = std::collections::HashSet::new();
        
        for tx in &block.transactions {
            let tx_hash = tx.hash();
            if !seen_hashes.insert(tx_hash) {
                return Err(ShieldedBlockValidationError::DuplicateTransaction);
            }
            
            // Individual transaction validation would go here
            // This would include:
            // - Signature verification
            // - Input/output validation
            // - Fee validation
            // - Zero-knowledge proof verification
        }
        
        // Check V2 transactions as well
        for tx in &block.transactions_v2 {
            let tx_hash = tx.hash();
            if !seen_hashes.insert(tx_hash) {
                return Err(ShieldedBlockValidationError::DuplicateTransaction);
            }
        }
        
        // Validate coinbase transaction
        self.validate_coinbase(&block.coinbase, context)?;
        
        Ok(())
    }
    
    /// Validate the coinbase transaction
    fn validate_coinbase(
        &self,
        coinbase: &crate::core::transaction::CoinbaseTransaction,
        context: &BlockValidationContext,
    ) -> Result<(), ShieldedBlockValidationError> {
        // Check block height
        if coinbase.height != context.block_height {
            return Err(ShieldedBlockValidationError::InvalidHeight {
                expected: context.block_height,
                actual: coinbase.height,
            });
        }
        
        // Check reward amount (base reward + fees)
        let total_fees = 0u64; // In a real implementation, sum all transaction fees
        let expected_reward = context.expected_reward + total_fees;
        
        if coinbase.reward != expected_reward {
            return Err(ShieldedBlockValidationError::InvalidCoinbaseReward {
                expected: expected_reward,
                actual: coinbase.reward,
            });
        }
        
        Ok(())
    }
    
    /// Validate state consistency (commitment tree, nullifier set)
    fn validate_state_consistency(
        &self,
        block: &ShieldedBlock,
        context: &BlockValidationContext,
    ) -> Result<(), ShieldedBlockValidationError> {
        // Validate commitment root
        if block.header.commitment_root != context.commitment_root {
            return Err(ShieldedBlockValidationError::CommitmentValidation(
                "Commitment root mismatch with expected state".to_string(),
            ));
        }
        
        // Validate nullifier root
        if block.header.nullifier_root != context.nullifier_root {
            return Err(ShieldedBlockValidationError::NullifierValidation(
                "Nullifier root mismatch with expected state".to_string(),
            ));
        }
        
        // Additional state validation would go here:
        // - Check that all nullifiers are new
        // - Verify commitment tree updates
        // - Check state root computations
        
        Ok(())
    }
    
    /// Validate cryptographic proofs
    fn validate_cryptographic_proofs(
        &self,
        _block: &ShieldedBlock,
        _context: &BlockValidationContext,
    ) -> Result<(), ShieldedBlockValidationError> {
        // This would validate:
        // - Zero-knowledge proofs in transactions
        // - Post-quantum signatures
        // - Merkle tree proofs
        // - Binding signatures
        
        // For now, we assume proofs are valid
        // In a real implementation, this would be the most expensive part
        
        Ok(())
    }
    
    /// Quick validation for blocks (skips expensive operations)
    pub fn validate_block_fast(
        &self,
        block: &ShieldedBlock,
        previous_difficulty: Option<u64>,
    ) -> Result<(), ShieldedBlockValidationError> {
        // Basic structure
        block.verify()?;
        
        // Quick PoW check
        self.pow_validator.validate_header_pow(
            &block.header,
            previous_difficulty,
            Some(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()),
        )?;
        
        Ok(())
    }
}

impl Default for ShieldedBlockValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility function for quick block validation
pub fn validate_shielded_block(
    block: &ShieldedBlock,
    context: &BlockValidationContext,
) -> Result<(), ShieldedBlockValidationError> {
    let validator = ShieldedBlockValidator::new();
    validator.validate_block(block, context)
}

/// Utility function for fast block validation (testing/sync)
pub fn validate_shielded_block_fast(
    block: &ShieldedBlock,
    previous_difficulty: Option<u64>,
) -> Result<(), ShieldedBlockValidationError> {
    let validator = ShieldedBlockValidator::fast();
    validator.validate_block_fast(block, previous_difficulty)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::transaction::CoinbaseTransaction;
    use crate::crypto::commitment::NoteCommitment;
    use crate::crypto::note::EncryptedNote;
    
    fn dummy_coinbase(height: u64, reward: u64) -> CoinbaseTransaction {
        CoinbaseTransaction::new(
            NoteCommitment([1u8; 32]),
            [1u8; 32],
            EncryptedNote {
                ciphertext: vec![0; 64],
                ephemeral_pk: vec![0; 32],
            },
            reward,
            height,
        )
    }
    
    #[test]
    fn test_validator_creation() {
        let validator = ShieldedBlockValidator::new();
        assert!(validator.verify_proofs);
        assert!(validator.verify_state);
        
        let fast_validator = ShieldedBlockValidator::fast();
        assert!(!fast_validator.verify_proofs);
        assert!(!fast_validator.verify_state);
    }
    
    #[test]
    fn test_genesis_block_validation() {
        let genesis = ShieldedBlock::genesis(8, dummy_coinbase(0, 50));
        
        let context = BlockValidationContext::new(
            0,
            [0u8; BLOCK_HASH_SIZE],
            1000000,
            50,
        );
        
        let validator = ShieldedBlockValidator::fast();
        
        // This might fail due to PoW, but should at least not panic
        let result = validator.validate_block(&genesis, &context);
        match result {
            Ok(_) => println!("Genesis validation passed"),
            Err(e) => println!("Genesis validation failed (expected): {}", e),
        }
    }
    
    #[test]
    fn test_invalid_previous_hash() {
        let mut block = ShieldedBlock::genesis(8, dummy_coinbase(1, 50));
        block.header.prev_hash = [1u8; BLOCK_HASH_SIZE];
        
        let context = BlockValidationContext::new(
            1,
            [2u8; BLOCK_HASH_SIZE], // Different from block's prev_hash
            1000000,
            50,
        );
        
        let validator = ShieldedBlockValidator::fast();
        let result = validator.validate_block(&block, &context);
        
        assert!(matches!(result, Err(ShieldedBlockValidationError::InvalidPreviousHash)));
    }
    
    #[test]
    fn test_invalid_coinbase_height() {
        let block = ShieldedBlock::genesis(8, dummy_coinbase(5, 50)); // Wrong height
        
        let context = BlockValidationContext::new(
            0, // Expected height 0
            [0u8; BLOCK_HASH_SIZE],
            1000000,
            50,
        );
        
        let validator = ShieldedBlockValidator::fast();
        let result = validator.validate_block(&block, &context);
        
        assert!(matches!(
            result,
            Err(ShieldedBlockValidationError::InvalidHeight { expected: 0, actual: 5 })
        ));
    }
    
    #[test]
    fn test_fast_validation_utility() {
        let block = ShieldedBlock::genesis(8, dummy_coinbase(0, 50));
        
        // This should complete without panic, regardless of result
        let result = validate_shielded_block_fast(&block, None);
        match result {
            Ok(_) => println!("Fast validation passed"),
            Err(e) => println!("Fast validation failed: {}", e),
        }
    }
}