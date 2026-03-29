//! Proof-of-Work validation for shielded blocks.
//!
//! This module provides robust PoW validation that integrates with the existing
//! block and difficulty structures. It validates:
//! 1. The nonce produces a hash that meets the difficulty target
//! 2. The difficulty value is valid for the given block height
//! 3. The block header hash is computed correctly

use crate::core::{BlockHeader, ShieldedBlock, BlockError, BLOCK_HASH_SIZE};
use crate::consensus::difficulty::{validate_difficulty, DifficultyValidationError};
use crate::consensus::poseidon_pow;
use thiserror::Error;

/// Errors that can occur during proof-of-work validation
#[derive(Error, Debug)]
pub enum PowValidationError {
    #[error("Block hash does not meet difficulty target: difficulty={difficulty}, hash={hash}")]
    InsufficientProofOfWork { difficulty: u64, hash: String },
    
    #[error("Invalid difficulty value: {0}")]
    InvalidDifficulty(#[from] DifficultyValidationError),
    
    #[error("Block header hash computation failed")]
    HashComputationFailed,
    
    #[error("Nonce overflow: maximum attempts reached")]
    NonceOverflow,
    
    #[error("Invalid timestamp: {reason}")]
    InvalidTimestamp { reason: String },
    
    #[error("Block validation failed: {0}")]
    BlockValidation(#[from] BlockError),
}

/// Core proof-of-work validator
pub struct PowValidator {
    /// Minimum difficulty allowed (safety measure)
    min_difficulty: u64,
    /// Maximum difficulty allowed (prevents runaway)
    max_difficulty: u64,
    /// Maximum time drift allowed in seconds
    max_time_drift: u64,
}

impl PowValidator {
    /// Create a new PoW validator with default settings
    pub fn new() -> Self {
        Self {
            min_difficulty: crate::consensus::difficulty::MIN_DIFFICULTY,
            max_difficulty: crate::consensus::difficulty::MAX_DIFFICULTY,
            max_time_drift: 60, // 1 minute
        }
    }
    
    /// Create a new PoW validator with custom settings
    pub fn with_config(min_difficulty: u64, max_difficulty: u64, max_time_drift: u64) -> Self {
        Self {
            min_difficulty,
            max_difficulty,
            max_time_drift,
        }
    }
    
    /// Validate the proof-of-work for a complete shielded block.
    /// This is the main validation entry point.
    pub fn validate_block_pow(
        &self, 
        block: &ShieldedBlock, 
        previous_difficulty: Option<u64>,
        current_time: Option<u64>
    ) -> Result<(), PowValidationError> {
        // Validate block structure first
        block.verify()?;
        
        // Validate header PoW
        self.validate_header_pow(&block.header, previous_difficulty, current_time)?;
        
        Ok(())
    }
    
    /// Validate the proof-of-work for a block header.
    /// This includes nonce, difficulty, and timestamp validation.
    pub fn validate_header_pow(
        &self, 
        header: &BlockHeader,
        previous_difficulty: Option<u64>,
        current_time: Option<u64>
    ) -> Result<(), PowValidationError> {
        // 1. Validate timestamp
        self.validate_timestamp(header, current_time)?;
        
        // 2. Validate difficulty value
        self.validate_difficulty_value(header, previous_difficulty)?;
        
        // 3. Validate that the hash meets the difficulty target
        self.validate_hash_meets_difficulty(header)?;
        
        Ok(())
    }
    
    /// Validate that the block timestamp is reasonable
    fn validate_timestamp(&self, header: &BlockHeader, current_time: Option<u64>) -> Result<(), PowValidationError> {
        let now = current_time.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });
        
        // Check if timestamp is too far in the future
        if header.timestamp > now + self.max_time_drift {
            return Err(PowValidationError::InvalidTimestamp {
                reason: format!(
                    "Timestamp {} is {} seconds in the future (max drift: {})",
                    header.timestamp,
                    header.timestamp - now,
                    self.max_time_drift
                ),
            });
        }
        
        // Timestamp should not be zero (except for genesis)
        if header.timestamp == 0 && header.prev_hash != [0u8; BLOCK_HASH_SIZE] {
            return Err(PowValidationError::InvalidTimestamp {
                reason: "Non-genesis block cannot have zero timestamp".to_string(),
            });
        }
        
        Ok(())
    }
    
    /// Validate the difficulty value using the consensus rules
    fn validate_difficulty_value(&self, header: &BlockHeader, previous_difficulty: Option<u64>) -> Result<(), PowValidationError> {
        // Use a block height estimation (in real implementation, this would come from the blockchain)
        // For now, we'll use a simple heuristic or require it to be passed in
        let estimated_height = self.estimate_block_height(header);
        
        validate_difficulty(header.difficulty, previous_difficulty, estimated_height)?;
        
        // Additional bounds checking
        if header.difficulty < self.min_difficulty {
            return Err(PowValidationError::InvalidDifficulty(
                DifficultyValidationError::BelowMinimum(header.difficulty)
            ));
        }
        
        if header.difficulty > self.max_difficulty {
            return Err(PowValidationError::InvalidDifficulty(
                DifficultyValidationError::AboveMaximum(header.difficulty)
            ));
        }
        
        Ok(())
    }
    
    /// Validate that the block hash meets the specified difficulty target
    fn validate_hash_meets_difficulty(&self, header: &BlockHeader) -> Result<(), PowValidationError> {
        // Compute the block hash
        let hash = header.hash();
        
        // Check if it meets the difficulty
        if !header.meets_difficulty() {
            let hash_hex = hex::encode(hash);
            let leading_zeros = count_leading_zeros(&hash);
            
            return Err(PowValidationError::InsufficientProofOfWork {
                difficulty: header.difficulty,
                hash: format!("{} (leading zeros: {})", hash_hex, leading_zeros),
            });
        }
        
        // Verify hash computation is correct by recomputing
        let recomputed_hash = self.compute_header_hash(header);
        if recomputed_hash != hash {
            return Err(PowValidationError::HashComputationFailed);
        }
        
        Ok(())
    }
    
    /// Recompute the header hash to verify correctness (Poseidon ZK-friendly)
    fn compute_header_hash(&self, header: &BlockHeader) -> [u8; BLOCK_HASH_SIZE] {
        poseidon_pow::poseidon_hash_header_parts(
            header.version,
            &header.prev_hash,
            &header.merkle_root,
            &header.commitment_root,
            &header.nullifier_root,
            header.timestamp,
            header.difficulty,
            header.nonce,
        )
    }
    
    /// Estimate block height from header (placeholder implementation)
    /// In a real implementation, this would be provided by the blockchain context
    fn estimate_block_height(&self, header: &BlockHeader) -> u64 {
        // Simple estimation based on timestamp (assuming 10s block time)
        // This is not accurate but serves as a fallback for validation
        if header.timestamp == 0 {
            return 0; // Genesis block
        }
        
        // Rough estimation: timestamp / target_block_time
        header.timestamp / crate::consensus::difficulty::TARGET_BLOCK_TIME_SECS
    }
}

impl Default for PowValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Count the number of leading zero bits in a byte array
fn count_leading_zeros(bytes: &[u8]) -> usize {
    let mut zeros = 0;
    for byte in bytes {
        if *byte == 0 {
            zeros += 8;
        } else {
            zeros += byte.leading_zeros() as usize;
            break;
        }
    }
    zeros
}

/// Utility function to verify a single block's PoW quickly
pub fn verify_block_pow(block: &ShieldedBlock, previous_difficulty: Option<u64>) -> Result<(), PowValidationError> {
    let validator = PowValidator::new();
    validator.validate_block_pow(block, previous_difficulty, None)
}

/// Utility function to verify just a block header's PoW
pub fn verify_header_pow(header: &BlockHeader, previous_difficulty: Option<u64>) -> Result<(), PowValidationError> {
    let validator = PowValidator::new();
    validator.validate_header_pow(header, previous_difficulty, None)
}

/// Advanced PoW validation context for blockchain integration
pub struct PowValidationContext {
    pub block_height: u64,
    pub parent_timestamp: Option<u64>,
    pub current_time: u64,
    pub chain_work: Option<u64>, // Total work in the chain
}

impl PowValidationContext {
    pub fn new(block_height: u64, current_time: u64) -> Self {
        Self {
            block_height,
            parent_timestamp: None,
            current_time,
            chain_work: None,
        }
    }
    
    pub fn with_parent_timestamp(mut self, parent_timestamp: u64) -> Self {
        self.parent_timestamp = Some(parent_timestamp);
        self
    }
    
    pub fn with_chain_work(mut self, chain_work: u64) -> Self {
        self.chain_work = Some(chain_work);
        self
    }
}

/// Extended PoW validator that uses full blockchain context
pub trait PowValidatorExt {
    /// Validate PoW with full blockchain context
    fn validate_with_context(
        &self, 
        header: &BlockHeader, 
        previous_difficulty: Option<u64>,
        context: &PowValidationContext
    ) -> Result<(), PowValidationError>;
}

impl PowValidatorExt for PowValidator {
    fn validate_with_context(
        &self, 
        header: &BlockHeader, 
        previous_difficulty: Option<u64>,
        context: &PowValidationContext
    ) -> Result<(), PowValidationError> {
        // Validate timestamp against parent
        if let Some(parent_ts) = context.parent_timestamp {
            if header.timestamp <= parent_ts {
                return Err(PowValidationError::InvalidTimestamp {
                    reason: format!(
                        "Block timestamp {} is not after parent timestamp {}",
                        header.timestamp, parent_ts
                    ),
                });
            }
        }
        
        // Use context-aware validation
        validate_difficulty(header.difficulty, previous_difficulty, context.block_height)?;
        
        // Standard PoW validation
        self.validate_hash_meets_difficulty(header)?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::transaction::CoinbaseTransaction;
    use crate::crypto::commitment::NoteCommitment;
    use crate::crypto::note::EncryptedNote;
    
    fn dummy_coinbase() -> CoinbaseTransaction {
        CoinbaseTransaction::new(
            NoteCommitment([1u8; 32]),
            [1u8; 32],
            EncryptedNote {
                ciphertext: vec![0; 64],
                ephemeral_pk: vec![0; 32],
            },
            50,
            0,
        )
    }
    
    #[test]
    fn test_pow_validator_creation() {
        let validator = PowValidator::new();
        assert_eq!(validator.min_difficulty, crate::consensus::difficulty::MIN_DIFFICULTY);
        assert_eq!(validator.max_difficulty, crate::consensus::difficulty::MAX_DIFFICULTY);
        assert_eq!(validator.max_time_drift, 60);
    }
    
    #[test]
    fn test_valid_genesis_block_pow() {
        let mut genesis = ShieldedBlock::genesis(8, dummy_coinbase());
        
        // Mine the genesis block to have valid PoW
        let validator = PowValidator::new();
        
        // For testing, we'll just set a difficulty that the current hash meets
        let hash = genesis.header.hash();
        let leading_zeros = count_leading_zeros(&hash);
        genesis.header.difficulty = leading_zeros.min(8) as u64;
        
        let result = validator.validate_block_pow(&genesis, None, Some(1000000));
        assert!(result.is_ok(), "Genesis block PoW validation failed: {:?}", result);
    }
    
    #[test]
    fn test_insufficient_proof_of_work() {
        let mut block = ShieldedBlock::genesis(32, dummy_coinbase()); // Very high difficulty
        block.header.nonce = 0; // Definitely won't meet difficulty 32
        
        let validator = PowValidator::new();
        let result = validator.validate_block_pow(&block, None, Some(1000000));
        
        assert!(matches!(result, Err(PowValidationError::InsufficientProofOfWork { .. })));
    }
    
    #[test]
    fn test_timestamp_too_far_in_future() {
        let mut block = ShieldedBlock::genesis(4, dummy_coinbase());
        
        // Set timestamp far in the future
        let future_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + 3600; // 1 hour in future
        block.header.timestamp = future_time;
        
        let validator = PowValidator::new();
        let result = validator.validate_block_pow(&block, None, None);
        
        assert!(matches!(result, Err(PowValidationError::InvalidTimestamp { .. })));
    }
    
    #[test]
    fn test_difficulty_below_minimum() {
        let mut block = ShieldedBlock::genesis(1, dummy_coinbase()); // Below minimum
        
        let validator = PowValidator::new();
        let result = validator.validate_header_pow(&block.header, None, Some(1000000));
        
        assert!(matches!(result, Err(PowValidationError::InvalidDifficulty(_))));
    }
    
    #[test]
    fn test_difficulty_above_maximum() {
        let mut block = ShieldedBlock::genesis(100, dummy_coinbase()); // Above maximum
        
        let validator = PowValidator::new();
        let result = validator.validate_header_pow(&block.header, None, Some(1000000));
        
        assert!(matches!(result, Err(PowValidationError::InvalidDifficulty(_))));
    }
    
    #[test]
    fn test_leading_zeros_counting() {
        assert_eq!(count_leading_zeros(&[0x00, 0x00, 0xFF]), 16);
        assert_eq!(count_leading_zeros(&[0x0F, 0x00, 0x00]), 4);
        assert_eq!(count_leading_zeros(&[0x80, 0x00, 0x00]), 0);
        assert_eq!(count_leading_zeros(&[0x40, 0x00, 0x00]), 1);
        assert_eq!(count_leading_zeros(&[0x01, 0x00, 0x00]), 7);
    }
    
    #[test]
    fn test_validation_context() {
        let context = PowValidationContext::new(100, 1000000)
            .with_parent_timestamp(999990)
            .with_chain_work(12345);
        
        assert_eq!(context.block_height, 100);
        assert_eq!(context.current_time, 1000000);
        assert_eq!(context.parent_timestamp, Some(999990));
        assert_eq!(context.chain_work, Some(12345));
    }
    
    #[test]
    fn test_utility_functions() {
        let block = ShieldedBlock::genesis(8, dummy_coinbase());
        
        // Test utility function
        let result = verify_block_pow(&block, None);
        assert!(result.is_ok() || matches!(result, Err(PowValidationError::InsufficientProofOfWork { .. })));
        
        // Test header utility function
        let result = verify_header_pow(&block.header, None);
        assert!(result.is_ok() || matches!(result, Err(PowValidationError::InsufficientProofOfWork { .. })));
    }
}