//! MIK integration with consensus mechanism.
//!
//! This module handles the integration of Mining Identity Keys with the
//! proof-of-work consensus, ensuring only registered and active MIKs can
//! produce valid blocks.

use crate::core::mik_manager::{MikManager, MikManagerConfig};
use crate::crypto::mik::{MikError, MikId, MikMetadata, MikStatus};
use crate::crypto::signature::verify_signature;
use fips204::ml_dsa_65;
use thiserror::Error;

/// Configuration for MIK consensus integration.
#[derive(Clone, Debug)]
pub struct MikConsensusConfig {
    /// Base MIK manager configuration.
    pub mik_config: MikManagerConfig,
    /// Require MIK signature in block header.
    pub require_mik_signature: bool,
    /// Penalty for invalid MIK blocks (in blocks).
    pub invalid_mik_penalty: u64,
}

impl Default for MikConsensusConfig {
    fn default() -> Self {
        Self {
            mik_config: MikManagerConfig::default(),
            require_mik_signature: true,
            invalid_mik_penalty: 100,
        }
    }
}

/// Result of MIK validation for a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MikValidationResult {
    /// MIK is valid and authorized to mine.
    Valid,
    /// MIK is valid but pending activation.
    Pending,
    /// MIK is not found or invalid.
    Invalid(MikConsensusError),
}

/// Errors specific to MIK consensus validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MikConsensusError {
    #[error("MIK not found in registry")]
    MikNotFound,
    
    #[error("MIK is not active")]
    MikNotActive,
    
    #[error("MIK is pending activation")]
    MikPending,
    
    #[error("MIK has been revoked")]
    MikRevoked,
    
    #[error("Invalid MIK signature")]
    InvalidSignature,
    
    #[error("MIK signature verification failed")]
    SignatureVerificationFailed,
    
    #[error("No MIK signature provided")]
    MissingSignature,
    
    #[error("Insufficient stake for mining")]
    InsufficientStake,
    
    #[error("MIK expired")]
    MikExpired,
}

/// MIK consensus validator.
/// Validates that blocks are mined by authorized MIKs.
pub struct MikConsensusValidator {
    config: MikConsensusConfig,
    mik_manager: MikManager,
}

impl MikConsensusValidator {
    /// Create a new validator with default configuration.
    pub fn new() -> Self {
        Self::with_config(MikConsensusConfig::default())
    }

    /// Create a new validator with custom configuration.
    pub fn with_config(config: MikConsensusConfig) -> Self {
        let mik_manager = MikManager::with_config(config.mik_config.clone());
        
        Self {
            config,
            mik_manager,
        }
    }

    /// Get a reference to the MIK manager.
    pub fn mik_manager(&self) -> &MikManager {
        &self.mik_manager
    }

    /// Get a mutable reference to the MIK manager.
    pub fn mik_manager_mut(&mut self) -> &mut MikManager {
        &mut self.mik_manager
    }

    /// Update the current block height in the MIK manager.
    pub fn set_height(&mut self, height: u64) {
        self.mik_manager.set_height(height);
    }

    /// Validate a MIK for mining at the current height.
    /// 
    /// This checks:
    /// 1. MIK exists in the registry
    /// 2. MIK is active (not pending/revoked/expired)
    /// 3. MIK has sufficient stake
    pub fn validate_mik_for_mining(
        &self,
        mik_id: &MikId,
    ) -> MikValidationResult {
        let metadata = match self.mik_manager.get(mik_id) {
            Some(m) => m,
            None => {
                return MikValidationResult::Invalid(MikConsensusError::MikNotFound);
            }
        };

        match metadata.status {
            MikStatus::Active => {
                // Check minimum stake
                if metadata.stake_amount < self.config.mik_config.min_stake {
                    return MikValidationResult::Invalid(
                        MikConsensusError::InsufficientStake
                    );
                }
                MikValidationResult::Valid
            }
            MikStatus::Pending => {
                MikValidationResult::Pending
            }
            MikStatus::Revoked => {
                MikValidationResult::Invalid(MikConsensusError::MikRevoked)
            }
            MikStatus::Expired => {
                MikValidationResult::Invalid(MikConsensusError::MikExpired)
            }
        }
    }

    /// Verify a MIK signature on block data.
    ///
    /// The signature proves that the block was mined by the owner
    /// of the MIK private key.
    pub fn verify_block_signature(
        &self,
        mik_id: &MikId,
        block_hash: &[u8; 32],
        signature: &[u8; 3309],
    ) -> Result<(), MikConsensusError> {
        let metadata = self.mik_manager.get(mik_id)
            .ok_or(MikConsensusError::MikNotFound)?;

        // Parse the public key
        let public_key = ml_dsa_65::PublicKey::try_from_bytes(metadata.public_key)
            .map_err(|_| MikConsensusError::InvalidSignature)?;

        // Parse the signature
        let sig = ml_dsa_65::Signature::try_from_bytes(*signature)
            .map_err(|_| MikConsensusError::InvalidSignature)?;

        // Verify the signature
        ml_dsa_65::verify(&public_key,
            block_hash,
            &sig,
            &[]
        ).map_err(|_| MikConsensusError::SignatureVerificationFailed)
    }

    /// Full validation of a block with MIK.
    ///
    /// This combines MIK validation with signature verification.
    pub fn validate_block(
        &self,
        mik_id: &MikId,
        block_hash: &[u8; 32],
        signature: Option<&[u8; 3309]>,
    ) -> Result<(), MikConsensusError> {
        // First validate the MIK
        match self.validate_mik_for_mining(mik_id) {
            MikValidationResult::Valid => {}
            MikValidationResult::Pending => {
                return Err(MikConsensusError::MikPending);
            }
            MikValidationResult::Invalid(e) => {
                return Err(e);
            }
        }

        // Then verify the signature if required
        if self.config.require_mik_signature {
            let sig = signature.ok_or(MikConsensusError::MissingSignature)?;
            self.verify_block_signature(mik_id, block_hash, sig)?;
        }

        Ok(())
    }

    /// Get the list of active MIKs eligible for mining.
    pub fn eligible_miners(&self) -> Vec<&MikMetadata> {
        self.mik_manager.active_miks()
    }

    /// Get the number of eligible miners.
    pub fn eligible_miner_count(&self) -> usize {
        self.mik_manager.active_count()
    }

    /// Calculate mining difficulty adjustment based on active MIK count.
    ///
    /// More miners = slightly higher difficulty to maintain block time.
    pub fn calculate_difficulty_adjustment(&self,
        base_difficulty: u64,
    ) -> u64 {
        let miner_count = self.eligible_miner_count() as u64;
        
        if miner_count == 0 {
            return base_difficulty;
        }

        // Simple adjustment: increase difficulty by 1% per 100 miners
        // This is a placeholder - real adjustment would be more sophisticated
        let adjustment = miner_count / 100;
        base_difficulty + adjustment
    }
}

impl Default for MikConsensusValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for MIK consensus configuration.
pub struct MikConsensusConfigBuilder {
    config: MikConsensusConfig,
}

impl MikConsensusConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: MikConsensusConfig::default(),
        }
    }

    pub fn min_stake(mut self, stake: u64) -> Self {
        self.config.mik_config.min_stake = stake;
        self
    }

    pub fn confirmation_blocks(mut self, blocks: u64) -> Self {
        self.config.mik_config.confirmation_blocks = blocks;
        self
    }

    pub fn require_signature(mut self, require: bool) -> Self {
        self.config.require_mik_signature = require;
        self
    }

    pub fn build(self) -> MikConsensusConfig {
        self.config
    }
}

impl Default for MikConsensusConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::mik_manager::MikManager;
    use crate::crypto::mik::{MiningIdentityKey, MikRegistrationRequest};

    fn create_test_mik_and_request(stake: u64) -> (MiningIdentityKey, MikRegistrationRequest) {
        let mik = MiningIdentityKey::generate(stake, 100).unwrap();
        let metadata = mik.metadata();
        let stake_proof = [0u8; 32];
        
        // Sign the metadata hash
        let msg_hash = metadata.hash();
        let signature = mik.sign(&msg_hash).unwrap();
        
        let request = MikRegistrationRequest::new(metadata, stake_proof, signature);
        (mik, request)
    }

    fn setup_validator_with_mik() -> (MikConsensusValidator, MiningIdentityKey, MikId) {
        let mut validator = MikConsensusValidator::new();
        validator.set_height(100);

        let (mik, request) = create_test_mik_and_request(2_000_000);
        let mik_id = validator.mik_manager_mut().register(request).unwrap();

        // Activate the MIK
        validator.set_height(250);

        (validator, mik, mik_id)
    }

    #[test]
    fn test_mik_validation_valid() {
        let (validator, _mik, mik_id) = setup_validator_with_mik();

        let result = validator.validate_mik_for_mining(&mik_id);
        assert_eq!(result, MikValidationResult::Valid);
    }

    #[test]
    fn test_mik_validation_not_found() {
        let validator = MikConsensusValidator::new();
        
        let fake_mik_id = MikId::generate();
        let result = validator.validate_mik_for_mining(&fake_mik_id);
        
        assert!(matches!(result, 
            MikValidationResult::Invalid(MikConsensusError::MikNotFound)));
    }

    #[test]
    fn test_mik_validation_pending() {
        let mut validator = MikConsensusValidator::new();
        validator.set_height(100);

        let (mik, request) = create_test_mik_and_request(2_000_000);
        let mik_id = validator.mik_manager_mut().register(request).unwrap();

        // Don't activate yet
        let result = validator.validate_mik_for_mining(&mik_id);
        assert_eq!(result, MikValidationResult::Pending);
    }

    #[test]
    fn test_block_signature_verification() {
        let (validator, mik, mik_id) = setup_validator_with_mik();

        let block_hash = [1u8; 32];
        let signature = mik.sign(&block_hash).unwrap();

        let result = validator.verify_block_signature(
            &mik_id,
            &block_hash,
            &signature,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_block_signature_invalid() {
        let (validator, _mik, mik_id) = setup_validator_with_mik();

        let block_hash = [1u8; 32];
        let fake_signature = [0u8; 3309];

        let result = validator.verify_block_signature(
            &mik_id,
            &block_hash,
            &fake_signature,
        );
        assert!(matches!(result, 
            Err(MikConsensusError::SignatureVerificationFailed)));
    }

    #[test]
    fn test_full_block_validation() {
        let (validator, mik, mik_id) = setup_validator_with_mik();

        let block_hash = [1u8; 32];
        let signature = mik.sign(&block_hash).unwrap();

        let result = validator.validate_block(
            &mik_id,
            &block_hash,
            Some(&signature),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_full_block_validation_missing_signature() {
        let (validator, _mik, mik_id) = setup_validator_with_mik();

        let block_hash = [1u8; 32];

        let result = validator.validate_block(
            &mik_id,
            &block_hash,
            None,
        );
        assert!(matches!(result, Err(MikConsensusError::MissingSignature)));
    }

    #[test]
    fn test_eligible_miners() {
        let (validator, _mik, _mik_id) = setup_validator_with_mik();

        let miners = validator.eligible_miners();
        assert_eq!(miners.len(), 1);
    }

    #[test]
    fn test_difficulty_adjustment() {
        let validator = MikConsensusValidator::new();
        
        // With no miners, difficulty should be unchanged
        let adjusted = validator.calculate_difficulty_adjustment(1000);
        assert_eq!(adjusted, 1000);
    }
}