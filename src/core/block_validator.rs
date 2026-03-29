use crate::consensus::signature::{ConsensusSignature, SignatureError, SignatureScheme};
use crate::core::block::Block;
use crate::core::transaction::Transaction;
use crate::crypto::keys::PublicKey;
use thiserror::Error;

/// Errors that can occur during block validation
#[derive(Error, Debug, Clone, PartialEq)]
pub enum BlockValidationError {
    #[error("Invalid block signature: {0}")]
    InvalidSignature(SignatureError),
    #[error("Block uses deprecated signature scheme")]
    DeprecatedSignatureScheme,
    #[error("Invalid miner public key")]
    InvalidMinerKey,
    #[error("Block signature verification failed")]
    SignatureVerificationFailed,
    #[error("Block height mismatch")]
    HeightMismatch,
    #[error("Previous block hash missing")]
    PreviousHashMissing,
}

/// Validates consensus rules for blocks
pub struct BlockValidator {
    /// Whether to accept deprecated signature schemes (for transition period)
    allow_deprecated_schemes: bool,
    /// Block height after which only SLH-DSA is accepted
    slh_dsa_mandatory_height: u64,
}

impl BlockValidator {
    /// Creates a new validator with transition period support
    pub fn new(allow_deprecated_schemes: bool, slh_dsa_mandatory_height: u64) -> Self {
        Self {
            allow_deprecated_schemes,
            slh_dsa_mandatory_height,
        }
    }

    /// Validates a block's consensus signature
    pub fn validate_block_signature(
        &self,
        block: &Block,
        miner_pubkey: &PublicKey,
    ) -> Result<(), BlockValidationError> {
        // Check if deprecated schemes are allowed for this height
        if block.height >= self.slh_dsa_mandatory_height && self.allow_deprecated_schemes {
            if block.signature.is_deprecated() {
                return Err(BlockValidationError::DeprecatedSignatureScheme);
            }
        }

        // Verify the signature
        let block_hash = block.hash();
        match block.signature.verify(&block_hash, miner_pubkey) {
            Ok(true) => Ok(()),
            Ok(false) => Err(BlockValidationError::SignatureVerificationFailed),
            Err(e) => Err(BlockValidationError::InvalidSignature(e)),
        }
    }

    /// Validates that the block uses only supported signature schemes
    pub fn validate_signature_schemes(&self, block: &Block) -> Result<(), BlockValidationError> {
        // Check block signature scheme
        if !self.allow_deprecated_schemes && block.signature.is_deprecated() {
            return Err(BlockValidationError::DeprecatedSignatureScheme);
        }

        // Check transaction signature schemes
        for tx in &block.transactions {
            self.validate_transaction_schemes(tx)?;
        }

        Ok(())
    }

