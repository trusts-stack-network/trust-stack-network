//! Validation logic for blocks and transactions - SECURE VERSION
//! 
//! This module contains the core validation rules for TSN, including
//! signature verification using SLH-DSA (FIPS 205) post-quantum signatures.
//! 
//! SECURITY: All unwraps/expects have been replaced with proper error handling
//! to prevent DoS via malicious inputs or system clock manipulation.

use crate::core::{Block, Transaction, BlockHeader};
use crate::crypto::hash::Hash;
use crate::crypto::signature::{SignatureScheme, SignatureError};
use crate::crypto::pq::slh_dsa::{SlhDsaVerifier, SlhDsaSignature, SLH_DSA_SHA2_128S};
use crate::state::StateView;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{warn, error};

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid block signature")]
    InvalidBlockSignature,
    #[error("Invalid transaction signature")]
    InvalidTransactionSignature,
    #[error("Block timestamp is too far in the future")]
    TimestampTooFarInFuture,
    #[error("Block timestamp is before parent block")]
    TimestampBeforeParent,
    #[error("Invalid proof of work")]
    InvalidProofOfWork,
    #[error("Merkle root mismatch")]
    MerkleRootMismatch,
    #[error("State root mismatch")]
    StateRootMismatch,
    #[error("Signature verification error: {0}")]
    SignatureVerification(#[from] SignatureError),
    #[error("System clock error: {0}")]
    SystemClockError(String),
    #[error("Invalid signature bytes")]
    InvalidSignatureBytes,
}

/// Maximum allowed time drift in seconds
const MAX_TIME_DRIFT: u64 = 60;

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

    /// Get current timestamp safely - returns error instead of panicking
    /// 
    /// SECURITY: SystemTime::now().duration_since(UNIX_EPOCH) can panic if
    /// system clock is before 1970. We handle this gracefully.
    fn current_timestamp_safe() -> Result<u64, ValidationError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| {
                error!("System clock is before UNIX epoch: {}", e);
                ValidationError::SystemClockError(format!("Clock before 1970: {}", e))
            })
    }

    /// Validate a complete block including all transactions
    pub fn validate_block(&self, block: &Block, parent_header: Option<&BlockHeader>, state_view: &dyn StateView) -> Result<(), ValidationError> {
        // Validate block header
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

    /// Validate block header
    fn validate_block_header(&self, header: &BlockHeader, parent_header: Option<&BlockHeader>) -> Result<(), ValidationError> {
        // Validate timestamp - SECURE: no unwrap
        let current_time = Self::current_timestamp_safe()?;

        if header.timestamp > current_time + MAX_TIME_DRIFT {
            return Err(ValidationError::TimestampTooFarInFuture);
        }

        if let Some(parent) = parent_header {
            if header.timestamp <= parent.timestamp {
                return Err(ValidationError::TimestampBeforeParent);
            }
        }

        // Validate proof of work
        if !header.verify_proof_of_work() {
            return Err(ValidationError::InvalidProofOfWork);
        }

        // Validate block signature using SLH-DSA
        self.validate_block_signature(header)?;

        Ok(())
    }

    /// Validate block signature using SLH-DSA
    fn validate_block_signature(&self, header: &BlockHeader) -> Result<(), ValidationError> {
        let message = header.signature_message();
        
        // SECURE: Handle signature parsing failure gracefully
        let signature = SlhDsaSignature::from_bytes(&header.signature)
            .map_err(|e| {
                warn!("Failed to parse block signature: {:?}", e);
                ValidationError::InvalidSignatureBytes
            })?;

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

        Ok(())
    }

    /// Validate transaction signature using SLH-DSA
    fn validate_transaction_signature(&self, tx: &Transaction) -> Result<(), ValidationError> {
        let message = tx.signature_message();
        
        // SECURE: Handle signature parsing failure gracefully
        let signature = SlhDsaSignature::from_bytes(&tx.signature)
            .map_err(|e| {
                warn!("Failed to parse transaction signature: {:?}", e);
                ValidationError::InvalidSignatureBytes
            })?;

        self.slh_dsa_verifier
            .verify(&tx.sender_public_key, &message, &signature)
            .map_err(|e| match e {
                SignatureError::InvalidSignature => ValidationError::InvalidTransactionSignature,
                other => ValidationError::SignatureVerification(other),
            })?;

        Ok(())
    }
}

impl Default for Validator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Transaction, TransactionInput, TransactionOutput};
    use crate::crypto::pq::slh_dsa::{SlhDsaSigner, SLH_DSA_SHA2_128S};
    use crate::crypto::keys::{PublicKey, PrivateKey};

    struct MockStateView;

    impl StateView for MockStateView {
        fn compute_state_root(&self, _txs: &[Transaction]) -> Result<Hash, ValidationError> {
            Ok(Hash::zero())
        }
    }

    #[test]
    fn test_validate_transaction_signature() {
        let validator = Validator::new();
        let signer = SlhDsaSigner::new(SLH_DSA_SHA2_128S);
        let (pk, sk) = signer.generate_keypair()
            .expect("Key generation should succeed");

        // Create a valid transaction
        let mut tx = Transaction {
            inputs: vec![TransactionInput {
                previous_output: Hash::zero(),
                script: vec![],
            }],
            outputs: vec![TransactionOutput {
                value: 100,
                script: vec![],
            }],
            sender_public_key: pk.to_bytes(),
            signature: vec![],
        };

        // Sign the transaction
        let message = tx.signature_message();
        let signature = signer.sign(&sk, &message)
            .expect("Signing should succeed");
        tx.signature = signature.to_bytes();

        // Validate should pass
        assert!(validator.validate_transaction(&tx).is_ok());

        // Tamper with the transaction - should fail gracefully
        tx.outputs[0].value = 200;
        assert!(validator.validate_transaction(&tx).is_err());
    }

    #[test]
    fn test_invalid_signature_bytes() {
        let validator = Validator::new();
        
        let tx = Transaction {
            inputs: vec![TransactionInput {
                previous_output: Hash::zero(),
                script: vec![],
            }],
            outputs: vec![TransactionOutput {
                value: 100,
                script: vec![],
            }],
            sender_public_key: vec![0u8; 32], // Invalid but present
            signature: vec![0xff; 100], // Invalid signature bytes
        };

        // Should fail gracefully without panic
        let result = validator.validate_transaction(&tx);
        assert!(result.is_err());
        match result {
            Err(ValidationError::InvalidSignatureBytes) => {},
            Err(ValidationError::InvalidTransactionSignature) => {},
            _ => panic!("Expected signature-related error"),
        }
    }

    #[test]
    fn test_current_timestamp_safe() {
        // This should never fail on a normal system
        let ts = Validator::current_timestamp_safe();
        assert!(ts.is_ok());
        assert!(ts.unwrap() > 1700000000); // After 2023
    }
}
