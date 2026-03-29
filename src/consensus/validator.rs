//! Consensus validator using SLH-DSA (SPHINCS+) signatures
//! 
//! SLH-DSA is a stateless hash-based digital signature scheme standardized in NIST FIPS 205.
//! This module replaces ML-DSA-65 with SLH-DSA-128f for block and transaction validation.

use crate::core::slh_dsa::{SlhDsaPublicKey, SlhDsaSignature, SlhDsaVerifier, SecurityLevel};
use crate::core::types::{Block, BlockHeader, Transaction, Hash};
use crate::state::state_manager::StateManager;
use std::collections::HashSet;
use thiserror::Error;

/// SLH-DSA variant configuration
pub const SLH_DSA_VARIANT: SecurityLevel = SecurityLevel::L128Fast;
pub const SLH_DSA_PK_SIZE: usize = 32;  // SLH-DSA-128 public key size
pub const SLH_DSA_SIG_SIZE: usize = 7856; // SLH-DSA-128f signature size (~7.8KB)

#[derive(Error, Debug, Clone)]
pub enum ConsensusError {
    #[error("Invalid block signature")]
    InvalidBlockSignature,
    #[error("Invalid transaction signature")]
    InvalidTransactionSignature,
    #[error("Invalid public key format")]
    InvalidPublicKey,
    #[error("Signature size exceeds maximum allowed")]
    SignatureTooLarge,
    #[error("Unknown validator")]
    UnknownValidator,
    #[error("Block height mismatch")]
    HeightMismatch,
    #[error("Double spending detected")]
    DoubleSpend,
    #[error("State error: {0}")]
    StateError(String),
}

/// Consensus validator responsible for SLH-DSA signature verification
pub struct SlhDsaValidator {
    verifier: SlhDsaVerifier,
    state: StateManager,
    max_sig_size: usize,
}

impl SlhDsaValidator {
    /// Create a new validator with SLH-DSA support
    pub fn new(state: StateManager) -> Self {
        Self {
            verifier: SlhDsaVerifier::new(SLH_DSA_VARIANT),
            state,
            max_sig_size: SLH_DSA_SIG_SIZE,
        }
    }

    /// Validate a complete block including all transactions
    pub fn validate_block(&self, block: &Block) -> Result<(), ConsensusError> {
        // Validate block header signature
        self.validate_block_header(&block.header)?;
        
        // Validate all transactions
        let mut seen_tx = HashSet::new();
        for tx in &block.transactions {
            if !seen_tx.insert(tx.hash()) {
                return Err(ConsensusError::DoubleSpend);
            }
            self.validate_transaction(tx)?;
        }
        
        // Verify merkle root matches
        let computed_root = self.compute_merkle_root(&block.transactions);
        if computed_root != block.header.tx_root {
            return Err(ConsensusError::StateError("Invalid merkle root".to_string()));
        }
        
        Ok(())
    }

    /// Validate block header signature using SLH-DSA
    fn validate_block_header(&self, header: &BlockHeader) -> Result<(), ConsensusError> {
        // Check signature size (SLH-DSA signatures are large)
        if header.signature.len() > self.max_sig_size {
            return Err(ConsensusError::SignatureTooLarge);
        }

        // Reconstruct message: hash of previous block + height + timestamp + tx_root
        let message = self.serialize_header_for_signing(header);
        
        // Get validator public key from state
        let validator_pk = self.state
            .get_validator_key(header.validator_index)
            .ok_or(ConsensusError::UnknownValidator)?;

        // Verify SLH-DSA signature
        let sig = SlhDsaSignature::from_bytes(&header.signature)
            .map_err(|_| ConsensusError::InvalidBlockSignature)?;
            
        let pk = SlhDsaPublicKey::from_bytes(&validator_pk)
            .map_err(|_| ConsensusError::InvalidPublicKey)?;

        self.verifier
            .verify(&message, &sig, &pk)
            .map_err(|_| ConsensusError::InvalidBlockSignature)?;

        Ok(())
    }

    /// Validate individual transaction signature
    pub fn validate_transaction(&self, tx: &Transaction) -> Result<(), ConsensusError> {
        if tx.signature.len() > self.max_sig_size {
            return Err(ConsensusError::SignatureTooLarge);
        }

        // Serialize transaction data (excluding signature)
        let message = tx.serialize_for_signing();
        
        // Get sender public key
        let sender_pk = SlhDsaPublicKey::from_bytes(&tx.sender_pubkey)
            .map_err(|_| ConsensusError::InvalidPublicKey)?;

        let sig = SlhDsaSignature::from_bytes(&tx.signature)
            .map_err(|_| ConsensusError::InvalidTransactionSignature)?;

        self.verifier
            .verify(&message, &sig, &sender_pk)
            .map_err(|_| ConsensusError::InvalidTransactionSignature)?;

        // Verify nonce and balance in state
        self.state.verify_nonce(&tx.sender, tx.nonce)?;
        
        Ok(())
    }

    fn serialize_header_for_signing(&self, header: &BlockHeader) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&header.prev_hash);
        data.extend_from_slice(&header.height.to_be_bytes());
        data.extend_from_slice(&header.timestamp.to_be_bytes());
        data.extend_from_slice(&header.tx_root);
        data
    }

    fn compute_merkle_root(&self, transactions: &[Transaction]) -> Hash {
        // Simplified merkle root computation
        if transactions.is_empty() {
            return [0u8; 32];
        }
        let mut hashes: Vec<_> = transactions.iter().map(|t| t.hash()).collect();
        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in hashes.chunks(2) {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&chunk[0]);
                if chunk.len() > 1 {
                    hasher.update(&chunk[1]);
                } else {
                    hasher.update(&chunk[0]); // Duplicate last if odd
                }
                next_level.push(*hasher.finalize().as_bytes());
            }
            hashes = next_level;
        }
        hashes[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::slh_dsa::{SlhDsaKeypair, SlhDsaSigner};
    use crate