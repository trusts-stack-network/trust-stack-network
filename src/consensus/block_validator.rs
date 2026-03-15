use crate::core::{Block, BlockHeader, Transaction};
use crate::consensus::{SLHDSASignatureValidator, SignatureValidationError};
use crate::consensus::difficulty::{DifficultyAdjuster, validate_difficulty};
use crate::consensus::pow::{validate_proof_of_work, calculate_block_hash};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BlockValidationError {
    #[error("Block signature validation failed: {0}")]
    SignatureError(#[from] SignatureValidationError),
    #[error("Proof of work validation failed")]
    InvalidProofOfWork