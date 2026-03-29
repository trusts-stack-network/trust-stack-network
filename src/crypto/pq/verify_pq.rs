//! Post-quantum transaction verification.
//!
//! This module verifies V2 transactions using:
//! - Plonky2 STARK proofs (quantum-resistant)
//! - ML-DSA-65 signatures (quantum-resistant)
//! - Hash-based commitments (quantum-resistant)

use std::collections::HashSet;

use thiserror::Error;

use crate::crypto::{verify, Signature};

use super::commitment_pq::NoteCommitmentPQ;
use super::merkle_pq::CommitmentTreePQ;
use super::proof_pq::{verify_proof, Plonky2Proof, TransactionPublicInputs};

/// Error type for V2 transaction verification.
#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Invalid STARK proof: {0}")]
    InvalidProof(String),

    #[error("Invalid anchor: root not in recent roots")]
    InvalidAnchor,

    #[error("Double spend detected: nullifier {0} already spent")]
    DoubleSpend(String),

    #[error("Invalid ownership signature for spend {index}")]
    InvalidSignature { index: usize },

    #[error("Journal extraction failed: {0}")]
    JournalError(String),

    #[error("Spend count mismatch: journal has {journal}, transaction has {transaction}")]
    SpendCountMismatch { journal: usize, transaction: usize },

    #[error("Output count mismatch: journal has {journal}, transaction has {transaction}")]
    OutputCountMismatch { journal: usize, transaction: usize },

    #[error("Fee mismatch: journal has {journal}, transaction has {transaction}")]
    FeeMismatch { journal: u64, transaction: u64 },

    #[error("Nullifier mismatch for spend {index}")]
    NullifierMismatch { index: usize },

    #[error("Note commitment mismatch for output {index}")]
    NoteCommitmentMismatch { index: usize },
}

/// A V2 spend description (post-quantum).
///
/// This is a simplified version without value_commitment or individual proof,
/// since balance is proven in the combined transaction proof.
#[derive(Clone, Debug)]
pub struct SpendDescriptionV2 {
    /// Merkle root of the commitment tree at spend time.
    pub anchor: [u8; 32],

    /// Nullifier marking this note as spent.
    pub nullifier: [u8; 32],

    /// ML-DSA-65 signature proving ownership.
    pub signature: Signature,

    /// ML-DSA-65 public key.
    pub public_key: Vec<u8>,
}

/// A V2 output description (post-quantum).
///
/// No value_commitment or individual proof needed.
#[derive(Clone, Debug)]
pub struct OutputDescriptionV2 {
    /// Commitment to the new note.
    pub note_commitment: NoteCommitmentPQ,

    /// Encrypted note data.
    pub encrypted_note: EncryptedNoteV2,
}

/// Encrypted note for V2 transactions.
#[derive(Clone, Debug)]
pub struct EncryptedNoteV2 {
    pub ciphertext: Vec<u8>,
    pub ephemeral_pk: Vec<u8>,
}

/// A V2 shielded transaction (post-quantum).
#[derive(Clone, Debug)]
pub struct ShieldedTransactionV2 {
    /// Version number (= 2).
    pub version: u8,

    /// Spend descriptions.
    pub spends: Vec<SpendDescriptionV2>,

    /// Output descriptions.
    pub outputs: Vec<OutputDescriptionV2>,

    /// Transaction fee (public).
    pub fee: u64,

    /// Combined Plonky2 STARK proof for the entire transaction.
    pub transaction_proof: Plonky2Proof,
}

impl ShieldedTransactionV2 {
    /// Get all nullifiers in this transaction.
    pub fn nullifiers(&self) -> Vec<[u8; 32]> {
        self.spends.iter().map(|s| s.nullifier).collect()
    }

    /// Get all note commitments created by this transaction.
    pub fn note_commitments(&self) -> Vec<NoteCommitmentPQ> {
        self.outputs.iter().map(|o| o.note_commitment).collect()
    }

    /// Get the approximate size of this transaction.
    pub fn size(&self) -> usize {
        let spends_size: usize = self.spends.iter().map(|s| {
            32 + 32 + s.signature.as_bytes().len() + s.public_key.len()
        }).sum();

        let outputs_size: usize = self.outputs.iter().map(|o| {
            32 + o.encrypted_note.ciphertext.len() + o.encrypted_note.ephemeral_pk.len()
        }).sum();

        1 + spends_size + outputs_size + 8 + self.transaction_proof.size()
    }

    /// Get the public inputs extracted from the proof.
    pub fn public_inputs(&self) -> &TransactionPublicInputs {
        &self.transaction_proof.public_inputs
    }
}

/// Verify a V2 transaction.
///
/// This function:
/// 1. Verifies the Plonky2 STARK proof
/// 2. Extracts the public inputs
/// 3. Validates anchors against the commitment tree
/// 4. Checks nullifiers aren't already spent
/// 5. Verifies ML-DSA-65 ownership signatures
pub fn verify_transaction_v2(
    tx: &ShieldedTransactionV2,
    commitment_tree: &CommitmentTreePQ,
    nullifier_set: &HashSet<[u8; 32]>,
) -> Result<(), VerificationError> {
    // 1. Verify Plonky2 proof
    let public_inputs = verify_proof(
        &tx.transaction_proof,
        tx.spends.len(),
        tx.outputs.len(),
    ).map_err(|e| VerificationError::InvalidProof(e.to_string()))?;

    // 2. Validate public inputs match transaction
    validate_public_inputs_match_tx(&public_inputs, tx)?;

    // 3. Validate anchors (merkle roots)
    for root in &public_inputs.merkle_roots {
        if !commitment_tree.is_valid_root(root) {
            return Err(VerificationError::InvalidAnchor);
        }
    }

    // 4. Check nullifiers not already spent
    for nf in &public_inputs.nullifiers {
        if nullifier_set.contains(nf) {
            return Err(VerificationError::DoubleSpend(hex::encode(nf)));
        }
    }

    // 5. Verify ownership signatures
    // The message signed is the nullifier for each spend
    for (i, spend) in tx.spends.iter().enumerate() {
        let message = &public_inputs.nullifiers[i];

        let valid = verify(message, &spend.signature, &spend.public_key)
            .map_err(|_| VerificationError::InvalidSignature { index: i })?;

        if !valid {
            return Err(VerificationError::InvalidSignature { index: i });
        }
    }

    Ok(())
}

/// Validate that the public inputs match the transaction.
fn validate_public_inputs_match_tx(
    public_inputs: &TransactionPublicInputs,
    tx: &ShieldedTransactionV2,
) -> Result<(), VerificationError> {
    // Check spend count
    if public_inputs.nullifiers.len() != tx.spends.len() {
        return Err(VerificationError::SpendCountMismatch {
            journal: public_inputs.nullifiers.len(),
            transaction: tx.spends.len(),
        });
    }

    // Check output count
    if public_inputs.note_commitments.len() != tx.outputs.len() {
        return Err(VerificationError::OutputCountMismatch {
            journal: public_inputs.note_commitments.len(),
            transaction: tx.outputs.len(),
        });
    }

    // Check fee
    if public_inputs.fee != tx.fee {
        return Err(VerificationError::FeeMismatch {
            journal: public_inputs.fee,
            transaction: tx.fee,
        });
    }

    // Check nullifiers match
    for (i, (pi_nf, spend)) in public_inputs.nullifiers.iter().zip(tx.spends.iter()).enumerate() {
        if pi_nf != &spend.nullifier {
            return Err(VerificationError::NullifierMismatch { index: i });
        }
    }

    // Check note commitments match
    for (i, (pi_cm, output)) in public_inputs.note_commitments.iter().zip(tx.outputs.iter()).enumerate() {
        if pi_cm != &output.note_commitment.to_bytes() {
            return Err(VerificationError::NoteCommitmentMismatch { index: i });
        }
    }

    // Check merkle roots match anchors
    for (pi_root, spend) in public_inputs.merkle_roots.iter().zip(tx.spends.iter()) {
        if pi_root != &spend.anchor {
            return Err(VerificationError::InvalidAnchor);
        }
    }

    Ok(())
}

/// Migration transaction for converting V1 notes to V2.
/// Note: The actual MigrationTransaction is defined in crate::core::transaction.
/// Import from crate::core::MigrationTransaction instead.


#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_proof() -> Plonky2Proof {
        Plonky2Proof {
            proof_bytes: vec![0u8; 1024],
            public_inputs: TransactionPublicInputs {
                merkle_roots: vec![[0u8; 32]],
                nullifiers: vec![[1u8; 32]],
                note_commitments: vec![[2u8; 32]],
                fee: 100,
            },
        }
    }

    #[test]
    fn test_transaction_v2_size() {
        let tx = ShieldedTransactionV2 {
            version: 2,
            spends: vec![SpendDescriptionV2 {
                anchor: [0u8; 32],
                nullifier: [1u8; 32],
                signature: Signature::from_bytes(vec![0u8; 3309]),
                public_key: vec![0u8; 1952],
            }],
            outputs: vec![OutputDescriptionV2 {
                note_commitment: NoteCommitmentPQ::from_bytes([2u8; 32]),
                encrypted_note: EncryptedNoteV2 {
                    ciphertext: vec![0u8; 88],
                    ephemeral_pk: vec![0u8; 32],
                },
            }],
            fee: 100,
            transaction_proof: dummy_proof(),
        };

        // Should be > 0 bytes
        assert!(tx.size() > 0);
    }

    #[test]
    fn test_verification_error_display() {
        let err = VerificationError::DoubleSpend("abc123".to_string());
        assert!(err.to_string().contains("abc123"));
    }

    #[test]
    fn test_public_inputs_validation() {
        let public_inputs = TransactionPublicInputs {
            merkle_roots: vec![[0u8; 32]],
            nullifiers: vec![[1u8; 32]],
            note_commitments: vec![[2u8; 32]],
            fee: 100,
        };

        let tx = ShieldedTransactionV2 {
            version: 2,
            spends: vec![SpendDescriptionV2 {
                anchor: [0u8; 32],
                nullifier: [1u8; 32],
                signature: Signature::from_bytes(vec![0u8; 3309]),
                public_key: vec![0u8; 1952],
            }],
            outputs: vec![OutputDescriptionV2 {
                note_commitment: NoteCommitmentPQ::from_bytes([2u8; 32]),
                encrypted_note: EncryptedNoteV2 {
                    ciphertext: vec![0u8; 88],
                    ephemeral_pk: vec![0u8; 32],
                },
            }],
            fee: 100,
            transaction_proof: dummy_proof(),
        };

        // Should match
        assert!(validate_public_inputs_match_tx(&public_inputs, &tx).is_ok());

        // Mismatched fee
        let bad_inputs = TransactionPublicInputs {
            fee: 999,
            ..public_inputs.clone()
        };
        assert!(matches!(
            validate_public_inputs_match_tx(&bad_inputs, &tx),
            Err(VerificationError::FeeMismatch { .. })
        ));
    }
}
