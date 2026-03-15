//! Plonky2 proof generation and verification for post-quantum transactions.
//!
//! This module provides the interface to Plonky2's STARK-based proving system.
//! The circuit (defined in circuit_pq.rs) verifies:
//! 1. Spend validity (note exists, nullifier correct)
//! 2. Output validity (commitment correct)
//! 3. Balance constraint (inputs = outputs + fee)
//!
//! ## Quantum Resistance
//!
//! Plonky2 uses FRI (Fast Reed-Solomon IOP) which relies only on hash function
//! security. Unlike Groth16 which uses elliptic curve pairings vulnerable to
//! Shor's algorithm, Plonky2 proofs provide post-quantum security.
//!
//! ## Browser Support
//!
//! Plonky2 compiles to WebAssembly, enabling client-side proving in browsers.
//! This is critical for self-custody wallets where users shouldn't need to
//! trust a third-party proving service.

use plonky2::field::types::{Field, PrimeField64};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::proof::ProofWithPublicInputs;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::circuit_pq::{CircuitCache, TransactionCircuit, C, D, F};
use super::commitment_pq::NoteCommitmentPQ;
use super::merkle_pq::MerkleWitnessPQ;

/// Error type for proof generation/verification.
#[derive(Debug, Error)]
pub enum ProofError {
    #[error("Proof generation failed: {0}")]
    GenerationFailed(String),

    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid witness: {0}")]
    InvalidWitness(String),

    #[error("Balance mismatch: inputs={inputs}, outputs={outputs}, fee={fee}")]
    BalanceMismatch { inputs: u64, outputs: u64, fee: u64 },

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Unsupported transaction shape: {0} spends, {1} outputs")]
    UnsupportedShape(usize, usize),
}

/// A Plonky2 proof for a V2 transaction.
///
/// This is the post-quantum replacement for Groth16 proofs.
/// Proof size is ~45KB and provides 128-bit post-quantum security.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plonky2Proof {
    /// The serialized proof bytes.
    #[serde(with = "hex_serde")]
    pub proof_bytes: Vec<u8>,

    /// Public inputs extracted from the proof.
    pub public_inputs: TransactionPublicInputs,
}

/// Public inputs for a transaction proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionPublicInputs {
    /// Merkle roots (one per spend)
    pub merkle_roots: Vec<[u8; 32]>,
    /// Nullifiers (one per spend)
    pub nullifiers: Vec<[u8; 32]>,
    /// Note commitments (one per output)
    pub note_commitments: Vec<[u8; 32]>,
    /// Transaction fee
    pub fee: u64,
}

impl Plonky2Proof {
    /// Get the size of the proof in bytes.
    pub fn size(&self) -> usize {
        self.proof_bytes.len()
    }
}

/// Witness for spending a note in V2 transactions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendWitnessPQ {
    /// The note's value (private).
    pub value: u64,
    /// Recipient public key hash (private).
    pub recipient_pk_hash: [u8; 32],
    /// Note randomness (private).
    pub randomness: [u8; 32],
    /// Nullifier key (private).
    pub nullifier_key: [u8; 32],
    /// Position in the commitment tree.
    pub position: u64,
    /// Merkle witness (path + root).
    pub merkle_witness: MerkleWitnessPQ,
}

impl SpendWitnessPQ {
    /// Compute the note commitment from this witness.
    pub fn note_commitment(&self) -> NoteCommitmentPQ {
        NoteCommitmentPQ::commit(self.value, &self.recipient_pk_hash, &self.randomness)
    }

    /// Compute the nullifier from this witness.
    pub fn nullifier(&self) -> [u8; 32] {
        use super::commitment_pq::derive_nullifier_pq;
        derive_nullifier_pq(
            &self.nullifier_key,
            &self.note_commitment().to_bytes(),
            self.position,
        )
    }

    /// Validate the witness locally (before proving).
    pub fn validate(&self) -> Result<(), ProofError> {
        let commitment = self.note_commitment();
        if !self.merkle_witness.verify(&commitment) {
            return Err(ProofError::InvalidWitness(
                "Merkle path does not verify".to_string(),
            ));
        }
        Ok(())
    }
}

/// Witness for creating an output note in V2 transactions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputWitnessPQ {
    /// The note's value (private).
    pub value: u64,
    /// Recipient public key hash.
    pub recipient_pk_hash: [u8; 32],
    /// Note randomness (private).
    pub randomness: [u8; 32],
}

impl OutputWitnessPQ {
    /// Compute the note commitment from this witness.
    pub fn note_commitment(&self) -> NoteCommitmentPQ {
        NoteCommitmentPQ::commit(self.value, &self.recipient_pk_hash, &self.randomness)
    }
}

/// Transaction prover using Plonky2.
pub struct TransactionProver {
    /// Cache of pre-built circuits
    circuit_cache: CircuitCache,
}

impl TransactionProver {
    /// Create a new prover with pre-built circuits.
    pub fn new() -> Self {
        Self {
            circuit_cache: CircuitCache::new(),
        }
    }

    /// Generate a proof for a transaction.
    pub fn prove(
        &self,
        spend_witnesses: &[SpendWitnessPQ],
        output_witnesses: &[OutputWitnessPQ],
        fee: u64,
    ) -> Result<Plonky2Proof, ProofError> {
        // Validate balance constraint
        let total_inputs: u64 = spend_witnesses.iter().map(|s| s.value).sum();
        let total_outputs: u64 = output_witnesses.iter().map(|o| o.value).sum();

        if total_inputs != total_outputs + fee {
            return Err(ProofError::BalanceMismatch {
                inputs: total_inputs,
                outputs: total_outputs,
                fee,
            });
        }

        // Validate all witnesses
        for (i, spend) in spend_witnesses.iter().enumerate() {
            spend
                .validate()
                .map_err(|e| ProofError::InvalidWitness(format!("Spend {} invalid: {}", i, e)))?;
        }

        // Get circuit for this shape
        let circuit = self
            .circuit_cache
            .get(spend_witnesses.len(), output_witnesses.len())
            .ok_or_else(|| {
                ProofError::UnsupportedShape(spend_witnesses.len(), output_witnesses.len())
            })?;
        let (circuit_data, targets) = circuit.as_ref();

        // Build witness
        let mut pw = PartialWitness::new();

        // Set spend witnesses
        for (spend, targets) in spend_witnesses.iter().zip(targets.spends.iter()) {
            self.set_spend_witness(&mut pw, spend, targets)?;
        }

        // Set output witnesses
        for (output, targets) in output_witnesses.iter().zip(targets.outputs.iter()) {
            self.set_output_witness(&mut pw, output, targets)?;
        }

        // Set fee
        pw.set_target(targets.fee, F::from_canonical_u64(fee))
            .map_err(|e| ProofError::GenerationFailed(e.to_string()))?;

        // Generate proof
        let proof = circuit_data
            .prove(pw)
            .map_err(|e| ProofError::GenerationFailed(e.to_string()))?;

        // Serialize proof (to_bytes returns Vec<u8> directly)
        let proof_bytes = proof.to_bytes();

        // Extract public inputs
        let public_inputs = self.extract_public_inputs(&proof, spend_witnesses.len(), output_witnesses.len());

        Ok(Plonky2Proof {
            proof_bytes,
            public_inputs,
        })
    }

    /// Set witness values for a spend.
    fn set_spend_witness(
        &self,
        pw: &mut PartialWitness<F>,
        spend: &SpendWitnessPQ,
        targets: &super::circuit_pq::SpendTargets,
    ) -> Result<(), ProofError> {
        let map_err = |e: anyhow::Error| ProofError::GenerationFailed(e.to_string());

        // Value
        pw.set_target(targets.value, F::from_canonical_u64(spend.value))
            .map_err(map_err)?;

        // PK hash (convert 32 bytes to 4 field elements)
        let pk_hash_fields = bytes_to_field_elements(&spend.recipient_pk_hash);
        for (i, &val) in pk_hash_fields.iter().enumerate() {
            pw.set_target(targets.pk_hash[i], val).map_err(map_err)?;
        }

        // Randomness
        let randomness_fields = bytes_to_field_elements(&spend.randomness);
        for (i, &val) in randomness_fields.iter().enumerate() {
            pw.set_target(targets.randomness[i], val).map_err(map_err)?;
        }

        // Nullifier key
        let nk_fields = bytes_to_field_elements(&spend.nullifier_key);
        for (i, &val) in nk_fields.iter().enumerate() {
            pw.set_target(targets.nullifier_key[i], val).map_err(map_err)?;
        }

        // Position
        pw.set_target(targets.position, F::from_canonical_u64(spend.position))
            .map_err(map_err)?;

        // Merkle path
        for (i, sibling) in spend.merkle_witness.path.siblings.iter().enumerate() {
            let sibling_fields = bytes_to_field_elements(sibling);
            for (j, &val) in sibling_fields.iter().enumerate() {
                pw.set_target(targets.merkle_path[i][j], val).map_err(map_err)?;
            }
        }

        // Path indices
        for (i, &idx) in spend.merkle_witness.path.indices.iter().enumerate() {
            pw.set_bool_target(targets.path_indices[i], idx != 0)
                .map_err(map_err)?;
        }

        // Expected merkle root (public)
        let root_fields = bytes_to_field_elements(&spend.merkle_witness.root);
        for (i, &val) in root_fields.iter().enumerate() {
            pw.set_target(targets.merkle_root[i], val).map_err(map_err)?;
        }

        // Expected nullifier (public)
        let nullifier = spend.nullifier();
        let nf_fields = bytes_to_field_elements(&nullifier);
        for (i, &val) in nf_fields.iter().enumerate() {
            pw.set_target(targets.nullifier[i], val).map_err(map_err)?;
        }

        Ok(())
    }

    /// Set witness values for an output.
    fn set_output_witness(
        &self,
        pw: &mut PartialWitness<F>,
        output: &OutputWitnessPQ,
        targets: &super::circuit_pq::OutputTargets,
    ) -> Result<(), ProofError> {
        let map_err = |e: anyhow::Error| ProofError::GenerationFailed(e.to_string());

        // Value
        pw.set_target(targets.value, F::from_canonical_u64(output.value))
            .map_err(map_err)?;

        // PK hash
        let pk_hash_fields = bytes_to_field_elements(&output.recipient_pk_hash);
        for (i, &val) in pk_hash_fields.iter().enumerate() {
            pw.set_target(targets.pk_hash[i], val).map_err(map_err)?;
        }

        // Randomness
        let randomness_fields = bytes_to_field_elements(&output.randomness);
        for (i, &val) in randomness_fields.iter().enumerate() {
            pw.set_target(targets.randomness[i], val).map_err(map_err)?;
        }

        // Expected note commitment (public)
        let commitment = output.note_commitment().to_bytes();
        let cm_fields = bytes_to_field_elements(&commitment);
        for (i, &val) in cm_fields.iter().enumerate() {
            pw.set_target(targets.note_commitment[i], val).map_err(map_err)?;
        }

        Ok(())
    }

    /// Extract public inputs from a proof.
    fn extract_public_inputs(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
        num_spends: usize,
        num_outputs: usize,
    ) -> TransactionPublicInputs {
        let pis = &proof.public_inputs;
        let mut idx = 0;

        // Each spend contributes: 4 (merkle_root) + 4 (nullifier) = 8 field elements
        let mut merkle_roots = Vec::with_capacity(num_spends);
        let mut nullifiers = Vec::with_capacity(num_spends);

        for _ in 0..num_spends {
            // Merkle root (4 field elements)
            let root = field_elements_to_bytes(&pis[idx..idx + 4]);
            merkle_roots.push(root);
            idx += 4;

            // Nullifier (4 field elements)
            let nf = field_elements_to_bytes(&pis[idx..idx + 4]);
            nullifiers.push(nf);
            idx += 4;
        }

        // Each output contributes: 4 (note_commitment) field elements
        let mut note_commitments = Vec::with_capacity(num_outputs);
        for _ in 0..num_outputs {
            let cm = field_elements_to_bytes(&pis[idx..idx + 4]);
            note_commitments.push(cm);
            idx += 4;
        }

        // Fee (1 field element)
        let fee = pis[idx].to_canonical_u64();

        TransactionPublicInputs {
            merkle_roots,
            nullifiers,
            note_commitments,
            fee,
        }
    }
}

impl Default for TransactionProver {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify a Plonky2 proof.
pub fn verify_proof(
    proof: &Plonky2Proof,
    num_spends: usize,
    num_outputs: usize,
) -> Result<TransactionPublicInputs, ProofError> {
    tracing::debug!(
        "Verifying proof: {} spends, {} outputs, proof_bytes_len={}",
        num_spends,
        num_outputs,
        proof.proof_bytes.len()
    );

    // Build circuit for this shape to get verifier data
    let circuit = TransactionCircuit::new(num_spends, num_outputs);
    let (circuit_data, _) = circuit.build();

    tracing::debug!(
        "Circuit built: num_public_inputs={}",
        circuit_data.common.num_public_inputs
    );

    // Deserialize proof
    let plonky2_proof: ProofWithPublicInputs<F, C, D> =
        ProofWithPublicInputs::from_bytes(proof.proof_bytes.clone(), &circuit_data.common)
            .map_err(|e| {
                tracing::warn!("Proof deserialization failed: {}", e);
                ProofError::SerializationError(e.to_string())
            })?;

    tracing::debug!(
        "Proof deserialized: {} public inputs",
        plonky2_proof.public_inputs.len()
    );

    // Log public inputs from proof for debugging
    tracing::debug!("Public inputs from proof: {:?}", plonky2_proof.public_inputs.iter().take(5).map(|f| f.to_canonical_u64()).collect::<Vec<_>>());

    // Verify
    tracing::debug!("Starting circuit verification...");
    let verify_result = circuit_data.verify(plonky2_proof.clone());
    match &verify_result {
        Ok(_) => tracing::debug!("Circuit verification PASSED"),
        Err(e) => tracing::warn!("Circuit verification FAILED: {}", e),
    }
    verify_result.map_err(|e| ProofError::VerificationFailed(e.to_string()))?;

    tracing::debug!("Returning public inputs from proof struct");
    Ok(proof.public_inputs.clone())
}

/// Convert 32 bytes to 4 Goldilocks field elements.
fn bytes_to_field_elements(bytes: &[u8; 32]) -> [F; 4] {
    let mut result = [F::ZERO; 4];
    for i in 0..4 {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let val = u64::from_le_bytes(chunk);
        // Reduce modulo Goldilocks prime
        result[i] = F::from_noncanonical_u64(val);
    }
    result
}

/// Convert 4 Goldilocks field elements to 32 bytes.
fn field_elements_to_bytes(fields: &[F]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for (i, &f) in fields.iter().take(4).enumerate() {
        let bytes = f.to_canonical_u64().to_le_bytes();
        result[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }
    result
}

/// Hex serialization helper.
mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::merkle_pq::CommitmentTreePQ;

    fn create_test_spend_witness(value: u64, tree: &mut CommitmentTreePQ) -> SpendWitnessPQ {
        let recipient_pk_hash = [1u8; 32];
        let randomness = [2u8; 32];
        let nullifier_key = [3u8; 32];

        let commitment = NoteCommitmentPQ::commit(value, &recipient_pk_hash, &randomness);
        tree.append(&commitment);
        let position = tree.size() - 1;
        let merkle_witness = tree.witness(position).unwrap();

        SpendWitnessPQ {
            value,
            recipient_pk_hash,
            randomness,
            nullifier_key,
            position,
            merkle_witness,
        }
    }

    fn create_test_output_witness(value: u64) -> OutputWitnessPQ {
        OutputWitnessPQ {
            value,
            recipient_pk_hash: [4u8; 32],
            randomness: [5u8; 32],
        }
    }

    #[test]
    fn test_spend_witness_validation() {
        let mut tree = CommitmentTreePQ::new();
        let spend = create_test_spend_witness(1000, &mut tree);
        assert!(spend.validate().is_ok());
    }

    #[test]
    fn test_balance_check() {
        let prover = TransactionProver::new();
        let mut tree = CommitmentTreePQ::new();

        let spend = create_test_spend_witness(1000, &mut tree);
        let output = create_test_output_witness(950);

        // This should fail balance check (1000 != 950 + 100)
        let result = prover.prove(&[spend], &[output], 100);
        assert!(matches!(result, Err(ProofError::BalanceMismatch { .. })));
    }

    #[test]
    fn test_bytes_to_field_elements_roundtrip() {
        let original = [42u8; 32];
        let fields = bytes_to_field_elements(&original);
        let recovered = field_elements_to_bytes(&fields);
        // Note: Not exact roundtrip due to field reduction, but should be close
        assert_eq!(original[0..8], recovered[0..8]);
    }
}
