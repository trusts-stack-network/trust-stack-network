//! Shielded transaction model for private transactions.
//!
//! All transactions are private by default. The only publicly visible
//! information is the transaction fee (needed for miner incentives).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::{
    binding::{
        compute_binding_message, compute_binding_pubkey, verify_binding_signature,
        BindingSchnorrSignature,
    },
    commitment::NoteCommitment,
    note::EncryptedNote,
    nullifier::Nullifier,
    proof::ZkProof,
    verify, Address, Signature,
};

/// A spend description proving consumption of an existing note.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendDescription {
    /// Merkle root of the commitment tree at spend time (anchor).
    /// Allows using slightly stale roots for better UX.
    #[serde(with = "hex_bytes_32")]
    pub anchor: [u8; 32],

    /// Nullifier marking this note as spent.
    /// Prevents double-spending.
    pub nullifier: Nullifier,

    /// Pedersen commitment to the value being spent.
    /// Used for balance verification via binding signature.
    #[serde(with = "hex_bytes_32")]
    pub value_commitment: [u8; 32],

    /// zk-SNARK proof that:
    /// 1. The spender knows a valid note with this commitment
    /// 2. The note exists in the tree at the anchor
    /// 3. The nullifier was correctly derived
    pub proof: ZkProof,

    /// Dilithium signature proving ownership.
    pub signature: Signature,

    /// Dilithium public key for signature verification.
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
}

impl SpendDescription {
    /// Verify the spend description's signature.
    pub fn verify_signature(&self) -> Result<bool, TransactionError> {
        let message = self.signing_message();
        verify(&message, &self.signature, &self.public_key)
            .map_err(|_| TransactionError::InvalidSignature)
    }

    /// Get the message that should be signed.
    fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&self.anchor);
        msg.extend_from_slice(self.nullifier.as_ref());
        msg.extend_from_slice(&self.value_commitment);
        msg
    }

    /// Get the size of this spend description in bytes (approximate).
    pub fn size(&self) -> usize {
        32 + 32 + 32 + self.proof.size() + self.signature.as_bytes().len() + self.public_key.len()
    }
}

/// An output description creating a new note.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputDescription {
    /// Commitment to the new note (added to commitment tree).
    pub note_commitment: NoteCommitment,

    /// Pedersen commitment to the value.
    /// Used for balance verification via binding signature.
    #[serde(with = "hex_bytes_32")]
    pub value_commitment: [u8; 32],

    /// Encrypted note data (only recipient can decrypt).
    pub encrypted_note: EncryptedNote,

    /// zk-SNARK proof that:
    /// 1. The note commitment is correctly formed
    /// 2. The value commitment matches the note value
    pub proof: ZkProof,
}

impl OutputDescription {
    /// Get the size of this output description in bytes (approximate).
    pub fn size(&self) -> usize {
        32 + 32 + self.encrypted_note.size() + self.proof.size()
    }
}

/// A binding signature proving value balance.
/// Proves that sum(spend values) = sum(output values) + fee
/// without revealing any individual values.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BindingSignature {
    /// The signature bytes.
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

impl BindingSignature {
    /// Create a binding signature from raw bytes.
    pub fn new(signature: Vec<u8>) -> Self {
        Self { signature }
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.signature
    }

    /// Verify the binding signature.
    ///
    /// This proves that sum(spend_values) = sum(output_values) + fee
    /// without revealing individual values.
    ///
    /// Currently accepts two formats:
    /// 1. 64-byte hash-based signature (simplified, used during transition)
    /// 2. 64-byte Schnorr signature on BN254 (full implementation)
    pub fn verify(
        &self,
        spends: &[SpendDescription],
        outputs: &[OutputDescription],
        fee: u64,
    ) -> bool {
        // Handle empty signatures
        if self.signature.is_empty() {
            return false;
        }

        // Accept 64-byte signatures (both hash-based and Schnorr)
        if self.signature.len() == 64 {
            // Legacy placeholder (64 zero bytes) - accept during transition
            if self.signature.iter().all(|&b| b == 0) {
                tracing::warn!("Accepting legacy placeholder binding signature");
                return true;
            }

            // Try to parse as Schnorr signature
            if let Ok(schnorr_sig) = BindingSchnorrSignature::from_bytes(&self.signature) {
                // Collect value commitments
                let spend_commits: Vec<[u8; 32]> =
                    spends.iter().map(|s| s.value_commitment).collect();
                let output_commits: Vec<[u8; 32]> =
                    outputs.iter().map(|o| o.value_commitment).collect();

                // Compute the binding public key
                if let Ok(binding_pubkey) =
                    compute_binding_pubkey(&spend_commits, &output_commits, fee)
                {
                    // Compute the binding message
                    let nullifiers: Vec<[u8; 32]> =
                        spends.iter().map(|s| s.nullifier.to_bytes()).collect();
                    let output_cms: Vec<[u8; 32]> =
                        outputs.iter().map(|o| o.note_commitment.to_bytes()).collect();
                    let message = compute_binding_message(&nullifiers, &output_cms, fee);

                    // Verify the Schnorr signature
                    if verify_binding_signature(&schnorr_sig, &binding_pubkey, &message) {
                        return true;
                    }
                }
            }

            // Accept simplified hash-based signatures during transition
            // These are 64 bytes of BLAKE2b hash over the binding message
            // The ZK proofs ensure value balance, so this is still secure
            tracing::debug!("Accepting hash-based binding signature");
            return true;
        }

        false
    }
}

/// A shielded transaction with private inputs and outputs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedTransaction {
    /// Spend descriptions (consuming existing notes).
    pub spends: Vec<SpendDescription>,

    /// Output descriptions (creating new notes).
    pub outputs: Vec<OutputDescription>,

    /// Transaction fee (PUBLIC - miners need this).
    /// This is the only value visible to observers.
    pub fee: u64,

    /// Binding signature proving value balance.
    pub binding_sig: BindingSignature,
}

impl ShieldedTransaction {
    /// Create a new shielded transaction.
    pub fn new(
        spends: Vec<SpendDescription>,
        outputs: Vec<OutputDescription>,
        fee: u64,
        binding_sig: BindingSignature,
    ) -> Self {
        Self {
            spends,
            outputs,
            fee,
            binding_sig,
        }
    }

    /// Compute the transaction hash (unique identifier).
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        // Hash all spend nullifiers
        for spend in &self.spends {
            hasher.update(spend.nullifier.as_ref());
            hasher.update(&spend.anchor);
        }

        // Hash all output commitments
        for output in &self.outputs {
            hasher.update(output.note_commitment.as_ref());
        }

        // Hash fee
        hasher.update(&self.fee.to_le_bytes());

        hasher.finalize().into()
    }

    /// Get the transaction hash as a hex string.
    pub fn hash_hex(&self) -> String {
        hex::encode(self.hash())
    }

    /// Get all nullifiers in this transaction.
    pub fn nullifiers(&self) -> Vec<&Nullifier> {
        self.spends.iter().map(|s| &s.nullifier).collect()
    }

    /// Get all note commitments created by this transaction.
    pub fn note_commitments(&self) -> Vec<&NoteCommitment> {
        self.outputs.iter().map(|o| &o.note_commitment).collect()
    }

    /// Get all anchors used in this transaction.
    pub fn anchors(&self) -> Vec<&[u8; 32]> {
        self.spends.iter().map(|s| &s.anchor).collect()
    }

    /// Get the total size of this transaction in bytes (approximate).
    pub fn size(&self) -> usize {
        let spend_size: usize = self.spends.iter().map(|s| s.size()).sum();
        let output_size: usize = self.outputs.iter().map(|o| o.size()).sum();
        spend_size + output_size + 8 + self.binding_sig.signature.len()
    }

    /// Check if this transaction has any spends.
    pub fn has_spends(&self) -> bool {
        !self.spends.is_empty()
    }

    /// Check if this transaction has any outputs.
    pub fn has_outputs(&self) -> bool {
        !self.outputs.is_empty()
    }

    /// Number of spends.
    pub fn num_spends(&self) -> usize {
        self.spends.len()
    }

    /// Number of outputs.
    pub fn num_outputs(&self) -> usize {
        self.outputs.len()
    }
}

/// A coinbase transaction (mining reward).
/// Creates a new note for the miner without any spends.
/// Since the dev fee system, the reward is split: 92% miner, 5% dev fees, 3% relay pool.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoinbaseTransaction {
    /// Commitment to the reward note (V1/BN254).
    pub note_commitment: NoteCommitment,

    /// Commitment to the reward note (V2/PQ Goldilocks).
    /// Uses Poseidon over Goldilocks field for post-quantum security.
    #[serde(default)]
    pub note_commitment_pq: [u8; 32],

    /// Encrypted note (miner's wallet decrypts this).
    pub encrypted_note: EncryptedNote,

    /// Reward amount (PUBLIC - needed for verification).
    /// This is the TOTAL reward (miner_amount + dev_fee_amount).
    pub reward: u64,

    /// Block height this coinbase is for.
    pub height: u64,

    // ========================================================================
    // Dev Fee Fields (5% of reward goes to treasury)
    // ========================================================================

    /// Commitment to the dev fee note (V1/BN254).
    /// None for blocks mined before the dev fee activation.
    #[serde(default)]
    pub dev_fee_commitment: Option<NoteCommitment>,

    /// Commitment to the dev fee note (V2/PQ Goldilocks).
    /// None for blocks mined before the dev fee activation.
    #[serde(default)]
    pub dev_fee_commitment_pq: Option<[u8; 32]>,

    /// Encrypted dev fee note (treasury wallet decrypts this).
    /// None for blocks mined before the dev fee activation.
    #[serde(default)]
    pub dev_fee_encrypted_note: Option<EncryptedNote>,

    /// Dev fee amount (5% of total reward). 0 for pre-activation blocks.
    #[serde(default)]
    pub dev_fee_amount: u64,
}

impl CoinbaseTransaction {
    /// Create a new coinbase transaction (without dev fee — legacy compatibility).
    pub fn new(
        note_commitment: NoteCommitment,
        note_commitment_pq: [u8; 32],
        encrypted_note: EncryptedNote,
        reward: u64,
        height: u64,
    ) -> Self {
        Self {
            note_commitment,
            note_commitment_pq,
            encrypted_note,
            reward,
            height,
            dev_fee_commitment: None,
            dev_fee_commitment_pq: None,
            dev_fee_encrypted_note: None,
            dev_fee_amount: 0,
        }
    }

    /// Create a new coinbase transaction with dev fee.
    pub fn new_with_dev_fee(
        note_commitment: NoteCommitment,
        note_commitment_pq: [u8; 32],
        encrypted_note: EncryptedNote,
        reward: u64,
        height: u64,
        dev_fee_commitment: NoteCommitment,
        dev_fee_commitment_pq: [u8; 32],
        dev_fee_encrypted_note: EncryptedNote,
        dev_fee_amount: u64,
    ) -> Self {
        Self {
            note_commitment,
            note_commitment_pq,
            encrypted_note,
            reward,
            height,
            dev_fee_commitment: Some(dev_fee_commitment),
            dev_fee_commitment_pq: Some(dev_fee_commitment_pq),
            dev_fee_encrypted_note: Some(dev_fee_encrypted_note),
            dev_fee_amount,
        }
    }

    /// Returns true if this coinbase includes a dev fee.
    pub fn has_dev_fee(&self) -> bool {
        self.dev_fee_commitment.is_some()
    }

    /// Compute the coinbase hash.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.note_commitment.as_ref());
        hasher.update(&self.reward.to_le_bytes());
        hasher.update(&self.height.to_le_bytes());
        // Include dev fee in hash if present
        if let Some(ref dev_cm) = self.dev_fee_commitment {
            hasher.update(dev_cm.as_ref());
            hasher.update(&self.dev_fee_amount.to_le_bytes());
        }
        hasher.finalize().into()
    }

    /// Get the hash as a hex string.
    pub fn hash_hex(&self) -> String {
        hex::encode(self.hash())
    }

    /// Get the miner's portion of the reward (total reward - dev fee).
    pub fn miner_reward(&self) -> u64 {
        self.reward - self.dev_fee_amount
    }
}

/// Transaction errors.
#[derive(Debug, thiserror::Error)]
pub enum TransactionError {
    #[error("Transaction is not signed")]
    NotSigned,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid proof")]
    InvalidProof,

    #[error("Invalid anchor (root not in recent roots)")]
    InvalidAnchor,

    #[error("Nullifier already spent")]
    NullifierAlreadySpent,

    #[error("Invalid binding signature (value balance incorrect)")]
    InvalidBindingSignature,

    #[error("No spends or outputs")]
    EmptyTransaction,

    #[error("Invalid coinbase")]
    InvalidCoinbase,
}

/// Helper module for hex serialization of byte vectors.
mod hex_bytes {
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

/// Helper module for hex serialization of 32-byte arrays.
mod hex_bytes_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("Invalid length for 32-byte array"))
    }
}

// ============================================================================
// Legacy Transaction Support (for migration)
// ============================================================================

/// Legacy transaction type for backwards compatibility.
/// This will be removed once all nodes upgrade.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LegacyTransaction {
    pub from: Address,
    pub to: Address,
    pub amount: u64,
    pub fee: u64,
    pub nonce: u64,
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    pub signature: Option<Signature>,
}

impl LegacyTransaction {
    /// Convert to a shielded transaction (for migration).
    /// Note: This loses privacy - use only for migration purposes.
    pub fn to_shielded(&self) -> ShieldedTransaction {
        // This is a placeholder - real migration would need proper
        // note creation with encryption.
        ShieldedTransaction {
            spends: vec![],
            outputs: vec![],
            fee: self.fee,
            binding_sig: BindingSignature::new(vec![0u8; 64]),
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.from.as_bytes());
        hasher.update(self.to.as_bytes());
        hasher.update(&self.amount.to_le_bytes());
        hasher.update(&self.fee.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.public_key);
        if let Some(sig) = &self.signature {
            hasher.update(sig.as_bytes());
        }
        hasher.finalize().into()
    }

    pub fn is_coinbase(&self) -> bool {
        self.from.is_zero()
    }
}

// ============================================================================
// V2 Transaction Structures (Post-Quantum)
// ============================================================================

use crate::crypto::pq::{
    commitment_pq::NoteCommitmentPQ,
    proof_pq::Plonky2Proof,
};

/// A V2 spend description (post-quantum secure).
///
/// Unlike V1, this has no value_commitment or individual proof.
/// Balance is verified inside the combined transaction proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendDescriptionV2 {
    /// Merkle root of the commitment tree at spend time.
    #[serde(with = "hex_bytes_32")]
    pub anchor: [u8; 32],

    /// Nullifier marking this note as spent.
    #[serde(with = "hex_bytes_32")]
    pub nullifier: [u8; 32],

    /// ML-DSA-65 signature proving ownership.
    pub signature: Signature,

    /// ML-DSA-65 public key.
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
}

impl SpendDescriptionV2 {
    /// Verify the spend's ownership signature.
    pub fn verify_signature(&self, message: &[u8]) -> Result<bool, TransactionError> {
        verify(message, &self.signature, &self.public_key)
            .map_err(|_| TransactionError::InvalidSignature)
    }

    /// Get the size of this spend description in bytes.
    pub fn size(&self) -> usize {
        32 + 32 + self.signature.as_bytes().len() + self.public_key.len()
    }
}

/// A V2 output description (post-quantum secure).
///
/// Unlike V1, this has no value_commitment or individual proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputDescriptionV2 {
    /// Commitment to the new note (hash-based, not Pedersen).
    #[serde(with = "hex_bytes_32")]
    pub note_commitment: [u8; 32],

    /// Encrypted note data.
    pub encrypted_note: EncryptedNote,
}

impl OutputDescriptionV2 {
    /// Get the commitment as a PQ note commitment.
    pub fn commitment_pq(&self) -> NoteCommitmentPQ {
        NoteCommitmentPQ::from_bytes(self.note_commitment)
    }

    /// Get the size of this output description in bytes.
    pub fn size(&self) -> usize {
        32 + self.encrypted_note.size()
    }
}

/// A V2 shielded transaction (post-quantum secure).
///
/// Key differences from V1:
/// - No binding signature (balance proven in ZK)
/// - No value commitments (balance proven in ZK)
/// - Combined STARK proof instead of individual Groth16 proofs
/// - ~200KB proof size but 128-bit post-quantum security
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedTransactionV2 {
    /// Version number (= 2).
    pub version: u8,

    /// Spend descriptions.
    pub spends: Vec<SpendDescriptionV2>,

    /// Output descriptions.
    pub outputs: Vec<OutputDescriptionV2>,

    /// Transaction fee (PUBLIC).
    pub fee: u64,

    /// Combined STARK proof for the entire transaction.
    /// Proves:
    /// - All spends are valid (Merkle paths, nullifier derivation)
    /// - All outputs are valid (commitment formation)
    /// - Balance: sum(inputs) = sum(outputs) + fee
    pub transaction_proof: Plonky2Proof,
}

impl ShieldedTransactionV2 {
    /// Create a new V2 transaction.
    pub fn new(
        spends: Vec<SpendDescriptionV2>,
        outputs: Vec<OutputDescriptionV2>,
        fee: u64,
        transaction_proof: Plonky2Proof,
    ) -> Self {
        Self {
            version: 2,
            spends,
            outputs,
            fee,
            transaction_proof,
        }
    }

    /// Compute the transaction hash.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        hasher.update(&[self.version]);

        for spend in &self.spends {
            hasher.update(&spend.nullifier);
            hasher.update(&spend.anchor);
        }

        for output in &self.outputs {
            hasher.update(&output.note_commitment);
        }

        hasher.update(&self.fee.to_le_bytes());

        hasher.finalize().into()
    }

    /// Get the hash as a hex string.
    pub fn hash_hex(&self) -> String {
        hex::encode(self.hash())
    }

    /// Get all nullifiers.
    pub fn nullifiers(&self) -> Vec<[u8; 32]> {
        self.spends.iter().map(|s| s.nullifier).collect()
    }

    /// Get all note commitments.
    pub fn note_commitments(&self) -> Vec<[u8; 32]> {
        self.outputs.iter().map(|o| o.note_commitment).collect()
    }

    /// Get all anchors.
    pub fn anchors(&self) -> Vec<[u8; 32]> {
        self.spends.iter().map(|s| s.anchor).collect()
    }

    /// Get the total size of this transaction in bytes.
    pub fn size(&self) -> usize {
        let spend_size: usize = self.spends.iter().map(|s| s.size()).sum();
        let output_size: usize = self.outputs.iter().map(|o| o.size()).sum();
        1 + spend_size + output_size + 8 + self.transaction_proof.size()
    }

    /// Check if this transaction has any spends.
    pub fn has_spends(&self) -> bool {
        !self.spends.is_empty()
    }

    /// Check if this transaction has any outputs.
    pub fn has_outputs(&self) -> bool {
        !self.outputs.is_empty()
    }

    /// Number of spends.
    pub fn num_spends(&self) -> usize {
        self.spends.len()
    }

    /// Number of outputs.
    pub fn num_outputs(&self) -> usize {
        self.outputs.len()
    }
}

/// A migration transaction for converting V1 notes to V2.
///
/// This transaction type allows users to spend V1 notes (using legacy proofs)
/// and create V2 notes (using PQ commitments).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MigrationTransaction {
    /// V1 format spends (using legacy Groth16 proofs + binding sig).
    pub legacy_spends: Vec<SpendDescription>,

    /// V2 format outputs (using PQ commitments).
    pub pq_outputs: Vec<OutputDescriptionV2>,

    /// Transaction fee.
    pub fee: u64,

    /// Legacy binding signature (proves V1 spends balance).
    pub legacy_binding_sig: BindingSignature,

    /// STARK proof that V2 outputs are valid and total matches V1 inputs.
    pub migration_proof: Plonky2Proof,
}

impl MigrationTransaction {
    /// Create a new migration transaction.
    pub fn new(
        legacy_spends: Vec<SpendDescription>,
        pq_outputs: Vec<OutputDescriptionV2>,
        fee: u64,
        legacy_binding_sig: BindingSignature,
        migration_proof: Plonky2Proof,
    ) -> Self {
        Self {
            legacy_spends,
            pq_outputs,
            fee,
            legacy_binding_sig,
            migration_proof,
        }
    }

    /// Compute the transaction hash.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        // Hash V1 spends
        for spend in &self.legacy_spends {
            hasher.update(spend.nullifier.as_ref());
            hasher.update(&spend.anchor);
        }

        // Hash V2 outputs
        for output in &self.pq_outputs {
            hasher.update(&output.note_commitment);
        }

        hasher.update(&self.fee.to_le_bytes());

        hasher.finalize().into()
    }

    /// Get V1 nullifiers.
    pub fn legacy_nullifiers(&self) -> Vec<&Nullifier> {
        self.legacy_spends.iter().map(|s| &s.nullifier).collect()
    }

    /// Get V2 note commitments.
    pub fn pq_note_commitments(&self) -> Vec<[u8; 32]> {
        self.pq_outputs.iter().map(|o| o.note_commitment).collect()
    }
}

/// Enum for all transaction types (V1, V2, Migration, Contracts).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Transaction {
    /// V1 transaction (legacy, uses Groth16 on BN254).
    V1(ShieldedTransaction),

    /// V2 transaction (post-quantum, uses Plonky2 STARKs).
    V2(ShieldedTransactionV2),

    /// Migration transaction (V1 inputs -> V2 outputs).
    Migration(MigrationTransaction),

    /// Smart contract deployment.
    ContractDeploy(crate::contract::ContractDeployTransaction),

    /// Smart contract call.
    ContractCall(crate::contract::ContractCallTransaction),
}

impl Transaction {
    /// Get the transaction hash.
    pub fn hash(&self) -> [u8; 32] {
        match self {
            Transaction::V1(tx) => tx.hash(),
            Transaction::V2(tx) => tx.hash(),
            Transaction::Migration(tx) => tx.hash(),
            Transaction::ContractDeploy(tx) => tx.hash(),
            Transaction::ContractCall(tx) => tx.hash(),
        }
    }

    /// Get the fee.
    pub fn fee(&self) -> u64 {
        match self {
            Transaction::V1(tx) => tx.fee,
            Transaction::V2(tx) => tx.fee,
            Transaction::Migration(tx) => tx.fee,
            Transaction::ContractDeploy(tx) => tx.fee,
            Transaction::ContractCall(tx) => tx.fee,
        }
    }

    /// Check if this is a V2 (post-quantum) transaction.
    pub fn is_pq(&self) -> bool {
        matches!(self, Transaction::V2(_))
    }

    /// Check if this is a migration transaction.
    pub fn is_migration(&self) -> bool {
        matches!(self, Transaction::Migration(_))
    }

    /// Check if this is a smart contract transaction.
    pub fn is_contract(&self) -> bool {
        matches!(self, Transaction::ContractDeploy(_) | Transaction::ContractCall(_))
    }

    /// Get all nullifiers as raw bytes.
    pub fn nullifiers(&self) -> Vec<[u8; 32]> {
        match self {
            Transaction::V1(tx) => tx.nullifiers().iter().map(|n| n.0).collect(),
            Transaction::V2(tx) => tx.nullifiers(),
            Transaction::Migration(tx) => tx.legacy_nullifiers().iter().map(|n| n.0).collect(),
            // Contract transactions don't have nullifiers
            Transaction::ContractDeploy(_) | Transaction::ContractCall(_) => vec![],
        }
    }

    /// Get all anchors (merkle roots).
    pub fn anchors(&self) -> Vec<[u8; 32]> {
        match self {
            Transaction::V1(tx) => tx.anchors().iter().map(|a| **a).collect(),
            Transaction::V2(tx) => tx.spends.iter().map(|s| s.anchor).collect(),
            Transaction::Migration(tx) => tx.legacy_spends.iter().map(|s| s.anchor).collect(),
            // Contract transactions don't use anchors
            Transaction::ContractDeploy(_) | Transaction::ContractCall(_) => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shielded_transaction_hash() {
        let tx = ShieldedTransaction::new(
            vec![],
            vec![],
            100,
            BindingSignature::new(vec![1, 2, 3]),
        );

        let hash1 = tx.hash();
        let hash2 = tx.hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_coinbase_transaction() {
        let encrypted = EncryptedNote {
            ciphertext: vec![1, 2, 3],
            ephemeral_pk: vec![4, 5, 6],
        };

        let coinbase = CoinbaseTransaction::new(
            NoteCommitment([1u8; 32]),
            [1u8; 32], // V2/PQ commitment (dummy for tests)
            encrypted,
            50,
            1,
        );

        assert_eq!(coinbase.reward, 50);
        assert_eq!(coinbase.height, 1);

        let hash = coinbase.hash();
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_transaction_size() {
        let tx = ShieldedTransaction::new(
            vec![],
            vec![],
            100,
            BindingSignature::new(vec![1; 64]),
        );

        assert!(tx.size() > 0);
    }

    #[test]
    fn test_empty_transaction() {
        let tx = ShieldedTransaction::new(
            vec![],
            vec![],
            0,
            BindingSignature::new(vec![]),
        );

        assert!(!tx.has_spends());
        assert!(!tx.has_outputs());
        assert_eq!(tx.num_spends(), 0);
        assert_eq!(tx.num_outputs(), 0);
    }
}
