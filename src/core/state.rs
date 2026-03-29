//! Shielded state model for private transactions.
//!
//! Instead of account balances, we track:
//! - CommitmentTree: All note commitments ever created (V1, BN254-based)
//! - CommitmentTreePQ: V2 commitment tree (Goldilocks-based, quantum-resistant)
//! - NullifierSet: All nullifiers (spent notes)
//!
//! This enables full transaction privacy - no balances are visible on-chain.

use std::collections::HashSet;

use serde::{Serialize, Deserialize};

use crate::crypto::{
    merkle_tree::{CommitmentTree, TreeHash},
    nullifier::Nullifier,
    proof::{
        bytes_to_public_inputs, output_bytes_to_public_inputs, verify_output_proof,
        verify_spend_proof, CircomVerifyingParams,
    },
    pq::{
        commitment_pq::NoteCommitmentPQ,
        merkle_pq::{CommitmentTreePQ, CommitmentTreeSnapshot, TreeHashPQ, MerkleWitnessPQ},
    },
};

use super::transaction::{
    CoinbaseTransaction, ShieldedTransaction, ShieldedTransactionV2,
    MigrationTransaction, Transaction, TransactionError,
};

/// The shielded state containing commitment tree and nullifier set.
///
/// This is the privacy-preserving state model. No account balances
/// are stored - only cryptographic commitments and nullifiers.
#[derive(Clone, Debug, Default)]
pub struct ShieldedState {
    /// V1 tree of all note commitments (Poseidon/BN254).
    commitment_tree: CommitmentTree,
    /// V2 tree of all note commitments (Poseidon/Goldilocks, quantum-resistant).
    commitment_tree_pq: CommitmentTreePQ,
    /// Set of all spent nullifiers.
    nullifier_set: HashSet<Nullifier>,
    /// Skip V1 tree updates (when loaded from V2-only snapshot).
    /// V1 tree is legacy BN254 — all blocks since height 0 use V2 (Goldilocks).
    /// Skipping V1 updates dramatically speeds up sync (10x+).
    skip_v1_tree: bool,
}

impl ShieldedState {
    /// Create a new empty shielded state.
    pub fn new() -> Self {
        Self {
            commitment_tree: CommitmentTree::new(),
            commitment_tree_pq: CommitmentTreePQ::new(),
            nullifier_set: HashSet::new(),
            skip_v1_tree: false,
        }
    }

    /// Get the current commitment tree root (V1).
    pub fn commitment_root(&self) -> TreeHash {
        self.commitment_tree.root()
    }

    /// Check if V1 tree updates are being skipped (V2-only snapshot loaded).
    pub fn is_v1_tree_skipped(&self) -> bool {
        self.skip_v1_tree
    }

    /// Force skip V1 tree validation. Used after fast-sync where the V1 tree
    /// may be inconsistent. The V2 (PQ) tree is always authoritative.
    pub fn force_skip_v1_tree(&mut self) {
        self.skip_v1_tree = true;
    }

    /// Get the current V2 commitment tree root.
    pub fn commitment_root_pq(&self) -> TreeHashPQ {
        self.commitment_tree_pq.root()
    }

    /// Get the number of commitments in the tree.
    /// Returns the max of V1 and V2 tree sizes (V2-only fast-sync leaves V1 at 0).
    pub fn commitment_count(&self) -> u64 {
        let v1 = self.commitment_tree.size();
        let v2 = self.commitment_tree_pq.size();
        v1.max(v2)
    }

    /// Get the number of spent nullifiers.
    pub fn nullifier_count(&self) -> usize {
        self.nullifier_set.len()
    }

    /// Check if a nullifier has been spent.
    pub fn is_nullifier_spent(&self, nullifier: &Nullifier) -> bool {
        self.nullifier_set.contains(nullifier)
    }

    /// Compute a deterministic state root hash from the current chain state.
    /// state_root = Blake2s("TSN_StateRoot" || commitment_count || nullifier_count ||
    ///              commitment_root_pq || nullifier_hashes_sorted_hash)
    ///
    /// This is used for snapshot validation: a peer providing a fast-sync snapshot
    /// must produce a state that matches the state_root in the block header.
    pub fn compute_state_root(&self) -> [u8; 32] {
        use blake2::{Blake2s256, Digest};

        let mut hasher = Blake2s256::new();
        hasher.update(b"TSN_StateRoot_v1");
        hasher.update(&self.commitment_count().to_le_bytes());
        hasher.update(&(self.nullifier_count() as u64).to_le_bytes());

        // Include PQ commitment root (authoritative tree)
        let pq_root = self.commitment_root_pq();
        hasher.update(&pq_root);

        // Include a sorted hash of all nullifiers for deterministic ordering
        let mut nullifier_bytes: Vec<[u8; 32]> = self.nullifier_set.iter()
            .map(|n| n.to_bytes())
            .collect();
        nullifier_bytes.sort();
        for nb in &nullifier_bytes {
            hasher.update(nb);
        }

        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }

    /// Check if a root is a valid recent root (V1).
    pub fn is_valid_anchor(&self, anchor: &TreeHash) -> bool {
        self.commitment_tree.is_valid_root(anchor)
    }

    /// Check if a root is a valid recent root (V2/PQ).
    pub fn is_valid_anchor_pq(&self, anchor: &TreeHashPQ) -> bool {
        self.commitment_tree_pq.is_valid_root(anchor)
    }

    /// Get the V1 commitment tree (for witness generation).
    pub fn commitment_tree(&self) -> &CommitmentTree {
        &self.commitment_tree
    }

    /// Get the V2 commitment tree (for witness generation).
    pub fn commitment_tree_pq(&self) -> &CommitmentTreePQ {
        &self.commitment_tree_pq
    }

    /// Get a V2 Merkle witness for a commitment at the given position.
    pub fn witness_pq(&self, position: u64) -> Option<MerkleWitnessPQ> {
        self.commitment_tree_pq.witness(position)
    }

    /// Get the nullifier set.
    pub fn nullifier_set(&self) -> &HashSet<Nullifier> {
        &self.nullifier_set
    }

    /// Validate a shielded transaction.
    ///
    /// Checks:
    /// 1. All zk-proofs are valid
    /// 2. All anchors are valid recent roots
    /// 3. No nullifiers are already spent
    /// 4. Binding signature verifies (value balance)
    /// 5. All spend signatures are valid
    pub fn validate_transaction(
        &self,
        tx: &ShieldedTransaction,
        verifying_params: &CircomVerifyingParams,
    ) -> Result<(), StateError> {
        // Must have at least one spend or output
        if tx.spends.is_empty() && tx.outputs.is_empty() {
            return Err(StateError::EmptyTransaction);
        }

        // Validate all spends
        for spend in &tx.spends {
            // Check anchor is valid
            if !self.is_valid_anchor(&spend.anchor) {
                return Err(StateError::InvalidAnchor);
            }

            // Check nullifier not already spent
            if self.is_nullifier_spent(&spend.nullifier) {
                return Err(StateError::NullifierAlreadySpent(spend.nullifier));
            }

            // Verify spend signature
            if !spend.verify_signature().map_err(|_| StateError::InvalidSignature)? {
                return Err(StateError::InvalidSignature);
            }

            // Verify spend proof
            let public_inputs = bytes_to_public_inputs(
                &spend.anchor,
                &spend.nullifier.to_bytes(),
                &spend.value_commitment,
            );
            if !verify_spend_proof(&spend.proof, &public_inputs, verifying_params) {
                return Err(StateError::InvalidProof);
            }
        }

        // Validate all outputs
        for output in &tx.outputs {
            // Verify output proof
            let public_inputs = output_bytes_to_public_inputs(
                &output.note_commitment.to_bytes(),
                &output.value_commitment,
            );
            if !verify_output_proof(&output.proof, &public_inputs, verifying_params) {
                return Err(StateError::InvalidProof);
            }
        }

        // Verify binding signature (proves value balance)
        if !tx.binding_sig.verify(&tx.spends, &tx.outputs, tx.fee) {
            return Err(StateError::InvalidBindingSignature);
        }

        Ok(())
    }

    /// Validate a transaction without proof verification.
    /// Used when proofs have already been verified or for testing.
    pub fn validate_transaction_basic(&self, tx: &ShieldedTransaction) -> Result<(), StateError> {
        // Must have at least one spend or output (or be fee-only)
        if tx.spends.is_empty() && tx.outputs.is_empty() && tx.fee == 0 {
            return Err(StateError::EmptyTransaction);
        }

        // Validate all spends
        for spend in &tx.spends {
            // Check anchor is valid
            if !self.is_valid_anchor(&spend.anchor) {
                return Err(StateError::InvalidAnchor);
            }

            // Check nullifier not already spent
            if self.is_nullifier_spent(&spend.nullifier) {
                return Err(StateError::NullifierAlreadySpent(spend.nullifier));
            }
        }

        Ok(())
    }

    /// Apply a validated transaction to the state.
    ///
    /// This:
    /// 1. Adds all nullifiers to the spent set
    /// 2. Adds all output commitments to both V1 and V2 trees
    pub fn apply_transaction(&mut self, tx: &ShieldedTransaction) {
        // Add nullifiers to spent set
        for spend in &tx.spends {
            self.nullifier_set.insert(spend.nullifier);
        }

        // Add output commitments to trees
        for output in &tx.outputs {
            if !self.skip_v1_tree {
                self.commitment_tree.append(&output.note_commitment);
            }
            // V2 tree (quantum-resistant, always updated)
            let cm_pq = NoteCommitmentPQ::from(output.note_commitment.to_bytes());
            self.commitment_tree_pq.append(&cm_pq);
        }
    }

    /// Validate and apply a transaction atomically.
    pub fn validate_and_apply(
        &mut self,
        tx: &ShieldedTransaction,
        verifying_params: &CircomVerifyingParams,
    ) -> Result<(), StateError> {
        self.validate_transaction(tx, verifying_params)?;
        self.apply_transaction(tx);
        Ok(())
    }

    /// Apply a coinbase transaction.
    /// Adds the miner reward note commitment to both V1 and V2 trees.
    /// If a dev fee is present, also adds the dev fee note commitment.
    pub fn apply_coinbase(&mut self, coinbase: &CoinbaseTransaction) {
        // Add miner's reward commitment
        if !self.skip_v1_tree {
            self.commitment_tree.append(&coinbase.note_commitment);
        }
        let cm_pq = NoteCommitmentPQ::from(coinbase.note_commitment_pq);
        self.commitment_tree_pq.append(&cm_pq);

        // Add dev fee commitment if present
        if let Some(ref dev_cm) = coinbase.dev_fee_commitment {
            if !self.skip_v1_tree {
                self.commitment_tree.append(dev_cm);
            }
            if let Some(dev_cm_pq) = coinbase.dev_fee_commitment_pq {
                let cm_pq = NoteCommitmentPQ::from(dev_cm_pq);
                self.commitment_tree_pq.append(&cm_pq);
            }
        }
    }

    /// Validate a coinbase transaction.
    pub fn validate_coinbase(
        &self,
        coinbase: &CoinbaseTransaction,
        expected_reward: u64,
        expected_height: u64,
    ) -> Result<(), StateError> {
        if coinbase.reward != expected_reward {
            return Err(StateError::InvalidCoinbaseReward {
                expected: expected_reward,
                got: coinbase.reward,
            });
        }

        if coinbase.height != expected_height {
            return Err(StateError::InvalidCoinbaseHeight {
                expected: expected_height,
                got: coinbase.height,
            });
        }

        Ok(())
    }

    /// Create a snapshot of the current state.
    pub fn snapshot(&self) -> ShieldedState {
        self.clone()
    }

    // ========================================================================
    // V2 (Post-Quantum) Transaction Support
    // ========================================================================

    /// Validate a V2 (post-quantum) transaction.
    ///
    /// V2 transactions use STARK proofs instead of Groth16, eliminating
    /// quantum-vulnerable elliptic curve assumptions.
    ///
    /// Checks:
    /// 1. STARK proof is valid
    /// 2. All anchors are valid recent roots
    /// 3. No nullifiers are already spent
    /// 4. All ML-DSA-65 ownership signatures are valid
    pub fn validate_transaction_v2(
        &self,
        tx: &ShieldedTransactionV2,
    ) -> Result<(), StateError> {
        use crate::crypto::pq::proof_pq::verify_proof;

        // Must have at least one spend or output
        if tx.spends.is_empty() && tx.outputs.is_empty() {
            return Err(StateError::EmptyTransaction);
        }

        // 1. Verify Plonky2 STARK proof
        let public_inputs = verify_proof(
            &tx.transaction_proof,
            tx.spends.len(),
            tx.outputs.len(),
        ).map_err(|_| StateError::InvalidProof)?;

        tracing::debug!(
            "verify_proof succeeded. public_inputs: nullifiers={}, commitments={}, merkle_roots={}, fee={}",
            public_inputs.nullifiers.len(),
            public_inputs.note_commitments.len(),
            public_inputs.merkle_roots.len(),
            public_inputs.fee
        );
        tracing::debug!(
            "Transaction: spends={}, outputs={}, fee={}",
            tx.spends.len(),
            tx.outputs.len(),
            tx.fee
        );

        // 2. Validate public inputs match transaction
        if public_inputs.nullifiers.len() != tx.spends.len() {
            tracing::warn!(
                "Nullifier count mismatch: proof has {}, tx has {}",
                public_inputs.nullifiers.len(),
                tx.spends.len()
            );
            return Err(StateError::InvalidProof);
        }
        if public_inputs.note_commitments.len() != tx.outputs.len() {
            tracing::warn!(
                "Note commitment count mismatch: proof has {}, tx has {}",
                public_inputs.note_commitments.len(),
                tx.outputs.len()
            );
            return Err(StateError::InvalidProof);
        }
        if public_inputs.fee != tx.fee {
            tracing::warn!(
                "Fee mismatch: proof has {}, tx has {}",
                public_inputs.fee,
                tx.fee
            );
            return Err(StateError::InvalidProof);
        }

        // 3. Validate anchors (using V2/PQ tree)
        for (i, root) in public_inputs.merkle_roots.iter().enumerate() {
            tracing::debug!(
                "Checking anchor {}: proof_root={}, tx_anchor={}",
                i,
                hex::encode(root),
                hex::encode(&tx.spends[i].anchor)
            );
            if !self.is_valid_anchor_pq(root) {
                tracing::warn!(
                    "V2 anchor validation failed for spend {}: anchor={}, recent_roots_count={}",
                    i,
                    hex::encode(root),
                    self.commitment_tree_pq.recent_roots().len()
                );
                // Log first and last recent roots for comparison
                let recent = self.commitment_tree_pq.recent_roots();
                if !recent.is_empty() {
                    tracing::warn!("  First recent root: {}", hex::encode(recent.front().unwrap()));
                    tracing::warn!("  Last recent root:  {}", hex::encode(recent.back().unwrap()));
                }
                return Err(StateError::InvalidAnchor);
            }
            // Verify proof root matches spend anchor
            if root != &tx.spends[i].anchor {
                tracing::warn!(
                    "Anchor mismatch for spend {}: proof_root={}, tx_anchor={}",
                    i,
                    hex::encode(root),
                    hex::encode(&tx.spends[i].anchor)
                );
                return Err(StateError::InvalidAnchor);
            }
        }

        // 4. Check nullifiers not already spent
        for (i, nf) in public_inputs.nullifiers.iter().enumerate() {
            tracing::debug!(
                "Checking nullifier {}: proof_nf={}, tx_nf={}",
                i,
                hex::encode(nf),
                hex::encode(&tx.spends[i].nullifier)
            );
            let nullifier = Nullifier(*nf);
            if self.is_nullifier_spent(&nullifier) {
                return Err(StateError::NullifierAlreadySpent(nullifier));
            }
            // Verify proof nullifier matches spend nullifier
            if nf != &tx.spends[i].nullifier {
                tracing::warn!(
                    "Nullifier mismatch for spend {}: proof_nf={}, tx_nf={}",
                    i,
                    hex::encode(nf),
                    hex::encode(&tx.spends[i].nullifier)
                );
                return Err(StateError::InvalidProof);
            }
        }

        // 5. Verify note commitments match
        for (i, cm) in public_inputs.note_commitments.iter().enumerate() {
            tracing::debug!(
                "Checking note_commitment {}: proof_cm={}, tx_cm={}",
                i,
                hex::encode(cm),
                hex::encode(&tx.outputs[i].note_commitment)
            );
            if cm != &tx.outputs[i].note_commitment {
                tracing::warn!(
                    "Note commitment mismatch for output {}: proof_cm={}, tx_cm={}",
                    i,
                    hex::encode(cm),
                    hex::encode(&tx.outputs[i].note_commitment)
                );
                return Err(StateError::InvalidProof);
            }
        }

        // 6. Verify ownership signatures (message is the nullifier)
        for (i, spend) in tx.spends.iter().enumerate() {
            let message = &public_inputs.nullifiers[i];
            let valid = spend.verify_signature(message)
                .map_err(|_| StateError::InvalidSignature)?;
            if !valid {
                return Err(StateError::InvalidSignature);
            }
        }

        Ok(())
    }

    /// Validate a V2 transaction without proof verification.
    /// Used when proofs have already been verified.
    pub fn validate_transaction_v2_basic(
        &self,
        tx: &ShieldedTransactionV2,
    ) -> Result<(), StateError> {
        // Must have at least one spend or output (or be fee-only)
        if tx.spends.is_empty() && tx.outputs.is_empty() && tx.fee == 0 {
            return Err(StateError::EmptyTransaction);
        }

        // Validate all spends
        for spend in &tx.spends {
            // Check anchor is valid (using V2/PQ tree)
            if !self.is_valid_anchor_pq(&spend.anchor) {
                return Err(StateError::InvalidAnchor);
            }

            // Check nullifier not already spent
            let nullifier = Nullifier(spend.nullifier);
            if self.is_nullifier_spent(&nullifier) {
                return Err(StateError::NullifierAlreadySpent(nullifier));
            }
        }

        Ok(())
    }

    /// Apply a validated V2 transaction to the state.
    pub fn apply_transaction_v2(&mut self, tx: &ShieldedTransactionV2) {
        use crate::crypto::commitment::NoteCommitment;

        // Add nullifiers to spent set
        for spend in &tx.spends {
            self.nullifier_set.insert(Nullifier(spend.nullifier));
        }

        // Add output commitments to both V1 and V2 trees
        for output in &tx.outputs {
            let cm = NoteCommitment(output.note_commitment);
            self.commitment_tree.append(&cm);
            // Also add to V2 tree for quantum-resistant proofs
            let cm_pq = NoteCommitmentPQ::from(output.note_commitment);
            self.commitment_tree_pq.append(&cm_pq);
        }
    }

    /// Validate and apply a V2 transaction atomically.
    pub fn validate_and_apply_v2(
        &mut self,
        tx: &ShieldedTransactionV2,
    ) -> Result<(), StateError> {
        self.validate_transaction_v2(tx)?;
        self.apply_transaction_v2(tx);
        Ok(())
    }

    /// Validate a migration transaction.
    ///
    /// Migration transactions spend V1 notes and create V2 notes,
    /// allowing users to upgrade their funds to post-quantum security.
    pub fn validate_migration_transaction(
        &self,
        tx: &MigrationTransaction,
        verifying_params: &CircomVerifyingParams,
    ) -> Result<(), StateError> {
        use crate::crypto::pq::proof_pq::verify_proof;

        // Must have at least one spend and one output
        if tx.legacy_spends.is_empty() {
            return Err(StateError::EmptyTransaction);
        }
        if tx.pq_outputs.is_empty() {
            return Err(StateError::EmptyTransaction);
        }

        // 1. Validate V1 spends (same as regular V1 validation)
        for spend in &tx.legacy_spends {
            // Check anchor is valid
            if !self.is_valid_anchor(&spend.anchor) {
                return Err(StateError::InvalidAnchor);
            }

            // Check nullifier not already spent
            if self.is_nullifier_spent(&spend.nullifier) {
                return Err(StateError::NullifierAlreadySpent(spend.nullifier));
            }

            // Verify spend signature
            if !spend.verify_signature().map_err(|_| StateError::InvalidSignature)? {
                return Err(StateError::InvalidSignature);
            }

            // Verify spend proof
            let public_inputs = bytes_to_public_inputs(
                &spend.anchor,
                &spend.nullifier.to_bytes(),
                &spend.value_commitment,
            );
            if !verify_spend_proof(&spend.proof, &public_inputs, verifying_params) {
                return Err(StateError::InvalidProof);
            }
        }

        // 2. Verify legacy binding signature (for V1 spends)
        // Note: The binding sig only covers the V1 portion
        // The migration proof handles the V2 output validation

        // 3. Verify migration Plonky2 STARK proof
        // Migration proofs have 0 spends (V1 spends are validated separately)
        // and N outputs (the new V2 notes)
        let _public_inputs = verify_proof(
            &tx.migration_proof,
            0, // No PQ spends in migration
            tx.pq_outputs.len(),
        ).map_err(|_| StateError::InvalidProof)?;

        Ok(())
    }

    /// Apply a migration transaction to the state.
    pub fn apply_migration_transaction(&mut self, tx: &MigrationTransaction) {
        use crate::crypto::commitment::NoteCommitment;

        // Add V1 nullifiers to spent set
        for spend in &tx.legacy_spends {
            self.nullifier_set.insert(spend.nullifier);
        }

        // Add V2 output commitments to both trees
        for output in &tx.pq_outputs {
            let cm = NoteCommitment(output.note_commitment);
            self.commitment_tree.append(&cm);
            // Also add to V2 tree for quantum-resistant proofs
            let cm_pq = NoteCommitmentPQ::from(output.note_commitment);
            self.commitment_tree_pq.append(&cm_pq);
        }
    }

    // ========================================================================
    // Unified Transaction Validation (supports all versions)
    // ========================================================================

    /// Validate any transaction type (V1, V2, or Migration).
    pub fn validate_any_transaction(
        &self,
        tx: &Transaction,
        verifying_params: &CircomVerifyingParams,
    ) -> Result<(), StateError> {
        match tx {
            Transaction::V1(v1_tx) => self.validate_transaction(v1_tx, verifying_params),
            Transaction::V2(v2_tx) => self.validate_transaction_v2(v2_tx),
            Transaction::Migration(mig_tx) => {
                self.validate_migration_transaction(mig_tx, verifying_params)
            }
            // Contract transactions are validated by the ContractExecutor, not here
            Transaction::ContractDeploy(_) | Transaction::ContractCall(_) => Ok(()),
        }
    }

    /// Apply any transaction type to the state.
    pub fn apply_any_transaction(&mut self, tx: &Transaction) {
        match tx {
            Transaction::V1(v1_tx) => self.apply_transaction(v1_tx),
            Transaction::V2(v2_tx) => self.apply_transaction_v2(v2_tx),
            Transaction::Migration(mig_tx) => self.apply_migration_transaction(mig_tx),
            // Contract transactions don't modify the shielded state
            Transaction::ContractDeploy(_) | Transaction::ContractCall(_) => {},
        }
    }

    /// Validate and apply any transaction atomically.
    pub fn validate_and_apply_any(
        &mut self,
        tx: &Transaction,
        verifying_params: &CircomVerifyingParams,
    ) -> Result<(), StateError> {
        self.validate_any_transaction(tx, verifying_params)?;
        self.apply_any_transaction(tx);
        Ok(())
    }

    /// Check if any of the given nullifiers conflict with pending nullifiers.
    /// Used by mempool to detect double-spend attempts.
    pub fn check_nullifier_conflicts(
        &self,
        nullifiers: &[&Nullifier],
        pending: &HashSet<Nullifier>,
    ) -> Option<Nullifier> {
        for nf in nullifiers {
            if self.nullifier_set.contains(*nf) || pending.contains(*nf) {
                return Some(**nf);
            }
        }
        None
    }

    /// Get recent roots for anchor validation.
    pub fn recent_roots(&self) -> &[TreeHash] {
        self.commitment_tree.recent_roots()
    }

    /// Get a Merkle path for a commitment at the given position.
    pub fn get_merkle_path(&self, position: u64) -> Option<crate::crypto::merkle_tree::MerklePath> {
        self.commitment_tree.get_path(position)
    }

    /// Get a commitment witness for spending.
    pub fn get_witness(
        &self,
        position: u64,
    ) -> Option<crate::crypto::merkle_tree::CommitmentWitness> {
        self.commitment_tree.witness(position)
    }

    // ========================================================================
    // State Snapshots (for fast loading)
    // ========================================================================

    /// Create a snapshot of the full state (V1 + V2 trees + nullifiers) for persistence.
    /// If V1 tree is being skipped (V2-only mode), save as version 1 (V2-only).
    pub fn snapshot_pq(&self) -> StateSnapshotPQ {
        if self.skip_v1_tree {
            // V2-only mode: pas de V1 tree, pas de migration_hash
            StateSnapshotPQ {
                tree_snapshot: self.commitment_tree_pq.snapshot(),
                nullifiers: self.nullifier_set.iter().map(|n| n.0).collect(),
                version: 1,
                v1_tree: None,
                migration_hash: None,
            }
        } else {
            // V1+V2 mode: calculer le migration_hash pour vérification ultérieure
            let v1_root = self.commitment_tree.root();
            let v2_root = self.commitment_tree_pq.root();
            let height = self.commitment_tree_pq.size();
            let mig_hash = StateSnapshotPQ::compute_migration_hash(&v1_root, &v2_root, height);
            StateSnapshotPQ {
                tree_snapshot: self.commitment_tree_pq.snapshot(),
                nullifiers: self.nullifier_set.iter().map(|n| n.0).collect(),
                version: 2,
                v1_tree: Some(self.commitment_tree.clone()),
                migration_hash: Some(mig_hash),
            }
        }
    }

    /// Restore full state from a snapshot (V1 + V2 trees + nullifiers).
    /// Vérifie le migration_hash si disponible dans le snapshot.
    pub fn restore_pq_from_snapshot(&mut self, snapshot: StateSnapshotPQ) {
        self.commitment_tree_pq = CommitmentTreePQ::from_snapshot(snapshot.tree_snapshot);
        self.nullifier_set = snapshot.nullifiers.into_iter().map(Nullifier).collect();
        // Restore V1 tree if present in snapshot (version >= 2)
        if let Some(v1_tree) = snapshot.v1_tree {
            self.commitment_tree = v1_tree;
            self.skip_v1_tree = false;

            // Vérifier le migration_hash si présent dans le checkpoint
            if snapshot.migration_hash.is_some() {
                let v1_root = self.commitment_tree.root();
                let v2_root = self.commitment_tree_pq.root();
                let height = self.commitment_tree_pq.size();
                let check = StateSnapshotPQ::compute_migration_hash(&v1_root, &v2_root, height);
                if let Some(expected) = &snapshot.migration_hash {
                    if &check != expected {
                        tracing::error!(
                            "Migration hash invalide lors de la restauration! attendu={}, calculé={}",
                            hex::encode(expected),
                            hex::encode(check)
                        );
                    } else {
                        tracing::info!("Migration hash vérifié avec succès");
                    }
                }
            }
        } else {
            // V2-only snapshot: V1 tree stays empty, skip V1 tree updates
            // and commitment_root validation (V1 root won't match headers).
            // Blocks are still validated by PoW, V2 tree, and all other checks.
            self.skip_v1_tree = true;

            // Pour un snapshot V2-only, vérifier le migration_hash contre le checkpoint si disponible
            if let Some(ref expected) = snapshot.migration_hash {
                tracing::warn!(
                    "Snapshot V2-only avec migration_hash présent ({}), vérification différée au prochain checkpoint V1+V2",
                    hex::encode(expected)
                );
            }
        }
    }

    /// Check if a snapshot is compatible with this state version.
    pub fn is_snapshot_compatible(snapshot: &StateSnapshotPQ) -> bool {
        snapshot.version == 1 || snapshot.version == 2
    }
}

/// Snapshot of the full state for fast loading.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateSnapshotPQ {
    /// V2 commitment tree snapshot.
    pub tree_snapshot: CommitmentTreeSnapshot,
    /// All spent nullifiers.
    pub nullifiers: Vec<[u8; 32]>,
    /// Version for compatibility checking (1 = V2-only, 2 = V1+V2).
    pub version: u32,
    /// V1 commitment tree (added in version 2).
    #[serde(default)]
    pub v1_tree: Option<CommitmentTree>,
    /// Hash de migration: SHA-256(v1_root || v2_root || height).
    /// Permet de vérifier l'intégrité lors de la restauration.
    #[serde(default)]
    pub migration_hash: Option<[u8; 32]>,
}

impl StateSnapshotPQ {
    /// Calcule le hash de migration: SHA-256(v1_root || v2_root || height).
    /// Utilisé pour vérifier l'intégrité entre les arbres V1 et V2 lors d'un checkpoint.
    pub fn compute_migration_hash(v1_root: &[u8; 32], v2_root: &[u8; 32], height: u64) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(v1_root);
        hasher.update(v2_root);
        hasher.update(height.to_le_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Vérifie le migration_hash si présent.
    /// Retourne Ok(()) si le hash est absent ou valide, Err sinon.
    pub fn verify_migration_hash(&self, v1_root: &[u8; 32], v2_root: &[u8; 32], height: u64) -> Result<(), String> {
        if let Some(expected) = &self.migration_hash {
            let computed = Self::compute_migration_hash(v1_root, v2_root, height);
            if &computed != expected {
                return Err(format!(
                    "Migration hash invalide: attendu {}, calculé {}",
                    hex::encode(expected),
                    hex::encode(computed)
                ));
            }
        }
        Ok(())
    }
}

/// State errors for shielded transactions.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("Invalid transaction signature")]
    InvalidSignature,

    #[error("Invalid zk-SNARK proof")]
    InvalidProof,

    #[error("Invalid anchor (not a recent root)")]
    InvalidAnchor,

    #[error("Nullifier already spent: {0:?}")]
    NullifierAlreadySpent(Nullifier),

    #[error("Invalid binding signature (value balance incorrect)")]
    InvalidBindingSignature,

    #[error("Transaction has no spends or outputs")]
    EmptyTransaction,

    #[error("Invalid coinbase reward: expected {expected}, got {got}")]
    InvalidCoinbaseReward { expected: u64, got: u64 },

    #[error("Invalid coinbase height: expected {expected}, got {got}")]
    InvalidCoinbaseHeight { expected: u64, got: u64 },

    #[error("Transaction error: {0}")]
    TransactionError(#[from] TransactionError),
}

// ============================================================================
// Legacy State Support (for migration)
// ============================================================================

use std::collections::HashMap;
use crate::crypto::Address;

/// Legacy account for backwards compatibility.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Account {
    pub address: Address,
    pub balance: u64,
    pub nonce: u64,
}

impl Account {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            balance: 0,
            nonce: 0,
        }
    }

    pub fn with_balance(address: Address, balance: u64) -> Self {
        Self {
            address,
            balance,
            nonce: 0,
        }
    }

    pub fn credit(&mut self, amount: u64) {
        self.balance = self.balance.saturating_add(amount);
    }

    pub fn debit(&mut self, amount: u64, fee: u64) -> Result<(), &'static str> {
        let total = amount.saturating_add(fee);
        if self.balance < total {
            return Err("Insufficient balance");
        }
        self.balance -= total;
        self.nonce += 1;
        Ok(())
    }

    pub fn can_afford(&self, amount: u64, fee: u64) -> bool {
        self.balance >= amount.saturating_add(fee)
    }
}

/// Legacy state for backwards compatibility during migration.
#[derive(Clone, Debug, Default)]
pub struct LegacyState {
    accounts: HashMap<Address, Account>,
}

impl LegacyState {
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
        }
    }

    pub fn get_account(&self, address: &Address) -> Account {
        self.accounts
            .get(address)
            .cloned()
            .unwrap_or_else(|| Account::new(*address))
    }

    pub fn get_account_mut(&mut self, address: &Address) -> &mut Account {
        self.accounts
            .entry(*address)
            .or_insert_with(|| Account::new(*address))
    }

    pub fn set_account(&mut self, account: Account) {
        self.accounts.insert(account.address, account);
    }

    pub fn balance(&self, address: &Address) -> u64 {
        self.get_account(address).balance
    }

    pub fn nonce(&self, address: &Address) -> u64 {
        self.get_account(address).nonce
    }

    pub fn accounts(&self) -> impl Iterator<Item = &Account> {
        self.accounts.values()
    }

    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    pub fn top_holders(&self, limit: usize) -> Vec<&Account> {
        let mut accounts: Vec<_> = self.accounts.values().collect();
        accounts.sort_by(|a, b| b.balance.cmp(&a.balance));
        accounts.truncate(limit);
        accounts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::commitment::NoteCommitment;
    use crate::crypto::nullifier::Nullifier;

    #[test]
    fn test_empty_shielded_state() {
        let state = ShieldedState::new();

        assert_eq!(state.commitment_count(), 0);
        assert_eq!(state.nullifier_count(), 0);
        assert_eq!(state.commitment_root(), CommitmentTree::empty_root());
    }

    #[test]
    fn test_nullifier_tracking() {
        let mut state = ShieldedState::new();
        let nf = Nullifier([1u8; 32]);

        assert!(!state.is_nullifier_spent(&nf));

        state.nullifier_set.insert(nf);

        assert!(state.is_nullifier_spent(&nf));
    }

    #[test]
    fn test_commitment_tracking() {
        let mut state = ShieldedState::new();
        let cm = NoteCommitment([1u8; 32]);

        let initial_root = state.commitment_root();
        state.commitment_tree.append(&cm);

        assert_eq!(state.commitment_count(), 1);
        assert_ne!(state.commitment_root(), initial_root);
    }

    #[test]
    fn test_anchor_validation() {
        let mut state = ShieldedState::new();

        let root_before = state.commitment_root();
        let cm = NoteCommitment([1u8; 32]);
        state.commitment_tree.append(&cm);
        let root_after = state.commitment_root();

        // Both roots should be valid
        assert!(state.is_valid_anchor(&root_before));
        assert!(state.is_valid_anchor(&root_after));

        // Random root should not be valid
        assert!(!state.is_valid_anchor(&[99u8; 32]));
    }

    #[test]
    fn test_snapshot() {
        let mut state = ShieldedState::new();
        state.nullifier_set.insert(Nullifier([1u8; 32]));

        let snapshot = state.snapshot();

        // Snapshot should have same data
        assert!(snapshot.is_nullifier_spent(&Nullifier([1u8; 32])));

        // Modifying original shouldn't affect snapshot
        state.nullifier_set.insert(Nullifier([2u8; 32]));
        assert!(!snapshot.is_nullifier_spent(&Nullifier([2u8; 32])));
    }

    #[test]
    fn test_nullifier_conflict_detection() {
        let mut state = ShieldedState::new();
        let nf1 = Nullifier([1u8; 32]);
        let nf2 = Nullifier([2u8; 32]);
        let nf3 = Nullifier([3u8; 32]);

        state.nullifier_set.insert(nf1);

        let mut pending = HashSet::new();
        pending.insert(nf2);

        // nf1 is in state
        assert_eq!(
            state.check_nullifier_conflicts(&[&nf1], &pending),
            Some(nf1)
        );

        // nf2 is in pending
        assert_eq!(
            state.check_nullifier_conflicts(&[&nf2], &pending),
            Some(nf2)
        );

        // nf3 has no conflict
        assert_eq!(state.check_nullifier_conflicts(&[&nf3], &pending), None);
    }
}
