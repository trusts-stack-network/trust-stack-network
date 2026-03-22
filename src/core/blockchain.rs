//! Shielded blockchain implementation.
//!
//! The blockchain manages the chain of shielded blocks, the commitment tree,
//! and the nullifier set. All transaction data is private - only fees and
//! roots are visible.

use std::collections::HashMap;
use std::sync::Arc;

use crate::consensus::{
    calculate_next_difficulty, should_adjust_difficulty, ADJUSTMENT_INTERVAL, MIN_DIFFICULTY,
};
use crate::crypto::{
    note::{Note, ViewingKey},
    proof::CircomVerifyingParams,
    pq::commitment_pq::commit_to_note_pq,
};
use crate::storage::Database;

use super::block::{BlockError, ShieldedBlock, BLOCK_HASH_SIZE};
use super::state::{ShieldedState, StateError};
use super::transaction::{CoinbaseTransaction, ShieldedTransaction, ShieldedTransactionV2};

/// The initial mining reward in smallest units (50 coins).
/// Use `crate::config::block_reward_at_height(h)` for halving-aware reward.
pub const BLOCK_REWARD: u64 = 50_000_000_000; // 50 coins with 9 decimal places

/// The shielded blockchain - manages chain, commitment tree, and nullifier set.
pub struct ShieldedBlockchain {
    /// All blocks indexed by hash.
    blocks: HashMap<[u8; 32], ShieldedBlock>,
    /// Block hashes by height.
    height_index: Vec<[u8; 32]>,
    /// Current shielded state (commitment tree + nullifier set).
    state: ShieldedState,
    /// Current mining difficulty.
    difficulty: u64,
    /// Optional persistent storage.
    db: Option<Arc<Database>>,
    /// Orphan blocks (blocks whose parent we don't have yet).
    orphans: HashMap<[u8; 32], ShieldedBlock>,
    /// Verifying parameters for zk-SNARK proof verification (Circom circuits).
    verifying_params: Option<Arc<CircomVerifyingParams>>,
    /// Assume-valid height: skip proof verification for blocks at or below this height.
    /// Set to 0 to disable (verify all proofs).
    assume_valid_height: u64,
    /// Height of the last finalized checkpoint for reorg protection.
    last_checkpoint_height: u64,
    /// Hash of the block at the last checkpoint height.
    last_checkpoint_hash: Option<[u8; 32]>,
    /// Cumulative work (sum of difficulties) for heaviest-chain fork choice.
    cumulative_work: u128,
    /// Height at which fast-sync snapshot was imported (0 = no fast-sync).
    /// Blocks before this height may not exist in DB.
    fast_sync_base_height: u64,
}

impl ShieldedBlockchain {
    /// Create a new blockchain with a genesis block (in-memory only).
    pub fn new(difficulty: u64, genesis_coinbase: CoinbaseTransaction) -> Self {
        use crate::config;

        let genesis = ShieldedBlock::genesis(difficulty, genesis_coinbase.clone());
        let genesis_hash = genesis.hash();

        let mut blocks = HashMap::new();
        blocks.insert(genesis_hash, genesis);
        // Initialize state with genesis coinbase
        let mut state = ShieldedState::new();
        state.apply_coinbase(&genesis_coinbase);

        // Get assume-valid configuration
        let assume_valid_height = if config::is_assume_valid_enabled() {
            config::ASSUME_VALID_HEIGHT
        } else {
            0
        };

        Self {
            blocks,
            height_index: vec![genesis_hash],
            state,
            difficulty,
            db: None,
            orphans: HashMap::new(),
            verifying_params: None,
            assume_valid_height,
            last_checkpoint_height: 0,
            last_checkpoint_hash: None,
            cumulative_work: difficulty as u128,
            fast_sync_base_height: 0,
        }
    }

    /// Create a new blockchain with a default genesis block for the given miner.
    /// This is a convenience method for standalone mining.
    pub fn with_miner(difficulty: u64, miner_pk_hash: [u8; 32], viewing_key: &ViewingKey) -> Self {
        let genesis_coinbase = Self::create_genesis_coinbase(miner_pk_hash, viewing_key);
        Self::new(difficulty, genesis_coinbase)
    }

    /// Open a persisted blockchain from disk, or create a new one.
    ///
    /// If a state snapshot exists, it is loaded for fast startup.
    /// Otherwise, state is rebuilt by replaying all blocks from genesis.
    pub fn open(db_path: &str, difficulty: u64) -> Result<Self, BlockchainError> {
        use crate::crypto::commitment::NoteCommitment;
        use crate::crypto::note::EncryptedNote;

        // Open the database
        let db = Database::open(db_path)
            .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
        let db = Arc::new(db);

        // Check if we have existing blocks
        let stored_height = db
            .get_height()
            .map_err(|e| BlockchainError::StorageError(e.to_string()))?;

        if let Some(height) = stored_height {
            // Load existing chain
            tracing::info!("Loading blockchain from disk (height: {})", height);

            let mut blocks = HashMap::new();
            let height_index;
            let mut state = ShieldedState::new();

            // Try to load state snapshot for fast startup
            let snapshot_height = match db.load_state_snapshot() {
                Ok(Some((snapshot, snap_height))) if snap_height <= height => {
                    if snapshot.v1_tree.is_some() {
                        tracing::info!(
                            "Loading full state snapshot (V1+V2) from height {} (skipping {} blocks)",
                            snap_height,
                            snap_height
                        );
                    } else {
                        tracing::info!(
                            "Loading V2-only snapshot from height {} (V1 tree will start empty)",
                            snap_height
                        );
                    }
                    state.restore_pq_from_snapshot(snapshot);
                    Some(snap_height)
                }
                Ok(_) => {
                    tracing::info!("No valid snapshot found, replaying all blocks");
                    None
                }
                Err(e) => {
                    tracing::warn!("Failed to load snapshot: {}, replaying all blocks", e);
                    None
                }
            };

            // Determine starting height for replay
            let start_height = snapshot_height.map(|h| h + 1).unwrap_or(0);
            let blocks_to_replay = height - start_height + 1;

            // Load full height index via sequential scan (much faster than N individual lookups)
            tracing::info!("Loading height index...");
            height_index = db.load_all_block_hashes()
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
            tracing::info!("Height index loaded ({} entries)", height_index.len());

            // Replay blocks from snapshot to current height to rebuild state
            // With snapshots every 10 blocks, this replays at most ~9 blocks
            if blocks_to_replay > 0 && start_height <= height {
                tracing::info!("Replaying {} blocks from height {} to {}...", blocks_to_replay, start_height, height);
                for h in start_height..=height {
                    let hash = height_index.get(h as usize).copied()
                        .or_else(|| db.get_block_hash_by_height(h).ok().flatten())
                        .ok_or_else(|| {
                            BlockchainError::StorageError(format!("Missing block hash at height {}", h))
                        })?;
                    let block = db
                        .load_block(&hash)
                        .map_err(|e| BlockchainError::StorageError(e.to_string()))?
                        .ok_or_else(|| {
                            BlockchainError::StorageError(format!("Missing block data at height {}", h))
                        })?;

                    for tx in &block.transactions {
                        state.apply_transaction(tx);
                    }
                    for tx in &block.transactions_v2 {
                        state.apply_transaction_v2(tx);
                    }
                    state.apply_coinbase(&block.coinbase);

                    blocks.insert(hash, block);
                }
                tracing::info!("Replay complete ({} blocks)", blocks_to_replay);
            } else {
                tracing::info!("Snapshot is up-to-date, no replay needed");
            }

            // Save updated snapshot for faster future startups
            if snapshot_height.is_none() || snapshot_height.unwrap() < height {
                tracing::info!("Saving state snapshot at height {}", height);
                let snapshot = state.snapshot_pq();
                if let Err(e) = db.save_state_snapshot(&snapshot, height) {
                    tracing::warn!("Failed to save state snapshot: {}", e);
                }
            }

            // Load difficulty from metadata or use last block's difficulty
            let current_difficulty = db
                .get_metadata("difficulty")
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(difficulty);

            tracing::info!(
                "Blockchain loaded: height={}, commitments={}, nullifiers={}",
                height,
                state.commitment_count(),
                state.nullifier_count()
            );

            // Get assume-valid configuration
            let assume_valid_height = if crate::config::is_assume_valid_enabled() {
                crate::config::ASSUME_VALID_HEIGHT
            } else {
                0
            };

            // Compute the last checkpoint from the loaded chain
            let (cp_height, cp_hash) = if crate::config::CHECKPOINT_ENABLED && height >= crate::config::CHECKPOINT_INTERVAL {
                let cp_h = (height / crate::config::CHECKPOINT_INTERVAL) * crate::config::CHECKPOINT_INTERVAL;
                let cp_hash = height_index.get(cp_h as usize).copied();
                if cp_hash.is_some() {
                    tracing::info!("Restored checkpoint finality at height {}", cp_h);
                }
                (cp_h, cp_hash)
            } else {
                (0, None)
            };

            // Load cumulative work from metadata (persisted at each snapshot)
            // Falls back to recalculating from blocks if not found
            let cumulative_work: u128 = db
                .get_metadata("cumulative_work")
                .ok()
                .flatten()
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or_else(|| {
                    tracing::info!("cumulative_work not in metadata, recalculating...");
                    let mut work: u128 = 0;
                    for h in 0..=height {
                        if let Some(hash) = height_index.get(h as usize) {
                            if let Some(block) = blocks.get(hash) {
                                work += block.header.difficulty as u128;
                            }
                        }
                    }
                    work
                });

            // Verify genesis hash if configured
            let expected_genesis = crate::config::EXPECTED_GENESIS_HASH;
            if !expected_genesis.is_empty() {
                if let Some(genesis_hash) = height_index.first() {
                    let actual = hex::encode(genesis_hash);
                    if actual != expected_genesis {
                        return Err(BlockchainError::StorageError(format!(
                            "Genesis hash mismatch! Expected: {}, Got: {}. This node has incompatible chain data.",
                            expected_genesis, actual
                        )));
                    }
                }
            }

            // Load fast_sync_base_height from metadata
            let fast_sync_base: u64 = db
                .get_metadata("fast_sync_base_height")
                .ok()
                .flatten()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);

            Ok(Self {
                blocks,
                height_index,
                state,
                difficulty: current_difficulty,
                db: Some(db),
                orphans: HashMap::new(),
                verifying_params: None,
                assume_valid_height,
                last_checkpoint_height: cp_height,
                last_checkpoint_hash: cp_hash,
                cumulative_work,
                fast_sync_base_height: fast_sync_base,
            })
        } else {
            // Create a fresh chain with a dummy genesis
            tracing::info!("Creating new blockchain");

            let genesis_coinbase = CoinbaseTransaction::new(
                NoteCommitment([0u8; 32]),
                [0u8; 32], // V2/PQ commitment (dummy for genesis)
                EncryptedNote {
                    ciphertext: vec![0; 64],
                    ephemeral_pk: vec![0; 32],
                },
                BLOCK_REWARD,
                0,
            );

            let genesis = ShieldedBlock::genesis(difficulty, genesis_coinbase.clone());
            let genesis_hash = genesis.hash();

            // Save genesis to database
            db.save_block(&genesis, 0)
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
            db.set_metadata("difficulty", &difficulty.to_string())
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
            db.flush()
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;

            let mut blocks = HashMap::new();
            blocks.insert(genesis_hash, genesis);

            // Initialize state with genesis coinbase
            let mut state = ShieldedState::new();
            state.apply_coinbase(&genesis_coinbase);

            // Get assume-valid configuration
            let assume_valid_height = if crate::config::is_assume_valid_enabled() {
                crate::config::ASSUME_VALID_HEIGHT
            } else {
                0
            };

            // Verify genesis hash if configured
            let expected_genesis = crate::config::EXPECTED_GENESIS_HASH;
            if !expected_genesis.is_empty() {
                let actual = hex::encode(genesis_hash);
                if actual != expected_genesis {
                    return Err(BlockchainError::StorageError(format!(
                        "Genesis hash mismatch! Expected: {}, Got: {}. Check GENESIS_DIFFICULTY and genesis parameters.",
                        expected_genesis, actual
                    )));
                }
            }

            Ok(Self {
                blocks,
                height_index: vec![genesis_hash],
                state,
                difficulty,
                db: Some(db),
                orphans: HashMap::new(),
                verifying_params: None,
                assume_valid_height,
                last_checkpoint_height: 0,
                last_checkpoint_hash: None,
                cumulative_work: difficulty as u128,
            fast_sync_base_height: 0,
            })
        }
    }

    /// Create a genesis coinbase for a miner.
    pub fn create_genesis_coinbase(
        miner_pk_hash: [u8; 32],
        _viewing_key: &ViewingKey,  // Kept for API compatibility but not used
    ) -> CoinbaseTransaction {
        use ark_serialize::CanonicalSerialize;

        let mut rng = ark_std::rand::thread_rng();
        let note = Note::new(BLOCK_REWARD, miner_pk_hash, &mut rng);
        // Encrypt using miner's pk_hash so they can decrypt it
        let miner_key = ViewingKey::from_pk_hash(miner_pk_hash);
        let encrypted = miner_key.encrypt_note(&note, &mut rng);

        // Compute V1 commitment (BN254 Poseidon)
        let commitment_v1 = note.commitment();

        // Compute V2/PQ commitment (Goldilocks Poseidon) for post-quantum security
        let mut randomness_bytes = [0u8; 32];
        note.randomness.serialize_compressed(&mut randomness_bytes[..]).unwrap();
        let commitment_pq = commit_to_note_pq(BLOCK_REWARD, &miner_pk_hash, &randomness_bytes);

        CoinbaseTransaction::new(commitment_v1, commitment_pq, encrypted, BLOCK_REWARD, 0)
    }

    /// Set the verifying parameters for proof verification.
    pub fn set_verifying_params(&mut self, params: Arc<CircomVerifyingParams>) {
        self.verifying_params = Some(params);
    }

    /// Get the verifying parameters for proof verification.
    pub fn verifying_params(&self) -> Option<&Arc<CircomVerifyingParams>> {
        self.verifying_params.as_ref()
    }

    /// Get the current chain height (0-indexed).
    pub fn height(&self) -> u64 {
        self.height_index.len() as u64 - 1
    }

    /// Get the current difficulty.
    pub fn difficulty(&self) -> u64 {
        self.difficulty
    }

    /// Calculate the next block's difficulty based on recent block times.
    pub fn next_difficulty(&self) -> u64 {
        let height = self.height();

        if height < ADJUSTMENT_INTERVAL {
            return self.difficulty.max(MIN_DIFFICULTY);
        }

        if should_adjust_difficulty(height + 1) {
            let window_start = height + 1 - ADJUSTMENT_INTERVAL;

            // After fast-sync, blocks before the snapshot don't exist.
            // If the adjustment window extends before the snapshot, trust self.difficulty.
            if self.fast_sync_base_height > 0 && window_start < self.fast_sync_base_height {
                return self.difficulty.max(MIN_DIFFICULTY);
            }

            let first_block = self.get_block_by_height(window_start);
            let last_block = self.get_block_by_height(height);

            if let (Some(first), Some(last)) = (first_block, last_block) {
                return calculate_next_difficulty(
                    self.difficulty,
                    first.header.timestamp,
                    last.header.timestamp,
                    ADJUSTMENT_INTERVAL,
                );
            }
            // Fallback if blocks are somehow missing
            return self.difficulty.max(MIN_DIFFICULTY);
        }

        self.difficulty.max(MIN_DIFFICULTY)
    }

    /// Get timestamps of recent blocks.
    pub fn recent_timestamps(&self, count: usize) -> Vec<u64> {
        let start = self.height_index.len().saturating_sub(count);
        self.height_index[start..]
            .iter()
            .filter_map(|hash| self.blocks.get(hash))
            .map(|block| block.header.timestamp)
            .collect()
    }

    /// Get the latest block hash.
    pub fn latest_hash(&self) -> [u8; 32] {
        *self.height_index.last().unwrap()
    }

    /// Get the latest block.
    pub fn latest_block(&self) -> ShieldedBlock {
        self.get_block(&self.latest_hash()).expect("latest block must exist")
    }

    /// Get a block by hash. Checks in-memory cache first, falls back to DB.
    pub fn get_block(&self, hash: &[u8; 32]) -> Option<ShieldedBlock> {
        if let Some(block) = self.blocks.get(hash) {
            return Some(block.clone());
        }
        // Fallback: load from database
        if let Some(ref db) = self.db {
            db.load_block(hash).ok().flatten()
        } else {
            None
        }
    }

    /// Get a block by height. Checks in-memory cache first, falls back to DB.
    pub fn get_block_by_height(&self, height: u64) -> Option<ShieldedBlock> {
        if let Some(hash) = self.height_index.get(height as usize) {
            if let Some(block) = self.blocks.get(hash) {
                return Some(block.clone());
            }
        }
        // Fallback: load from database
        if let Some(ref db) = self.db {
            db.load_block_by_height(height).ok().flatten()
        } else {
            None
        }
    }

    /// Get the current shielded state.
    pub fn state(&self) -> &ShieldedState {
        &self.state
    }

    /// Get the current commitment tree root.
    pub fn commitment_root(&self) -> [u8; 32] {
        self.state.commitment_root()
    }

    /// Get the number of commitments in the tree.
    pub fn commitment_count(&self) -> u64 {
        self.state.commitment_count()
    }

    /// Get the number of spent nullifiers.
    pub fn nullifier_count(&self) -> usize {
        self.state.nullifier_count()
    }

    /// Validate a block before adding it.
    ///
    /// If assume-valid is enabled and the block height is at or below the
    /// assume-valid checkpoint, ZK proof verification is skipped. Block structure,
    /// proof-of-work, and state transitions are still fully validated.
    pub fn validate_block(&self, block: &ShieldedBlock) -> Result<(), BlockchainError> {
        // Check previous hash
        if block.header.prev_hash != self.latest_hash() {
            return Err(BlockchainError::InvalidPrevHash);
        }

        // Check block structure and proof-of-work
        block.verify().map_err(BlockchainError::BlockError)?;

        // Check difficulty
        let expected_difficulty = self.next_difficulty();
        if block.header.difficulty != expected_difficulty {
            // After fast-sync, difficulty adjustment may not be computable
            // (missing blocks in the adjustment window). Accept the block's difficulty
            // if the window extends before the fast-sync base height.
            let expected_height = self.height() + 1;
            let window_extends_before_sync = self.fast_sync_base_height > 0
                && should_adjust_difficulty(expected_height)
                && expected_height.saturating_sub(ADJUSTMENT_INTERVAL) < self.fast_sync_base_height;

            if !window_extends_before_sync {
                return Err(BlockchainError::InvalidDifficulty);
            }
            // Accept and update difficulty from the trusted peer's block
            tracing::debug!(
                "Accepting difficulty {} from trusted peer (fast-sync window)",
                block.header.difficulty
            );
        }

        // Validate coinbase (with halving-aware reward)
        let expected_height = self.height() + 1;
        let total_fees = block.total_fees();
        let base_reward = crate::config::block_reward_at_height(expected_height);
        let expected_reward = base_reward + total_fees;

        self.state
            .validate_coinbase(&block.coinbase, expected_reward, expected_height)
            .map_err(|e| BlockchainError::StateError(e))?;

        // Validate dev fee if present
        if block.coinbase.has_dev_fee() {
            use crate::config;
            let expected_dev_fee = config::dev_fee(expected_reward);
            if block.coinbase.dev_fee_amount != expected_dev_fee {
                return Err(BlockchainError::InvalidCoinbaseAmount);
            }
            // Verify dev fee commitment exists
            if block.coinbase.dev_fee_commitment.is_none()
                || block.coinbase.dev_fee_encrypted_note.is_none()
            {
                return Err(BlockchainError::InvalidCoinbase);
            }
        }

        // Check if we should skip proof verification (assume-valid optimization)
        let skip_proof_verification = self.assume_valid_height > 0
            && expected_height <= self.assume_valid_height;

        if skip_proof_verification {
            // Still validate transaction structure and nullifiers, just skip ZK proofs
            for tx in &block.transactions {
                self.state
                    .validate_transaction_basic(tx)
                    .map_err(|e| BlockchainError::StateError(e))?;
            }
            for tx in &block.transactions_v2 {
                self.state
                    .validate_transaction_v2_basic(tx)
                    .map_err(|e| BlockchainError::StateError(e))?;
            }
        } else {
            // Full validation including ZK proof verification
            // Validate all V1 transactions
            if let Some(ref params) = self.verifying_params {
                for tx in &block.transactions {
                    self.state
                        .validate_transaction(tx, params)
                        .map_err(|e| BlockchainError::StateError(e))?;
                }
            } else {
                // If no verifying params, just do basic validation
                for tx in &block.transactions {
                    self.state
                        .validate_transaction_basic(tx)
                        .map_err(|e| BlockchainError::StateError(e))?;
                }
            }

            // Validate all V2 transactions (with STARK proof verification)
            for tx in &block.transactions_v2 {
                self.state
                    .validate_transaction_v2(tx)
                    .map_err(|e| BlockchainError::StateError(e))?;
            }
        }

        // Verify commitment root matches expected
        let mut temp_state = self.state.snapshot();
        for tx in &block.transactions {
            temp_state.apply_transaction(tx);
        }
        for tx in &block.transactions_v2 {
            temp_state.apply_transaction_v2(tx);
        }
        temp_state.apply_coinbase(&block.coinbase);

        // Verify commitment root if V1 tree is available.
        // When loaded from V2-only snapshot, V1 tree is empty and skip_v1_tree is set,
        // so we skip this check (PoW and other validations still apply).
        if !temp_state.is_v1_tree_skipped() && temp_state.commitment_root() != block.header.commitment_root {
            return Err(BlockchainError::InvalidCommitmentRoot);
        }

        Ok(())
    }

    /// Add a validated block to the chain.
    /// Add a block without full validation (trusted source, e.g. fast-sync from seeds).
    /// Only checks prev_hash continuity. Skips PoW, signatures, ZK proofs.
    /// Security: caller MUST verify a checkpoint hash after importing a batch.
    pub fn add_block_trusted(&mut self, block: ShieldedBlock) -> Result<(), BlockchainError> {
        if block.header.prev_hash != self.latest_hash() {
            return Err(BlockchainError::InvalidPrevHash);
        }
        self.insert_block_internal(block, false)
    }

    pub fn add_block(&mut self, block: ShieldedBlock) -> Result<(), BlockchainError> {
        self.validate_block(&block)?;
        self.insert_block_internal(block, true)
    }

    /// Verify that a specific height has the expected hash.
    /// Used after fast-sync to validate the trusted chain against hardcoded checkpoints.
    pub fn verify_checkpoint(&self, height: u64, expected_hash: &str) -> bool {
        if let Some(block) = self.get_block_by_height(height) {
            let actual_hash = hex::encode(block.hash());
            actual_hash == expected_hash
        } else {
            false
        }
    }

    /// Internal: insert a block into the chain (shared by add_block and add_block_trusted).
    fn insert_block_internal(&mut self, block: ShieldedBlock, full_mode: bool) -> Result<(), BlockchainError> {
        let hash = block.hash();
        let new_height = self.height_index.len() as u64;

        // Persist block and nullifiers
        if let Some(ref db) = self.db {
            db.save_block(&block, new_height)
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;

            for tx in &block.transactions {
                for spend in &tx.spends {
                    db.save_nullifier(&spend.nullifier.to_bytes())
                        .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
                }
            }
            for tx in &block.transactions_v2 {
                for spend in &tx.spends {
                    db.save_nullifier(&spend.nullifier)
                        .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
                }
            }

            db.set_metadata("difficulty", &block.header.difficulty.to_string())
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;

            // In trusted mode, flush less frequently (every 100 blocks instead of every block)
            if full_mode || new_height % 100 == 0 {
                db.flush()
                    .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
            }
        }

        // Apply transactions to state
        for tx in &block.transactions {
            self.state.apply_transaction(tx);
        }
        for tx in &block.transactions_v2 {
            self.state.apply_transaction_v2(tx);
        }
        self.state.apply_coinbase(&block.coinbase);

        // Update chain state
        self.difficulty = block.header.difficulty;
        self.cumulative_work += block.header.difficulty as u128;
        self.blocks.insert(hash, block);
        self.height_index.push(hash);

        // Checkpoint finalization
        if crate::config::CHECKPOINT_ENABLED
            && new_height > 0
            && new_height % crate::config::CHECKPOINT_INTERVAL == 0
            && new_height > self.last_checkpoint_height
        {
            self.last_checkpoint_height = new_height;
            self.last_checkpoint_hash = Some(hash);
            if full_mode {
                tracing::info!(
                    "Checkpoint finalized at height {} (hash: {})",
                    new_height, hex::encode(hash)
                );
            }
        }

        // Save state snapshot every 10 blocks (for fast startup)
        // In trusted mode with full_mode=false, save less frequently (every 500 blocks)
        let snapshot_interval = if full_mode { 10 } else { 500 };
        if new_height > 0 && new_height % snapshot_interval == 0 {
            if let Some(ref db) = self.db {
                let snapshot = self.state.snapshot_pq();
                if let Err(e) = db.save_state_snapshot(&snapshot, new_height) {
                    tracing::warn!("Failed to save state snapshot at height {}: {}", new_height, e);
                }
                let _ = db.set_metadata("cumulative_work", &self.cumulative_work.to_string());
            }
        }

        Ok(())
    }

    /// Check if a block exists in RAM cache or in the database.
    fn has_block(&self, hash: &[u8; 32]) -> bool {
        if self.blocks.contains_key(hash) {
            return true;
        }
        if let Some(ref db) = self.db {
            db.get_block_hash_by_height(0).is_ok() // just check DB is alive
                && db.load_block(hash).ok().flatten().is_some()
        } else {
            false
        }
    }

    /// Try to add a block, handling orphans and potential reorgs.
    pub fn try_add_block(&mut self, block: ShieldedBlock) -> Result<bool, BlockchainError> {
        let block_hash = block.hash();

        // Already have this block?
        if self.has_block(&block_hash) {
            return Ok(false);
        }

        // Does it extend our current chain?
        if block.header.prev_hash == self.latest_hash() {
            self.add_block(block)?;
            self.process_orphans()?;
            return Ok(true);
        }

        // Do we have the parent block? Check RAM + DB
        if !self.has_block(&block.header.prev_hash) {
            // Store as orphan
            self.orphans.insert(block_hash, block);
            return Ok(false);
        }

        // We have the parent but it's not our tip - potential fork
        let fork_work = self.calculate_chain_work(&block);
        let current_height = self.height();
        let fork_height = self.calculate_chain_height(&block);

        // Check MAX_REORG_DEPTH: reject forks that would reorg too deep
        // Skip this check when in fast-sync zone (height_index has placeholders)
        if current_height > fork_height && self.fast_sync_base_height == 0 {
            let reorg_depth = current_height - fork_height + 1;
            if reorg_depth > crate::config::MAX_REORG_DEPTH {
                tracing::warn!(
                    "Rejecting fork: reorg depth {} exceeds MAX_REORG_DEPTH {}",
                    reorg_depth, crate::config::MAX_REORG_DEPTH
                );
                return Ok(false);
            }
        }

        // Heaviest chain: compare cumulative work, not just height
        if fork_work > self.cumulative_work {
            tracing::info!(
                "Fork has more work ({} vs {}), reorganizing",
                fork_work, self.cumulative_work
            );
            self.reorganize_to_block(block)?;
            self.process_orphans()?;
            return Ok(true);
        }

        // Fork has less or equal work - store but don't switch
        self.blocks.insert(block_hash, block);
        Ok(false)
    }

    /// Calculate the height a block would have if added.
    fn calculate_chain_height(&self, block: &ShieldedBlock) -> u64 {
        let mut height = 1u64;
        let mut prev_hash = block.header.prev_hash;

        while let Some(parent) = self.get_block(&prev_hash) {
            height += 1;
            if parent.header.prev_hash == [0u8; BLOCK_HASH_SIZE] {
                break;
            }
            prev_hash = parent.header.prev_hash;
        }

        height
    }

    /// Calculate cumulative work for a chain ending at the given block.
    /// Used for heaviest-chain fork choice (inspired by Quantus/Bitcoin).
    fn calculate_chain_work(&self, block: &ShieldedBlock) -> u128 {
        let mut work = block.header.difficulty as u128;
        let mut prev_hash = block.header.prev_hash;

        while let Some(parent) = self.get_block(&prev_hash) {
            work += parent.header.difficulty as u128;
            if parent.header.prev_hash == [0u8; BLOCK_HASH_SIZE] {
                break;
            }
            prev_hash = parent.header.prev_hash;
        }

        work
    }

    /// Get the cumulative work of the current chain.
    pub fn cumulative_work(&self) -> u128 {
        self.cumulative_work
    }

    /// Process orphan blocks to see if any can now be connected.
    fn process_orphans(&mut self) -> Result<(), BlockchainError> {
        let mut connected = true;

        while connected {
            connected = false;
            let orphan_hashes: Vec<[u8; 32]> = self.orphans.keys().cloned().collect();

            for hash in orphan_hashes {
                if let Some(orphan) = self.orphans.get(&hash).cloned() {
                    if orphan.header.prev_hash == self.latest_hash() {
                        self.orphans.remove(&hash);
                        if self.add_block(orphan).is_ok() {
                            connected = true;
                        }
                    } else if self.blocks.contains_key(&orphan.header.prev_hash) {
                        let fork_work = self.calculate_chain_work(&orphan);
                        if fork_work > self.cumulative_work {
                            self.orphans.remove(&hash);
                            self.reorganize_to_block(orphan)?;
                            connected = true;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Reorganize the chain to include the given block.
    fn reorganize_to_block(&mut self, new_tip: ShieldedBlock) -> Result<(), BlockchainError> {
        // Check checkpoint finality: reject reorgs that would go below the checkpoint
        if crate::config::CHECKPOINT_ENABLED && self.last_checkpoint_height > 0 {
            let fork_height = self.calculate_chain_height(&new_tip);
            if fork_height <= self.last_checkpoint_height {
                tracing::warn!(
                    "Rejecting reorg: fork height {} does not exceed checkpoint at {}",
                    fork_height,
                    self.last_checkpoint_height
                );
                return Err(BlockchainError::CheckpointViolation(self.last_checkpoint_height));
            }

            // Verify the new chain includes the checkpoint block
            if let Some(cp_hash) = self.last_checkpoint_hash {
                let mut includes_checkpoint = false;
                let mut prev = new_tip.header.prev_hash;
                while let Some(block) = self.blocks.get(&prev) {
                    if prev == cp_hash {
                        includes_checkpoint = true;
                        break;
                    }
                    if block.header.prev_hash == [0u8; BLOCK_HASH_SIZE] {
                        break;
                    }
                    prev = block.header.prev_hash;
                }
                if !includes_checkpoint {
                    tracing::warn!(
                        "Rejecting reorg: new chain does not include checkpoint block at height {}",
                        self.last_checkpoint_height
                    );
                    return Err(BlockchainError::CheckpointViolation(self.last_checkpoint_height));
                }
            }
        }

        // Build the new chain path from genesis to new_tip
        let mut new_chain: Vec<ShieldedBlock> = vec![new_tip.clone()];
        let mut prev_hash = new_tip.header.prev_hash;

        while prev_hash != [0u8; 32] {
            if let Some(block) = self.blocks.get(&prev_hash).cloned() {
                prev_hash = block.header.prev_hash;
                new_chain.push(block);
            } else {
                return Err(BlockchainError::InvalidPrevHash);
            }
        }

        new_chain.reverse();

        // Rebuild state from genesis
        let mut new_state = ShieldedState::new();
        let mut new_height_index = Vec::new();
        let mut new_difficulty = self.difficulty;
        let mut new_cumulative_work: u128 = 0;

        for block in &new_chain {
            for tx in &block.transactions {
                new_state.apply_transaction(tx);
            }
            new_state.apply_coinbase(&block.coinbase);
            new_height_index.push(block.hash());
            new_difficulty = block.header.difficulty;
            new_cumulative_work += block.header.difficulty as u128;
        }

        // Add new tip to blocks
        let new_tip_hash = new_tip.hash();
        self.blocks.insert(new_tip_hash, new_tip.clone());

        // Switch to new chain
        self.state = new_state;
        self.height_index = new_height_index.clone();
        self.difficulty = new_difficulty;
        self.cumulative_work = new_cumulative_work;

        // Persist the reorganized chain if we have a database
        if let Some(ref db) = self.db {
            tracing::info!("Persisting chain reorganization (new height: {})", new_height_index.len() - 1);

            // Clear nullifiers and rebuild from new chain
            db.clear_nullifiers()
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;

            // Re-persist all blocks in the new chain
            for (height, hash) in new_height_index.iter().enumerate() {
                if let Some(block) = self.blocks.get(hash) {
                    db.save_block(block, height as u64)
                        .map_err(|e| BlockchainError::StorageError(e.to_string()))?;

                    // Save nullifiers from this block
                    for tx in &block.transactions {
                        for spend in &tx.spends {
                            db.save_nullifier(&spend.nullifier.to_bytes())
                                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
                        }
                    }
                }
            }

            // Update metadata
            db.set_metadata("difficulty", &new_difficulty.to_string())
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;

            db.flush()
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
        }

        Ok(())
    }

    /// Get the number of orphan blocks.
    pub fn orphan_count(&self) -> usize {
        self.orphans.len()
    }

    /// Create a coinbase transaction for a new block.
    /// Splits reward: 92% to miner, 5% dev fees to treasury, 3% relay pool.
    pub fn create_coinbase(
        &self,
        miner_pk_hash: [u8; 32],
        _viewing_key: &ViewingKey,  // Kept for API compatibility but not used
        extra_fees: u64,
    ) -> CoinbaseTransaction {
        use ark_serialize::CanonicalSerialize;
        use crate::config;

        let mut rng = ark_std::rand::thread_rng();
        let height = self.height() + 1;
        let base_reward = crate::config::block_reward_at_height(height);
        let total_reward = base_reward + extra_fees;

        // Split reward: 92% miner, 5% dev fees, 3% relay pool
        let miner_amount = config::miner_reward(total_reward);
        let dev_amount = config::dev_fee(total_reward);
        // Note: relay_pool(total_reward) = 3% accumulated for relay node distribution

        // --- Miner note (92%) ---
        let miner_note = Note::new(miner_amount, miner_pk_hash, &mut rng);
        let miner_key = ViewingKey::from_pk_hash(miner_pk_hash);
        let miner_encrypted = miner_key.encrypt_note(&miner_note, &mut rng);

        let miner_commitment_v1 = miner_note.commitment();

        let mut miner_randomness_bytes = [0u8; 32];
        miner_note.randomness.serialize_compressed(&mut miner_randomness_bytes[..]).unwrap();
        let miner_commitment_pq = commit_to_note_pq(miner_amount, &miner_pk_hash, &miner_randomness_bytes);

        // --- Dev fees note (5%) ---
        let treasury_pk_hash = config::DEV_TREASURY_PK_HASH;
        let dev_note = Note::new(dev_amount, treasury_pk_hash, &mut rng);
        let treasury_key = ViewingKey::from_pk_hash(treasury_pk_hash);
        let dev_encrypted = treasury_key.encrypt_note(&dev_note, &mut rng);

        let dev_commitment_v1 = dev_note.commitment();

        let mut dev_randomness_bytes = [0u8; 32];
        dev_note.randomness.serialize_compressed(&mut dev_randomness_bytes[..]).unwrap();
        let dev_commitment_pq = commit_to_note_pq(dev_amount, &treasury_pk_hash, &dev_randomness_bytes);

        CoinbaseTransaction::new_with_dev_fee(
            miner_commitment_v1,
            miner_commitment_pq,
            miner_encrypted,
            total_reward,
            height,
            dev_commitment_v1,
            dev_commitment_pq,
            dev_encrypted,
            dev_amount,
        )
    }

    /// Create a new block template for mining.
    pub fn create_block_template(
        &self,
        miner_pk_hash: [u8; 32],
        viewing_key: &ViewingKey,
        transactions: Vec<ShieldedTransaction>,
    ) -> ShieldedBlock {
        self.create_block_template_with_v2(miner_pk_hash, viewing_key, transactions, vec![])
    }

    /// Create a new block template for mining with V2 transactions.
    pub fn create_block_template_with_v2(
        &self,
        miner_pk_hash: [u8; 32],
        viewing_key: &ViewingKey,
        transactions: Vec<ShieldedTransaction>,
        transactions_v2: Vec<ShieldedTransactionV2>,
    ) -> ShieldedBlock {
        let total_fees: u64 = transactions.iter().map(|tx| tx.fee).sum::<u64>()
            + transactions_v2.iter().map(|tx| tx.fee).sum::<u64>();
        let coinbase = self.create_coinbase(miner_pk_hash, viewing_key, total_fees);

        // Calculate commitment root after applying transactions
        let mut temp_state = self.state.snapshot();
        for tx in &transactions {
            temp_state.apply_transaction(tx);
        }
        for tx in &transactions_v2 {
            temp_state.apply_transaction_v2(tx);
        }
        temp_state.apply_coinbase(&coinbase);
        let commitment_root = temp_state.commitment_root();

        // Nullifier root (simplified - just hash the count for now)
        let nullifier_root = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&(temp_state.nullifier_count() as u64).to_le_bytes());
            let hash: [u8; 32] = hasher.finalize().into();
            hash
        };

        ShieldedBlock::new_with_v2(
            self.latest_hash(),
            transactions,
            transactions_v2,
            coinbase,
            commitment_root,
            nullifier_root,
            self.next_difficulty(),
        )
    }

    /// Get the last finalized checkpoint height.
    pub fn last_checkpoint_height(&self) -> u64 {
        self.last_checkpoint_height
    }

    /// Get chain info for API responses.
    pub fn info(&self) -> ChainInfo {
        ChainInfo {
            height: self.height(),
            latest_hash: hex::encode(self.latest_hash()),
            difficulty: self.difficulty,
            next_difficulty: self.next_difficulty(),
            commitment_count: self.commitment_count(),
            nullifier_count: self.nullifier_count() as u64,
            proof_verification_enabled: self.verifying_params.is_some(),
            assume_valid_height: self.assume_valid_height,
            last_checkpoint_height: self.last_checkpoint_height,
            network_hashrate: self.estimate_network_hashrate(),
        }
    }

    /// Estimate network hashrate using Bitcoin's method:
    /// hashrate = sum(difficulty_of_each_block) / time_span
    /// over the last HASHRATE_WINDOW blocks.
    fn estimate_network_hashrate(&self) -> f64 {
        const HASHRATE_WINDOW: u64 = 120; // Same as Bitcoin Core default

        let tip = self.height();
        if tip < 2 {
            return 0.0;
        }

        let start_height = if tip > HASHRATE_WINDOW { tip - HASHRATE_WINDOW } else { 1 };

        // Get timestamps and difficulties of blocks in window
        let tip_block = match self.get_block_by_height(tip) {
            Some(b) => b,
            None => return 0.0,
        };
        let start_block = match self.get_block_by_height(start_height) {
            Some(b) => b,
            None => return 0.0,
        };

        let time_span = tip_block.header.timestamp.saturating_sub(start_block.header.timestamp);
        if time_span == 0 {
            return 0.0;
        }

        // Sum difficulties of all blocks in window (= total work done)
        let mut total_work: f64 = 0.0;
        for h in (start_height + 1)..=tip {
            if let Some(block) = self.get_block_by_height(h) {
                total_work += block.header.difficulty as f64;
            }
        }

        // hashrate = total_work / time_span (in seconds)
        total_work / time_span as f64
    }

    /// Get the current assume-valid height.
    pub fn assume_valid_height(&self) -> u64 {
        self.assume_valid_height
    }

    /// Set the assume-valid height (for testing or manual override).
    pub fn set_assume_valid_height(&mut self, height: u64) {
        self.assume_valid_height = height;
    }

    /// Get recent block hashes (for sync protocol).
    pub fn recent_hashes(&self, count: usize) -> Vec<[u8; 32]> {
        let start = self.height_index.len().saturating_sub(count);
        self.height_index[start..].to_vec()
    }

    /// Get a Merkle path for a commitment at a given position.
    pub fn get_merkle_path(
        &self,
        position: u64,
    ) -> Option<crate::crypto::merkle_tree::MerklePath> {
        self.state.get_merkle_path(position)
    }

    /// Get recent valid anchors.
    pub fn recent_anchors(&self) -> Vec<[u8; 32]> {
        self.state.recent_roots().to_vec()
    }

    /// Export state snapshot data for fast sync download.
    /// Returns (snapshot_json_bytes, height, block_hash_at_height).
    pub fn export_snapshot(&self) -> Option<(Vec<u8>, u64, String)> {
        let snapshot = self.state.snapshot_pq();
        let height = self.height();
        let hash = hex::encode(self.latest_hash());
        let data = serde_json::to_vec(&snapshot).ok()?;
        Some((data, height, hash))
    }

    /// Import a state snapshot from a peer, setting the chain to the given height.
    /// This skips block replay entirely — the state is trusted (verified by checkpoints after).
    /// Only the last few blocks are synced normally to build the height index tail.
    pub fn import_snapshot_at_height(
        &mut self,
        snapshot: crate::core::StateSnapshotPQ,
        height: u64,
        block_hash: [u8; 32],
        difficulty: u64,
        next_difficulty: u64,
    ) {
        // Restore state
        self.state.restore_pq_from_snapshot(snapshot.clone());

        // Set chain metadata — use next_difficulty so validation works after fast-sync
        self.difficulty = next_difficulty;
        self.cumulative_work = difficulty as u128 * height as u128; // approximate
        self.fast_sync_base_height = height;

        // Build a minimal height index (we'll fill in real hashes when we sync recent blocks)
        // For now, put placeholder hashes — the important thing is height() returns the right value
        self.height_index.clear();
        for _ in 0..height {
            self.height_index.push([0u8; 32]); // placeholder
        }
        // Set the tip hash correctly
        self.height_index.push(block_hash);

        // Update checkpoint
        self.last_checkpoint_height = height;
        self.last_checkpoint_hash = Some(block_hash);

        // Save snapshot to local DB for fast restart
        if let Some(ref db) = self.db {
            if let Err(e) = db.save_state_snapshot(&snapshot, height) {
                tracing::warn!("Failed to save imported snapshot: {}", e);
            }
            let _ = db.set_metadata("height", &height.to_string());
            let _ = db.set_metadata("difficulty", &difficulty.to_string());
            let _ = db.set_metadata("cumulative_work", &self.cumulative_work.to_string());
            let _ = db.set_metadata("latest_hash", &hex::encode(block_hash));
            let _ = db.set_metadata("fast_sync_base_height", &height.to_string());
            let _ = db.flush();
        }

        tracing::info!(
            "Snapshot imported: height={}, commitments={}, nullifiers={}",
            height, self.state.commitment_count(), self.state.nullifier_count()
        );
    }
}

/// Summary information about the chain.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChainInfo {
    pub height: u64,
    pub latest_hash: String,
    pub difficulty: u64,
    pub next_difficulty: u64,
    pub commitment_count: u64,
    pub nullifier_count: u64,
    pub proof_verification_enabled: bool,
    /// Assume-valid checkpoint height. Blocks at or below this height
    /// skip ZK proof verification during sync. Set to 0 if disabled.
    pub assume_valid_height: u64,
    /// Height of the last finalized checkpoint. Reorgs below this height
    /// are rejected. Set to 0 if no checkpoint yet.
    pub last_checkpoint_height: u64,
    /// Estimated network hashrate in H/s (Bitcoin-style: sum(difficulty) / time_span over last N blocks)
    pub network_hashrate: f64,
}

#[derive(Debug, thiserror::Error)]
pub enum BlockchainError {
    #[error("Block error: {0}")]
    BlockError(#[from] BlockError),

    #[error("State error: {0}")]
    StateError(#[from] StateError),

    #[error("Invalid previous block hash")]
    InvalidPrevHash,

    #[error("Invalid difficulty")]
    InvalidDifficulty,

    #[error("Invalid coinbase")]
    InvalidCoinbase,

    #[error("Invalid coinbase amount")]
    InvalidCoinbaseAmount,

    #[error("Invalid commitment root")]
    InvalidCommitmentRoot,

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Checkpoint violation: cannot reorganize below finalized height {0}")]
    CheckpointViolation(u64),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::note::{compute_pk_hash, ViewingKey};

    fn test_viewing_key() -> ViewingKey {
        ViewingKey::new(b"test_miner_key")
    }

    fn test_pk_hash() -> [u8; 32] {
        compute_pk_hash(b"test_miner_public_key")
    }

    #[test]
    fn test_new_blockchain() {
        let vk = test_viewing_key();
        let pk_hash = test_pk_hash();
        let coinbase = ShieldedBlockchain::create_genesis_coinbase(pk_hash, &vk);
        let chain = ShieldedBlockchain::new(MIN_DIFFICULTY, coinbase);

        assert_eq!(chain.height(), 0);
        assert!(chain.get_block_by_height(0).is_some());
        assert_eq!(chain.commitment_count(), 1); // Genesis coinbase
    }

    #[test]
    fn test_chain_info() {
        let vk = test_viewing_key();
        let pk_hash = test_pk_hash();
        let coinbase = ShieldedBlockchain::create_genesis_coinbase(pk_hash, &vk);
        let chain = ShieldedBlockchain::new(8, coinbase);

        let info = chain.info();
        assert_eq!(info.height, 0);
        assert_eq!(info.difficulty, 8);
        assert_eq!(info.commitment_count, 1);
        assert_eq!(info.nullifier_count, 0);
    }

    #[test]
    fn test_create_block_template() {
        let vk = test_viewing_key();
        let pk_hash = test_pk_hash();
        let coinbase = ShieldedBlockchain::create_genesis_coinbase(pk_hash, &vk);
        let chain = ShieldedBlockchain::new(MIN_DIFFICULTY, coinbase);

        let template = chain.create_block_template(pk_hash, &vk, vec![]);

        assert_eq!(template.header.prev_hash, chain.latest_hash());
        assert_eq!(template.coinbase.height, 1);
        assert_eq!(template.coinbase.reward, BLOCK_REWARD);
    }

    #[test]
    fn test_commitment_tracking() {
        let vk = test_viewing_key();
        let pk_hash = test_pk_hash();
        let coinbase = ShieldedBlockchain::create_genesis_coinbase(pk_hash, &vk);
        let chain = ShieldedBlockchain::new(MIN_DIFFICULTY, coinbase);

        // Genesis creates one commitment
        assert_eq!(chain.commitment_count(), 1);

        // Commitment root should not be empty
        assert_ne!(chain.commitment_root(), [0u8; 32]);
    }

    #[test]
    fn test_persistence_roundtrip() {
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_blockchain");
        let db_path_str = db_path.to_str().unwrap();

        let genesis_hash;
        let genesis_commitment_root;

        // Create and persist a blockchain
        {
            let chain = ShieldedBlockchain::open(db_path_str, MIN_DIFFICULTY).unwrap();
            assert_eq!(chain.height(), 0);
            genesis_hash = chain.latest_hash();
            genesis_commitment_root = chain.commitment_root();
        }

        // Reopen and verify data persisted
        {
            let chain = ShieldedBlockchain::open(db_path_str, MIN_DIFFICULTY).unwrap();
            assert_eq!(chain.height(), 0);
            assert_eq!(chain.latest_hash(), genesis_hash);
            assert_eq!(chain.commitment_root(), genesis_commitment_root);
            assert_eq!(chain.commitment_count(), 1);
        }
    }

    #[test]
    fn test_persistence_with_blocks() {
        use tempfile::tempdir;
        use crate::consensus::mine_block;

        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_blockchain_blocks");
        let db_path_str = db_path.to_str().unwrap();

        let vk = test_viewing_key();
        let pk_hash = test_pk_hash();

        let block1_hash;
        let final_commitment_count;

        // Create blockchain, mine a block, persist
        {
            let mut chain = ShieldedBlockchain::open(db_path_str, MIN_DIFFICULTY).unwrap();
            assert_eq!(chain.height(), 0);

            // Create and mine a block
            let mut block = chain.create_block_template(pk_hash, &vk, vec![]);
            mine_block(&mut block);

            chain.add_block(block.clone()).unwrap();
            assert_eq!(chain.height(), 1);

            block1_hash = block.hash();
            final_commitment_count = chain.commitment_count();
        }

        // Reopen and verify blocks persisted
        {
            let chain = ShieldedBlockchain::open(db_path_str, MIN_DIFFICULTY).unwrap();
            assert_eq!(chain.height(), 1);
            assert_eq!(chain.latest_hash(), block1_hash);
            assert_eq!(chain.commitment_count(), final_commitment_count);

            // Verify we can get the block by height
            let loaded_block = chain.get_block_by_height(1).unwrap();
            assert_eq!(loaded_block.hash(), block1_hash);
        }
    }
}
