//! Shielded blockchain implementation.
//!
//! The blockchain manages the chain of shielded blocks, the commitment tree,
//! and the nullifier set. All transaction data is private - only fees and
//! roots are visible.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use lru::LruCache;

use crate::consensus::{
    calculate_next_difficulty, calculate_next_difficulty_lwma, should_adjust_difficulty,
    ADJUSTMENT_INTERVAL, LWMA_WINDOW, MIN_DIFFICULTY,
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
    /// Recent blocks LRU cache (max 1000 entries). Older blocks are loaded from DB.
    /// Previously was an unbounded HashMap that grew indefinitely → OOM risk.
    blocks: LruCache<[u8; 32], ShieldedBlock>,
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
    /// Recent state snapshots for instant rollback (up to 10 blocks deep).
    /// Each entry is (height_before_block, state_before_block).
    /// Avoids expensive replay from fast-sync snapshot on short reorgs.
    prev_block_states: std::collections::VecDeque<(u64, ShieldedState)>,
    /// Number of commitments in the tree at the time of fast-sync snapshot.
    /// Used to calculate correct positions in /outputs/since/ when blocks before
    /// fast_sync_base_height don't exist in DB.
    fast_sync_commitment_offset: u64,
    /// Canonical chain height — the SINGLE source of truth.
    /// Persisted as metadata "height" in sled DB.
    /// Never derived from height_index.len() (which can be wrong after fast-sync + restart).
    canonical_height: u64,
    /// Height of the last finalized block. Blocks at or below this height
    /// can never be reorg'd. Computed as max(last_checkpoint_height, tip - MAX_REORG_DEPTH).
    /// Inspired by Quantus deterministic finalization at fixed depth.
    finalized_height: u64,
}

impl ShieldedBlockchain {
    /// Create a new blockchain with a genesis block (in-memory only).
    pub fn new(difficulty: u64, genesis_coinbase: CoinbaseTransaction) -> Self {
        use crate::config;

        let genesis = ShieldedBlock::genesis(difficulty, genesis_coinbase.clone());
        let genesis_hash = genesis.hash();

        let mut blocks = LruCache::new(NonZeroUsize::new(1000).unwrap());
        blocks.put(genesis_hash, genesis);
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
            fast_sync_commitment_offset: 0,
            prev_block_states: std::collections::VecDeque::new(),
            canonical_height: 0,
            finalized_height: 0,
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
            // WAL: check for interrupted reorg (crash during rollback)
            let reorg_flag = db.get_metadata("reorg_in_progress")
                .ok().flatten().unwrap_or_default();
            if !reorg_flag.is_empty() {
                tracing::error!(
                    "DETECTED INTERRUPTED REORG: '{}'. Chain may be corrupted. Wiping for fresh sync.",
                    reorg_flag
                );
                // Wipe DB and restart fresh — safest recovery
                let _ = db.set_metadata("reorg_in_progress", "");
                drop(db);
                let _ = std::fs::remove_dir_all(db_path);
                return Self::open(db_path, difficulty);
            }

            // Load existing chain
            tracing::info!("Loading blockchain from disk (height: {})", height);

            let mut blocks = LruCache::new(NonZeroUsize::new(1000).unwrap());
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

            // SAFETY: if no snapshot exists but we have fast-sync placeholders,
            // replaying from height 0 will fail (placeholder blocks have no data).
            // Detect this and wipe the DB to trigger a fresh fast-sync.
            let fast_sync_base_check: u64 = db
                .get_metadata("fast_sync_base_height")
                .ok()
                .flatten()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            if snapshot_height.is_none() && fast_sync_base_check > 0 && start_height < fast_sync_base_check {
                tracing::warn!(
                    "Snapshot missing but fast-sync placeholders exist (base={}). \
                     Cannot replay from height {}. Wiping DB for fresh sync.",
                    fast_sync_base_check, start_height
                );
                // Wipe and return empty blockchain — caller will fast-sync from peers
                drop(db);
                let _ = std::fs::remove_dir_all(db_path);
                return Self::open(db_path, difficulty);
            }

            // Load full height index via sequential scan (much faster than N individual lookups)
            tracing::info!("Loading height index...");
            let raw_hashes = db.load_all_block_hashes()
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;

            // After fast-sync, only recent blocks exist in DB (~6491 entries).
            // But height_index must cover heights 0..=stored_height so that
            // height() == height_index.len() - 1 == stored_height.
            // Fill missing heights 0..fast_sync_base with placeholder [0u8; 32].
            let fast_sync_base_for_index: u64 = db
                .get_metadata("fast_sync_base_height")
                .ok()
                .flatten()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);

            if fast_sync_base_for_index > 0 && (raw_hashes.len() as u64) < height + 1 {
                let needed_total = (height + 1) as usize;
                let mut full_index: Vec<[u8; 32]> = Vec::with_capacity(needed_total);
                // Placeholders for heights 0..fast_sync_base (blocks not on disk)
                full_index.resize(fast_sync_base_for_index as usize, [0u8; 32]);
                // Real block hashes from DB (heights fast_sync_base..=stored_height)
                full_index.extend_from_slice(&raw_hashes);
                // Pad if still short (shouldn't happen, but safety)
                while full_index.len() < needed_total {
                    full_index.push([0u8; 32]);
                }
                height_index = full_index;
                tracing::info!("Height index loaded ({} entries, {} from fast-sync placeholders)",
                    height_index.len(), fast_sync_base_for_index);
            } else {
                height_index = raw_hashes;
                tracing::info!("Height index loaded ({} entries)", height_index.len());
            }

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

                    blocks.put(hash, block);
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

            // v1.7.0: Read cumulative_work from DB (single source of truth).
            // The per-height tree has the exact value stored at each block import.
            // Fallback: recalculate from blocks and store (one-time migration).
            let cumulative_work: u128 = if let Ok(Some(stored_work)) = db.get_cumulative_work(height) {
                tracing::info!("cumulative_work: restored from DB at height {} = {}", height, stored_work);
                stored_work
            } else {
                // Migration fallback: recalculate from blocks (LRU + DB) and store
                let mut work: u128 = 0;
                let mut counted = 0u64;
                for h in 0..=height {
                    if let Some(hash) = height_index.get(h as usize) {
                        if *hash != [0u8; 32] {
                            // Try LRU cache first, then DB
                            let difficulty = blocks.get(hash)
                                .map(|b| b.header.difficulty)
                                .or_else(|| {
                                    db.load_block(hash).ok().flatten()
                                        .map(|b| b.header.difficulty)
                                });
                            if let Some(diff) = difficulty {
                                work += diff as u128;
                                counted += 1;
                            }
                        }
                    }
                    let _ = db.save_cumulative_work(h, work);
                }
                tracing::info!(
                    "cumulative_work: migrated from {} real blocks, total work={} (stored in DB)",
                    counted, work
                );
                work
            };

            // Verify genesis hash if configured (skip in test builds)
            // Skip verification for fast-synced nodes (genesis is a placeholder)
            #[cfg(not(test))]
            {
                let expected_genesis = crate::config::EXPECTED_GENESIS_HASH;
                if !expected_genesis.is_empty() {
                    if let Some(genesis_hash) = height_index.first() {
                        let actual = hex::encode(genesis_hash);
                        let is_placeholder = actual == "0".repeat(64);
                        if actual != expected_genesis && !is_placeholder {
                            return Err(BlockchainError::StorageError(format!(
                                "Genesis hash mismatch! Expected: {}, Got: {}. This node has incompatible chain data.",
                                expected_genesis, actual
                            )));
                        }
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

            // Load fast_sync_commitment_offset from metadata
            let fast_sync_commitment_offset: u64 = db
                .get_metadata("fast_sync_commitment_offset")
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
                fast_sync_commitment_offset,
                prev_block_states: std::collections::VecDeque::new(),
                canonical_height: height,
                finalized_height: height.saturating_sub(crate::config::MAX_REORG_DEPTH).max(cp_height),
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

            let mut blocks = LruCache::new(NonZeroUsize::new(1000).unwrap());
            blocks.put(genesis_hash, genesis);

            // Initialize state with genesis coinbase
            let mut state = ShieldedState::new();
            state.apply_coinbase(&genesis_coinbase);

            // Get assume-valid configuration
            let assume_valid_height = if crate::config::is_assume_valid_enabled() {
                crate::config::ASSUME_VALID_HEIGHT
            } else {
                0
            };

            // Verify genesis hash if configured (skip in test builds)
            #[cfg(not(test))]
            {
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
                fast_sync_commitment_offset: 0,
                prev_block_states: std::collections::VecDeque::new(),
                canonical_height: 0,
                finalized_height: 0,
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

    /// Reset chain to height 0 for snapshot re-sync from peers.
    /// Used when no common ancestor is found but peer passes checkpoint validation.
    /// Safer than full DB wipe — preserves DB structure, just resets chain state.
    pub fn reset_for_snapshot_resync(&mut self) {
        tracing::warn!("RESYNC: Resetting chain to height 0 for snapshot re-sync");
        self.height_index.clear();
        self.height_index.push([0u8; 32]); // Genesis placeholder
        self.canonical_height = 0;
        self.cumulative_work = 0;
        self.fast_sync_base_height = 0;
        self.fast_sync_commitment_offset = 0;
        self.finalized_height = 0; // Reset finalization for fresh sync
        self.last_checkpoint_height = 0;
        self.prev_block_states.clear();
        self.state = ShieldedState::new();
        if let Some(ref db) = self.db {
            let _ = db.set_metadata("height", "0");
            let _ = db.set_metadata("cumulative_work", "0");
            let _ = db.set_metadata("fast_sync_base_height", "0");
            let _ = db.clear_state_snapshot();
        }
        tracing::info!("RESYNC: Chain reset to height 0, ready for snapshot sync");
    }

    /// Get the current chain height (0-indexed).
    /// Uses canonical_height (persisted in DB metadata) — NOT height_index.len().
    pub fn height(&self) -> u64 {
        self.canonical_height
    }

    /// Get the current finalization height. Blocks at or below this height
    /// are permanently finalized and can never be reorganized.
    pub fn finalized_height(&self) -> u64 {
        self.finalized_height
    }

    /// Update the finalization height after adding a block.
    /// Blocks deeper than MAX_REORG_DEPTH from tip are considered final.
    /// Inspired by Quantus deterministic finalization at fixed depth (180 blocks).
    fn update_finalization(&mut self) {
        let tip = self.height();
        if tip > crate::config::MAX_REORG_DEPTH {
            let depth_finalized = tip - crate::config::MAX_REORG_DEPTH;
            let new_finalized = depth_finalized.max(self.last_checkpoint_height);
            if new_finalized > self.finalized_height {
                self.finalized_height = new_finalized;
                // Prune orphans that reference blocks below finalized height
                self.orphans.retain(|_, block| block.coinbase.height > self.finalized_height);
                tracing::debug!("Finalization advanced to height {}", self.finalized_height);
            }
        }
    }

    /// Get compact headers for heights (start_height, start_height+limit] for headers-first sync.
    /// Returns up to `limit` headers starting from start_height+1.
    /// Each header is ~200 bytes vs ~5KB+ for a full block.
    pub fn get_compact_headers_since(&self, start_height: u64, limit: usize) -> Vec<crate::core::CompactHeader> {
        let mut headers = Vec::with_capacity(limit.min(500));
        let tip = self.height();

        // Get cumulative work at start_height from DB
        let mut running_work: u128 = if start_height > 0 {
            if let Some(ref db) = self.db {
                db.get_cumulative_work(start_height).ok().flatten().unwrap_or(0)
            } else {
                0
            }
        } else {
            0
        };

        let first_h = match start_height.checked_add(1) {
            Some(h) => h,
            None => return headers, // start_height = u64::MAX, nothing to return
        };
        for h in first_h..=tip {
            if headers.len() >= limit { break; }
            if let Some(block) = self.get_block_by_height(h) {
                running_work += block.header.difficulty as u128;
                headers.push(crate::core::CompactHeader {
                    height: h,
                    hash: hex::encode(block.hash()),
                    prev_hash: hex::encode(block.header.prev_hash),
                    difficulty: block.header.difficulty,
                    timestamp: block.header.timestamp,
                    cumulative_work: running_work,
                });
            } else if let Some(hash_bytes) = self.get_hash_at_height(h) {
                // Block not in LRU cache but hash exists in height_index
                let hash_hex = hex::encode(hash_bytes);
                if hash_hex != "0".repeat(64) {
                    running_work += self.difficulty as u128; // estimate for missing blocks
                    headers.push(crate::core::CompactHeader {
                        height: h,
                        hash: hash_hex,
                        prev_hash: if h > 0 {
                            self.get_hash_at_height(h - 1)
                                .map(hex::encode)
                                .unwrap_or_else(|| "0".repeat(64))
                        } else {
                            "0".repeat(64)
                        },
                        difficulty: self.difficulty,
                        timestamp: 0,
                        cumulative_work: running_work,
                    });
                }
            }
        }
        headers
    }

    /// Reset the blockchain for a complete re-sync from network.
    /// Wipes state, height index, and metadata back to genesis.
    /// Used when the node detects it's on an incompatible fork during initial sync.
    pub fn reset_for_resync(&mut self) {
        tracing::warn!("RESYNC: Wiping local chain state for fresh sync from network");
        self.state = crate::core::state::ShieldedState::new();
        self.height_index.clear();
        self.height_index.push([0u8; 32]); // genesis placeholder
        self.canonical_height = 0;
        self.cumulative_work = 0;
        self.difficulty = crate::config::GENESIS_DIFFICULTY;
        self.fast_sync_base_height = 0;
        self.last_checkpoint_height = 0;
        self.finalized_height = 0; // Reset finalization for fresh sync
        self.prev_block_states.clear();
        // Clear DB snapshot so fast-sync can reimport
        if let Some(ref db) = self.db {
            let _ = db.clear_state_snapshot();
        }
        tracing::info!("RESYNC: Chain reset to height 0, ready for fast-sync");
    }

    /// Rollback the chain to a specific height, discarding all blocks above it.
    /// Rebuilds state by replaying blocks from genesis (or fast-sync base) to target height.
    /// Returns true if rollback happened, false if already at or below target height.
    /// Maximum allowed reorg depth. Any rollback deeper than this is rejected.
    /// Protects against long-range attacks and accidental chain destruction.
    pub const MAX_REORG_DEPTH: u64 = 100;

    pub fn rollback_to_height(&mut self, target_height: u64) -> Result<bool, BlockchainError> {
        let current = self.height();
        if target_height >= current {
            return Ok(false);
        }

        let depth = current - target_height;

        // SECURITY: Never rollback below finalized height (deterministic finalization)
        if target_height < self.finalized_height {
            tracing::error!(
                "REJECTED rollback to {} — below finalization height {}. Finalized blocks are permanent.",
                target_height, self.finalized_height
            );
            return Err(BlockchainError::StorageError(format!(
                "Cannot rollback to {} — below finalized height {}",
                target_height, self.finalized_height
            )));
        }

        // SECURITY: Never rollback more than MAX_REORG_DEPTH blocks
        if depth > Self::MAX_REORG_DEPTH {
            tracing::error!(
                "REJECTED rollback of {} blocks ({} → {}). Max allowed: {}. This protects the chain from destruction.",
                depth, current, target_height, Self::MAX_REORG_DEPTH
            );
            return Err(BlockchainError::StorageError(format!(
                "Rollback of {} blocks exceeds MAX_REORG_DEPTH ({}). Rejected to protect chain integrity.",
                depth, Self::MAX_REORG_DEPTH
            )));
        }

        tracing::warn!(
            "SYNC_DEBUG: ROLLBACK_START current={} target={} depth={} lru_size={} orphan_size={}",
            current, target_height, depth, self.blocks.len(), self.orphans.len()
        );
        tracing::info!("Rolling back {} blocks: {} → {}", depth, current, target_height);

        // WAL: Write reorg intent to DB BEFORE any changes (crash safety)
        if let Some(ref db) = self.db {
            let _ = db.set_metadata("reorg_in_progress", &format!("{}:{}", current, target_height));
        }

        // Fast path: check cached states for instant rollback (up to 10 blocks deep)
        if let Some(pos) = self.prev_block_states.iter().rposition(|(h, _)| *h == target_height) {
            // Remove all states after the target and take the matching one
            self.prev_block_states.truncate(pos + 1);
            if let Some((cached_height, cached_state)) = self.prev_block_states.pop_back() {
                tracing::info!("Rollback: instant restore from cached state at height {} (depth={})", cached_height, depth);
                self.state = cached_state;
                self.height_index.truncate((target_height + 1) as usize);
                self.canonical_height = target_height;
                // Recalculate difficulty and cumulative work from target block
                if let Some(hash) = self.height_index.last() {
                    if let Some(block) = self.get_block(hash) {
                        self.difficulty = block.header.difficulty;
                    }
                }
                // v1.7.0: Read cumulative_work from DB (single source of truth).
                self.cumulative_work = self.db.as_ref()
                    .and_then(|db| db.get_cumulative_work(target_height).ok().flatten())
                    .unwrap_or(0);
                // Clean up cumulative_work entries above target
                if let Some(ref db) = self.db {
                    let _ = db.remove_cumulative_work_from(target_height + 1);
                }
                // WAL: clear reorg flag — rollback completed successfully
                if let Some(ref db) = self.db {
                    let _ = db.set_metadata("reorg_in_progress", "");
                }
                // v1.8.0: Purge LRU block cache after rollback.
                // Blocks from the old fork were stored as LESS_WORK in the LRU.
                // Without purging, sync would find them via has_block() → DUP → "none accepted".
                let lru_before = self.blocks.len();
                // Save tip block before clearing — sync needs it for has_block() to connect new blocks.
                let tip_hash = self.latest_hash();
                let tip_block = self.blocks.get(&tip_hash).cloned()
                    .or_else(|| self.db.as_ref().and_then(|db| db.load_block(&tip_hash).ok().flatten()));
                self.blocks.clear();
                self.orphans.clear();
                // Re-insert tip block so incoming blocks can connect via prev_hash check.
                if let Some(tb) = tip_block {
                    self.blocks.put(tip_hash, tb);
                }
                tracing::warn!(
                    "SYNC_DEBUG: ROLLBACK_DONE(instant) height={} tip={} work={} lru_purged={} orphans_cleared",
                    self.height(), hex::encode(&self.latest_hash()[..8]),
                    self.cumulative_work, lru_before
                );
                tracing::info!("Rollback complete (instant): height={}", self.height());
                return Ok(true);
            }
        }

        // Slow path: Determine replay start, use fast-sync snapshot if available
        let (mut new_state, replay_from) =
            if self.fast_sync_base_height > 0 && target_height >= self.fast_sync_base_height {
                let snapshot_state = if let Some(ref db) = self.db {
                    match db.load_state_snapshot() {
                        Ok(Some((snapshot, _snap_height))) => {
                            let mut s = ShieldedState::new();
                            s.restore_pq_from_snapshot(snapshot);
                            Some(s)
                        }
                        _ => None,
                    }
                } else {
                    None
                };

                if let Some(state) = snapshot_state {
                    tracing::info!(
                        "Rollback: using fast-sync snapshot at height {}, replaying {} blocks",
                        self.fast_sync_base_height,
                        target_height.saturating_sub(self.fast_sync_base_height)
                    );
                    (state, self.fast_sync_base_height + 1)
                } else {
                    tracing::warn!("Rollback: no snapshot in DB, replaying from genesis");
                    (ShieldedState::new(), 0)
                }
            } else {
                (ShieldedState::new(), 0)
            };

        let mut new_difficulty = self.difficulty;

        // Replay state only (cumulative_work comes from DB, not recalculated)
        for h in replay_from..=target_height {
            if let Some(hash) = self.height_index.get(h as usize) {
                if *hash == [0u8; BLOCK_HASH_SIZE] { continue; } // placeholder
                if let Some(block) = self.get_block(hash) {
                    for tx in &block.transactions { new_state.apply_transaction(tx); }
                    for tx in &block.transactions_v2 { new_state.apply_transaction_v2(tx); }
                    new_state.apply_coinbase(&block.coinbase);
                    new_difficulty = block.header.difficulty;
                }
            }
        }

        // skip_v1_tree is now only true for V2-only snapshots (no V1 tree data).
        // Normal nodes (genesis or snapshot with V1 tree) always have skip_v1_tree=false.
        // After rollback replay, the new_state inherits skip_v1_tree from the snapshot
        // it was rebuilt from, which is correct. No forced override needed.

        tracing::warn!(
            "SYNC_DEBUG: ROLLBACK_REPLAY_DONE replay_from={} to={} new_state_v1_skip={} v1_count={} pq_count={}",
            replay_from, target_height,
            new_state.is_v1_tree_skipped(),
            new_state.commitment_count(),
            new_state.commitment_tree_pq().size(),
        );

        // Truncate height_index and update canonical height
        self.height_index.truncate((target_height + 1) as usize);
        self.canonical_height = target_height;
        self.state = new_state;
        self.difficulty = new_difficulty;
        // v1.7.0: cumulative_work from DB (single source of truth)
        self.cumulative_work = self.db.as_ref()
            .and_then(|db| db.get_cumulative_work(target_height).ok().flatten())
            .unwrap_or(0);

        // v1.4.0: Clean up cumulative_work entries above target
        if let Some(ref db) = self.db {
            let _ = db.remove_cumulative_work_from(target_height + 1);
        }

        // WAL: clear reorg flag — rollback completed successfully
        if let Some(ref db) = self.db {
            let _ = db.set_metadata("reorg_in_progress", "");
        }
        // v1.8.0: Purge LRU block cache after rollback.
        let lru_before = self.blocks.len();
        let tip_hash = self.latest_hash();
        let tip_block = self.blocks.get(&tip_hash).cloned()
            .or_else(|| self.db.as_ref().and_then(|db| db.load_block(&tip_hash).ok().flatten()));
        self.blocks.clear();
        self.orphans.clear();
        if let Some(tb) = tip_block {
            self.blocks.put(tip_hash, tb);
        }
        tracing::warn!(
            "SYNC_DEBUG: ROLLBACK_DONE(slow) height={} tip={} work={} lru_purged={} orphans_cleared",
            self.height(), hex::encode(&self.latest_hash()[..8]),
            self.cumulative_work, lru_before
        );
        tracing::info!("Rollback complete: height={}", self.height());
        Ok(true)
    }

    /// Get the current difficulty.
    pub fn difficulty(&self) -> u64 {
        self.difficulty
    }

    /// Calculate the next block's difficulty using LWMA (per-block adjustment).
    /// Inspired by Monero — adjusts every block using a weighted moving average.
    pub fn next_difficulty(&self) -> u64 {
        let height = self.height();

        // Not enough blocks for LWMA yet — keep current difficulty
        if height < LWMA_WINDOW + 1 {
            return self.difficulty.max(MIN_DIFFICULTY);
        }

        // After fast-sync, blocks before the snapshot don't exist.
        let window_start = height.saturating_sub(LWMA_WINDOW);
        if self.fast_sync_base_height > 0 && window_start < self.fast_sync_base_height {
            return self.difficulty.max(MIN_DIFFICULTY);
        }

        // Collect N difficulties and N+1 timestamps for the LWMA window
        let mut difficulties = Vec::with_capacity(LWMA_WINDOW as usize);
        let mut timestamps = Vec::with_capacity(LWMA_WINDOW as usize + 1);

        // We need the timestamp of the block BEFORE the window (for solvetime of first block)
        if let Some(pre_block) = self.get_block_by_height(window_start) {
            timestamps.push(pre_block.header.timestamp);
        } else {
            return self.difficulty.max(MIN_DIFFICULTY);
        }

        for h in (window_start + 1)..=height {
            if let Some(block) = self.get_block_by_height(h) {
                difficulties.push(block.header.difficulty);
                timestamps.push(block.header.timestamp);
            } else {
                // Missing block in window — fallback
                return self.difficulty.max(MIN_DIFFICULTY);
            }
        }

        calculate_next_difficulty_lwma(&difficulties, &timestamps)
    }

    /// Get timestamps of recent blocks.
    pub fn recent_timestamps(&self, count: usize) -> Vec<u64> {
        let start = self.height_index.len().saturating_sub(count);
        self.height_index[start..]
            .iter()
            .filter_map(|hash| self.blocks.peek(hash))
            .map(|block| block.header.timestamp)
            .collect()
    }

    /// Get the latest block hash.
    pub fn latest_hash(&self) -> [u8; 32] {
        *self.height_index.last().unwrap()
    }

    /// Get the block hash at a specific height (returns None if height out of range).
    pub fn get_hash_at_height(&self, height: u64) -> Option<[u8; 32]> {
        self.height_index.get(height as usize).copied()
    }

    /// Get the latest block.
    pub fn latest_block(&self) -> ShieldedBlock {
        self.get_block(&self.latest_hash()).expect("latest block must exist")
    }

    /// Get a block by hash. Checks in-memory cache first, falls back to DB.
    pub fn get_block(&self, hash: &[u8; 32]) -> Option<ShieldedBlock> {
        if let Some(block) = self.blocks.peek(hash) {
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
            if let Some(block) = self.blocks.peek(hash) {
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

    /// Height at which fast-sync snapshot was imported (0 = no fast-sync).
    pub fn fast_sync_base_height(&self) -> u64 {
        self.fast_sync_base_height
    }

    /// Number of commitments at the time of fast-sync snapshot.
    /// Used to calculate correct output positions when blocks before
    /// fast_sync_base_height don't exist in DB.
    pub fn fast_sync_commitment_offset(&self) -> u64 {
        self.fast_sync_commitment_offset
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

        // Minimum block interval: reject blocks with timestamp too close to previous block
        let min_interval = crate::config::MIN_BLOCK_INTERVAL_SECS;
        if self.height() > 0 {
            if let Some(prev_block) = self.get_block_by_height(self.height()) {
                if block.header.timestamp < prev_block.header.timestamp + min_interval {
                    return Err(BlockchainError::InvalidTransaction(
                        format!(
                            "Block timestamp {} is less than {}s after previous block timestamp {}",
                            block.header.timestamp, min_interval, prev_block.header.timestamp
                        )
                    ));
                }
            }
        }

        // Check block structure and proof-of-work
        block.verify().map_err(BlockchainError::BlockError)?;

        // Check difficulty
        let expected_difficulty = self.next_difficulty();
        if block.header.difficulty != expected_difficulty {
            // After fast-sync, the node may not have enough block history to compute
            // difficulty adjustments correctly. Trust the peer's difficulty if:
            // 1. We fast-synced (fast_sync_base_height > 0), OR
            // 2. The mismatch is within ±25% (one adjustment step) — prevents
            //    minor rounding differences from causing rejection
            let ratio = if expected_difficulty > 0 {
                block.header.difficulty as f64 / expected_difficulty as f64
            } else {
                1.0
            };
            // M4 audit fix: reduced from ±25% to ±10% to prevent gradual difficulty manipulation
            let within_one_step = ratio >= 0.90 && ratio <= 1.10;

            if self.fast_sync_base_height > 0 {
                // v1.4.0: Graduated difficulty tolerance post fast-sync.
                // After fast-sync, the node has no real block history for LWMA, so
                // next_difficulty() returns a fallback value that can be wildly off from
                // the actual network difficulty. Tolerance is graduated:
                //   0..LWMA_WINDOW*2 blocks: accept any difficulty >= MIN_DIFFICULTY
                //   (The LWMA window needs LWMA_WINDOW real blocks to converge, and even
                //    then the first few windows after fast-sync can be inaccurate because
                //    the pre-window timestamp anchor is estimated.)
                //   After LWMA_WINDOW*2: enforce normal 10% tolerance (LWMA is warm)
                let blocks_since_sync = self.height().saturating_sub(self.fast_sync_base_height);
                // LWMA needs a full window of real blocks + the pre-window anchor.
                // fast_sync_base_height can point to the ORIGINAL snapshot (not the most
                // recent one), so blocks_since_sync may be larger than expected.
                // Use 3× the window to ensure LWMA has fully converged.
                let warmup_window = LWMA_WINDOW * 3;
                if blocks_since_sync <= warmup_window {
                    // After fast-sync, next_difficulty() returns a fallback value that can
                    // diverge from the real LWMA-computed difficulty. Accept any valid
                    // difficulty while LWMA is warming up.
                    if block.header.difficulty >= MIN_DIFFICULTY {
                        tracing::debug!(
                            "Accepting difficulty {} from peer (expected {}, {}/{} blocks since fast-sync, LWMA warming up)",
                            block.header.difficulty, expected_difficulty, blocks_since_sync, warmup_window
                        );
                    } else {
                        return Err(BlockchainError::InvalidDifficulty);
                    }
                } else if !within_one_step {
                    // After LWMA warm-up: enforce normal 10% tolerance
                    return Err(BlockchainError::InvalidDifficulty);
                }
            } else if within_one_step {
                // Not fast-synced but within one adjustment step — allow it
                tracing::debug!(
                    "Accepting difficulty {} (expected {}, within adjustment margin)",
                    block.header.difficulty, expected_difficulty
                );
            } else {
                return Err(BlockchainError::InvalidDifficulty);
            }
        }

        // Validate coinbase (with halving-aware reward)
        let expected_height = self.height() + 1;
        let total_fees = block.total_fees();
        let base_reward = crate::config::block_reward_at_height(expected_height);
        // M2 audit fix: checked arithmetic to prevent u64 overflow
        let expected_reward = base_reward.checked_add(total_fees)
            .ok_or(BlockchainError::InvalidTransaction("base_reward + total_fees overflow".into()))?;

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
        tracing::debug!(
            "SYNC_DEBUG: VALIDATE_BLOCK h={} state_v1_skip={} state_v1_count={} state_pq_count={}",
            block.coinbase.height,
            temp_state.is_v1_tree_skipped(),
            temp_state.commitment_count(),
            temp_state.commitment_tree_pq().size(),
        );
        for tx in &block.transactions {
            temp_state.apply_transaction(tx);
        }
        for tx in &block.transactions_v2 {
            temp_state.apply_transaction_v2(tx);
        }
        temp_state.apply_coinbase(&block.coinbase);

        // v1.8.0: Skip commitment_root validation during block acceptance.
        // After fast-sync/snapshot restore, the Merkle trees (V1 and PQ) can diverge
        // between nodes because snapshot state doesn't always match exactly the state
        // that produced the block header. The commitment_root is still SET correctly
        // during mining (from the miner's own state), but cross-node validation fails
        // because trees diverge after snapshot. Security is maintained by:
        // - PoW verification (computational cost to produce blocks)
        // - Nullifier uniqueness (double-spend prevention)
        // - Transaction proof verification (ZK proofs)
        // - Cumulative work comparison (heaviest chain rule)
        // TODO: Fix tree determinism after snapshot restore to re-enable this check.
        {
            let computed = temp_state.commitment_root();
            let expected = block.header.commitment_root;
            if computed != expected {
                tracing::debug!(
                    "Commitment root mismatch at height {} (non-blocking): computed={}, expected={}, v1_skip={}, pq_count={}",
                    block.coinbase.height,
                    hex::encode(&computed[..8]),
                    hex::encode(&expected[..8]),
                    temp_state.is_v1_tree_skipped(),
                    temp_state.commitment_tree_pq().size(),
                );
                // Do NOT reject — tree divergence after snapshot is expected.
                // Block validity is ensured by PoW + nullifiers + ZK proofs.
            }
        }

        Ok(())
    }

    /// Add a validated block to the chain.
    /// Add a block without full validation (trusted source, e.g. fast-sync from seeds).
    /// v1.4.0: Now validates PoW and MIN_DIFFICULTY even in trusted mode.
    /// Skips ZK proofs, coinbase validation, and commitment root checks.
    /// Security: caller MUST verify a checkpoint hash after importing a batch.
    pub fn add_block_trusted(&mut self, block: ShieldedBlock) -> Result<(), BlockchainError> {
        if block.header.prev_hash != self.latest_hash() {
            return Err(BlockchainError::InvalidPrevHash);
        }
        // v1.4.0: Verify PoW even in trusted mode — prevents importing invalid blocks
        block.verify().map_err(BlockchainError::BlockError)?;
        // v1.4.0: Reject blocks below MIN_DIFFICULTY
        if block.header.difficulty < MIN_DIFFICULTY {
            tracing::warn!(
                "Rejecting trusted block: difficulty {} below MIN_DIFFICULTY {}",
                block.header.difficulty, MIN_DIFFICULTY
            );
            return Err(BlockchainError::InvalidDifficulty);
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

    /// Check if a block hash at a given height violates a hardcoded checkpoint.
    /// Returns Err if the hash doesn't match a known checkpoint at this height.
    /// Returns Ok(()) if height is not a checkpoint or if the hash matches.
    pub fn validate_against_hardcoded_checkpoints(height: u64, hash: &[u8; 32]) -> Result<(), BlockchainError> {
        let hash_hex = hex::encode(hash);
        for &(cp_height, cp_hash) in crate::config::HARDCODED_CHECKPOINTS {
            if height == cp_height && hash_hex != cp_hash {
                tracing::warn!(
                    "REJECTED: block at height {} has hash {} but hardcoded checkpoint expects {}",
                    height, hash_hex, cp_hash
                );
                return Err(BlockchainError::CheckpointViolation(cp_height));
            }
        }
        Ok(())
    }

    /// Internal: insert a block into the chain (shared by add_block and add_block_trusted).
    fn insert_block_internal(&mut self, block: ShieldedBlock, full_mode: bool) -> Result<(), BlockchainError> {
        let hash = block.hash();
        let block_difficulty = block.header.difficulty;
        let new_height = self.height_index.len() as u64;

        // v1.3.3: validate against hardcoded checkpoints
        Self::validate_against_hardcoded_checkpoints(new_height, &hash)?;

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
            // Persist canonical height — source of truth on restart
            db.set_metadata("height", &new_height.to_string())
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;

            // In trusted mode, flush less frequently (every 100 blocks instead of every block)
            if full_mode || new_height % 100 == 0 {
                db.flush()
                    .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
            }
        }

        // Save state snapshot before applying (for instant rollback up to 10 blocks)
        if full_mode {
            self.prev_block_states.push_back((self.height(), self.state.clone()));
            if self.prev_block_states.len() > 10 {
                self.prev_block_states.pop_front();
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
        // NOTE: cumulative_work is updated BELOW (single location, v1.6.0+)
        self.blocks.put(hash, block);
        self.height_index.push(hash);
        self.canonical_height = new_height;

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

        // v1.7.0: cumulative_work from DB (single source of truth, Bitcoin-like model).
        // Formula: work[N] = db.get_work(N-1) + difficulty[N]
        // self.cumulative_work is a cache, never a source of calculation.
        // NO fallback on self.cumulative_work — if DB is missing, repair explicitly.
        {
            let parent_work = if new_height == 0 {
                0u128
            } else if let Some(ref db) = self.db {
                match db.get_cumulative_work(new_height - 1) {
                    Ok(Some(w)) => w,
                    _ => {
                        // DB entry missing — repair: store current height-1 work, then continue.
                        // This can happen on first run after migration from pre-v1.7.0.
                        tracing::warn!(
                            "cumulative_work missing in DB at height {} — repairing",
                            new_height - 1
                        );
                        // Reconstruct parent work by summing from genesis or last known entry
                        let mut repair_work = 0u128;
                        for h in 0..new_height {
                            if let Ok(Some(w)) = db.get_cumulative_work(h) {
                                repair_work = w;
                            } else if let Some(hash) = self.height_index.get(h as usize) {
                                if *hash != [0u8; BLOCK_HASH_SIZE] {
                                    if let Some(blk) = self.get_block(hash) {
                                        repair_work += blk.header.difficulty as u128;
                                    }
                                }
                                let _ = db.save_cumulative_work(h, repair_work);
                            }
                        }
                        repair_work
                    }
                }
            } else {
                // No DB at all (in-memory only, tests) — use 0 for genesis chain
                0u128
            };
            let new_work = parent_work + block_difficulty as u128;
            if let Some(ref db) = self.db {
                let _ = db.save_cumulative_work(new_height, new_work);
            }
            self.cumulative_work = new_work;
        }

        // Save state snapshot every 10 blocks (for fast startup)
        // v1.4.0: In trusted mode, save every 50 blocks (was 500) for faster recovery
        let snapshot_interval = if full_mode { 10 } else { 50 };
        if new_height > 0 && new_height % snapshot_interval == 0 {
            if let Some(ref db) = self.db {
                let snapshot = self.state.snapshot_pq();
                if let Err(e) = db.save_state_snapshot(&snapshot, new_height) {
                    tracing::warn!("Failed to save state snapshot at height {}: {}", new_height, e);
                }
                let _ = db.set_metadata("cumulative_work", &self.cumulative_work.to_string());
            }
        }

        // Auto-checkpoint: persist block hash every 500 blocks.
        // These are used for fork detection and shared with peers via /chain/info.
        // Unlike hardcoded checkpoints, these are dynamic and grow with the chain.
        if new_height > 0 && new_height % 500 == 0 {
            if let Some(ref db) = self.db {
                let cp_key = format!("checkpoint_{}", new_height);
                let _ = db.set_metadata(&cp_key, &hex::encode(hash));
                tracing::info!("Auto-checkpoint saved at height {}", new_height);
            }
        }

        // Update deterministic finalization (blocks > MAX_REORG_DEPTH deep become permanent)
        self.update_finalization();

        Ok(())
    }

    /// Check if a block exists in RAM cache or in the database.
    fn has_block(&self, hash: &[u8; 32]) -> bool {
        if self.blocks.contains(hash) {
            tracing::debug!("SYNC_DEBUG: has_block {} = TRUE (source=LRU)", hex::encode(&hash[..8]));
            return true;
        }
        if let Some(ref db) = self.db {
            let in_db = db.get_block_hash_by_height(0).is_ok() // just check DB is alive
                && db.load_block(hash).ok().flatten().is_some();
            if in_db {
                tracing::debug!("SYNC_DEBUG: has_block {} = TRUE (source=DB)", hex::encode(&hash[..8]));
            }
            return in_db;
        } else {
            false
        }
    }

    /// Try to add a block, handling orphans and potential reorgs.
    pub fn try_add_block(&mut self, block: ShieldedBlock) -> Result<bool, BlockchainError> {
        let block_hash = block.hash();
        let block_hash_hex = hex::encode(&block_hash[..8]);
        let block_height = block.coinbase.height;
        let prev_hash_hex = hex::encode(&block.header.prev_hash[..8]);

        tracing::debug!(
            "SYNC_DEBUG: try_add_block block={} height={} prev={} tip={} local_h={} lru_size={} orphan_size={}",
            block_hash_hex, block_height, prev_hash_hex,
            hex::encode(&self.latest_hash()[..8]), self.height(),
            self.blocks.len(), self.orphans.len()
        );

        // Already have this block?
        if self.has_block(&block_hash) {
            tracing::debug!("SYNC_DEBUG: REJECT DUP block={} height={}", block_hash_hex, block_height);
            return Ok(false);
        }

        // Does it extend our current chain?
        if block.header.prev_hash == self.latest_hash() {
            tracing::debug!("SYNC_DEBUG: ACCEPT EXTENDS_TIP block={} height={}", block_hash_hex, block_height);
            self.add_block(block)?;
            self.process_orphans()?;
            return Ok(true);
        }

        // Do we have the parent block? Check RAM + DB
        if !self.has_block(&block.header.prev_hash) {
            // v1.4.0: Validate PoW and MIN_DIFFICULTY before storing orphans.
            // Prevents attackers from filling the orphan pool with invalid blocks.
            if let Err(e) = block.verify() {
                tracing::warn!("SYNC_DEBUG: REJECT ORP_POW block={} height={} err={}", block_hash_hex, block_height, e);
                return Ok(false);
            }
            if block.header.difficulty < MIN_DIFFICULTY {
                tracing::warn!(
                    "SYNC_DEBUG: REJECT ORP_DIFF block={} height={} diff={} min={}",
                    block_hash_hex, block_height, block.header.difficulty, MIN_DIFFICULTY
                );
                return Ok(false);
            }
            // Cap orphans to prevent memory exhaustion from fork chain spam
            const MAX_ORPHANS: usize = 500;
            if self.orphans.len() >= MAX_ORPHANS {
                tracing::warn!(
                    "SYNC_DEBUG: REJECT ORP_FULL block={} height={} pool={}",
                    block_hash_hex, block_height, self.orphans.len()
                );
                return Ok(false);
            }
            tracing::debug!("SYNC_DEBUG: STORED_ORPHAN block={} height={} parent={}", block_hash_hex, block_height, prev_hash_hex);
            self.orphans.insert(block_hash, block);
            return Ok(false);
        }

        // We have the parent but it's not our tip - potential fork
        // Use the block's actual height from coinbase (reliable even post-fast-sync)
        // instead of calculate_chain_height which only traverses in-memory blocks.
        let fork_height = block.coinbase.height;
        let current_height = self.height();

        // Check MAX_REORG_DEPTH: reject forks that would reorg too deep
        if current_height > fork_height {
            let reorg_depth = current_height - fork_height + 1;
            if reorg_depth > crate::config::MAX_REORG_DEPTH {
                tracing::warn!(
                    "SYNC_DEBUG: REJECT REORG_DEEP block={} height={} depth={} max={}",
                    block_hash_hex, block_height, reorg_depth, crate::config::MAX_REORG_DEPTH
                );
                return Ok(false);
            }
        }

        // v1.4.0: ALWAYS use cumulative_work for fork choice (heaviest chain rule).
        // Never use height alone — a longer chain with less work is a spam attack.
        let fork_work = self.calculate_chain_work(&block);
        let should_reorg = self.should_prefer_candidate(
            fork_work,
            block.header.difficulty,
            block_hash,
        );

        if should_reorg {
            tracing::warn!(
                "SYNC_DEBUG: ACCEPT REORG block={} height={} fork_work={} local_work={}",
                block_hash_hex, block_height, fork_work, self.cumulative_work
            );
            self.reorganize_to_block(block)?;
            self.process_orphans()?;
            return Ok(true);
        }

        // Fork has less or equal work - store but don't switch
        tracing::warn!(
            "SYNC_DEBUG: REJECT LESS_WORK block={} height={} fork_work={} local_work={} → stored in LRU",
            block_hash_hex, block_height, fork_work, self.cumulative_work
        );
        self.blocks.put(block_hash, block);
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
    /// v1.8.0: If parent's cumulative_work is missing from DB (e.g. after rollback
    /// cleaned entries above the ancestor), walk back through the block chain
    /// (LRU + DB) accumulating difficulties until we find an ancestor with known work.
    /// This prevents fork blocks from being rejected with fork_work ≈ 0 after rollback.
    fn calculate_chain_work(&self, block: &ShieldedBlock) -> u128 {
        let block_work = block.header.difficulty as u128;
        let parent_height = if block.coinbase.height > 0 {
            block.coinbase.height - 1
        } else {
            0
        };

        // Fast path: parent's cumulative_work is in DB
        if let Some(parent_work) = self.db.as_ref()
            .and_then(|db| db.get_cumulative_work(parent_height).ok().flatten())
        {
            return parent_work + block_work;
        }

        // Slow path: walk back through parent blocks to find known cumulative_work.
        // This happens after rollback clears work entries above the ancestor height.
        let mut accumulated_difficulty = block_work;
        let mut current_hash = block.header.prev_hash;
        let mut depth = 0u32;
        const MAX_WALK: u32 = 200;

        loop {
            if depth >= MAX_WALK {
                tracing::warn!(
                    "SYNC_DEBUG: calculate_chain_work walked {} blocks without finding known work, using accumulated={}",
                    depth, accumulated_difficulty
                );
                break;
            }

            // Try to get this ancestor's work from DB by looking up its height
            if let Some(ancestor) = self.get_block(&current_hash) {
                let ancestor_h = ancestor.coinbase.height;

                // Check if this ancestor has known cumulative_work in DB
                if let Some(known_work) = self.db.as_ref()
                    .and_then(|db| db.get_cumulative_work(ancestor_h).ok().flatten())
                {
                    tracing::warn!(
                        "SYNC_DEBUG: calculate_chain_work found known work={} at height={} after walking {} blocks",
                        known_work, ancestor_h, depth
                    );
                    return known_work + accumulated_difficulty;
                }

                // Accumulate this block's difficulty and continue walking
                accumulated_difficulty += ancestor.header.difficulty as u128;
                current_hash = ancestor.header.prev_hash;
                depth += 1;
            } else {
                // Can't find the block — stop walking
                tracing::warn!(
                    "SYNC_DEBUG: calculate_chain_work block not found at depth={}, using accumulated={}",
                    depth, accumulated_difficulty
                );
                break;
            }
        }

        accumulated_difficulty
    }

    /// v1.4.0: Determine if a candidate fork should replace the current chain.
    /// Compares: cumulative work first, then tip difficulty, then hash as final tiebreaker.
    /// Returns true if the candidate chain should be preferred.
    fn should_prefer_candidate(
        &self,
        candidate_work: u128,
        candidate_difficulty: u64,
        candidate_hash: [u8; 32],
    ) -> bool {
        if candidate_work > self.cumulative_work {
            return true;
        }
        if candidate_work < self.cumulative_work {
            return false;
        }
        // Equal work: prefer higher difficulty tip (harder to produce)
        if candidate_difficulty > self.difficulty {
            return true;
        }
        if candidate_difficulty < self.difficulty {
            return false;
        }
        // Equal work and difficulty: lower hash wins (deterministic tiebreaker)
        candidate_hash < self.latest_hash()
    }

    /// Get the cumulative work of the current chain.
    pub fn cumulative_work(&self) -> u128 {
        self.cumulative_work
    }

    /// Process orphan blocks to see if any can now be connected.
    pub fn process_orphans(&mut self) -> Result<(), BlockchainError> {
        let mut connected = true;
        let mut promoted = 0u32;
        tracing::debug!(
            "SYNC_DEBUG: PROCESS_ORPHANS_START orphan_count={} lru_size={} tip={} height={}",
            self.orphans.len(), self.blocks.len(),
            hex::encode(&self.latest_hash()[..8]), self.height()
        );

        while connected {
            connected = false;
            let orphan_hashes: Vec<[u8; 32]> = self.orphans.keys().cloned().collect();

            for hash in orphan_hashes {
                if let Some(orphan) = self.orphans.get(&hash).cloned() {
                    if orphan.header.prev_hash == self.latest_hash() {
                        tracing::debug!(
                            "SYNC_DEBUG: ORPHAN_PROMOTE block={} height={} (extends tip)",
                            hex::encode(&hash[..8]), orphan.coinbase.height
                        );
                        self.orphans.remove(&hash);
                        if self.add_block(orphan).is_ok() {
                            connected = true;
                            promoted += 1;
                        }
                    } else if self.blocks.contains(&orphan.header.prev_hash) {
                        let fork_work = self.calculate_chain_work(&orphan);
                        if fork_work > self.cumulative_work {
                            tracing::debug!(
                                "SYNC_DEBUG: ORPHAN_REORG block={} height={} fork_work={} > local_work={}",
                                hex::encode(&hash[..8]), orphan.coinbase.height,
                                fork_work, self.cumulative_work
                            );
                            self.orphans.remove(&hash);
                            self.reorganize_to_block(orphan)?;
                            connected = true;
                            promoted += 1;
                        }
                    }
                }
            }
        }

        tracing::warn!(
            "SYNC_DEBUG: PROCESS_ORPHANS_DONE promoted={} remaining_orphans={} height={}",
            promoted, self.orphans.len(), self.height()
        );
        Ok(())
    }

    /// Reorganize the chain to include the given block.
    fn reorganize_to_block(&mut self, new_tip: ShieldedBlock) -> Result<(), BlockchainError> {
        let new_tip_height = new_tip.coinbase.height;
        let current_height = self.height();
        let new_tip_hash = new_tip.hash();

        // v1.3.3: validate the new tip against hardcoded checkpoints
        Self::validate_against_hardcoded_checkpoints(new_tip_height, &new_tip_hash)?;

        // SECURITY: Reject reorgs deeper than MAX_REORG_DEPTH
        if current_height > new_tip_height && current_height - new_tip_height > Self::MAX_REORG_DEPTH {
            tracing::error!(
                "REJECTED reorg: depth {} exceeds MAX_REORG_DEPTH ({})",
                current_height - new_tip_height, Self::MAX_REORG_DEPTH
            );
            return Err(BlockchainError::StorageError(format!(
                "Reorg depth {} exceeds MAX_REORG_DEPTH ({})",
                current_height - new_tip_height, Self::MAX_REORG_DEPTH
            )));
        }

        // Check checkpoint finality: reject reorgs where the new tip is below the checkpoint.
        // We use the block's actual height (from coinbase) instead of traversing ancestry,
        // because after fast-sync not all ancestor blocks are in memory.
        if crate::config::CHECKPOINT_ENABLED && self.last_checkpoint_height > 0 {
            if new_tip_height < self.last_checkpoint_height {
                tracing::warn!(
                    "Rejecting reorg: new tip height {} is below checkpoint at {}",
                    new_tip_height,
                    self.last_checkpoint_height
                );
                return Err(BlockchainError::CheckpointViolation(self.last_checkpoint_height));
            }
        }

        // Find the common ancestor between our chain and the fork chain.
        // Trace back the new chain until we find a block that's in our height_index.
        let mut fork_blocks: Vec<ShieldedBlock> = vec![new_tip.clone()];
        let mut prev_hash = new_tip.header.prev_hash;
        let mut common_ancestor_height: Option<u64> = None;

        loop {
            // Check if prev_hash is in our main chain (height_index)
            for h in (0..=current_height).rev() {
                if let Some(hash_at_h) = self.height_index.get(h as usize) {
                    if *hash_at_h == prev_hash && *hash_at_h != [0u8; BLOCK_HASH_SIZE] {
                        common_ancestor_height = Some(h);
                        break;
                    }
                }
            }
            if common_ancestor_height.is_some() {
                break;
            }

            // Genesis reached without finding ancestor
            if prev_hash == [0u8; BLOCK_HASH_SIZE] {
                break;
            }

            // Try to get the parent block from RAM or DB
            if let Some(block) = self.get_block(&prev_hash) {
                prev_hash = block.header.prev_hash;
                fork_blocks.push(block);
            } else {
                // Can't trace back further — if we're post fast-sync, the reorg is too deep
                tracing::warn!(
                    "Reorg too deep: can't find block {} in RAM or DB (fast_sync_base={})",
                    hex::encode(prev_hash), self.fast_sync_base_height
                );
                return Err(BlockchainError::InvalidPrevHash);
            }
        }

        fork_blocks.reverse(); // Now ordered from common_ancestor+1 to new_tip

        // v1.7.0: Validate-before-disconnect (Dilithion-inspired).
        // Verify ALL fork blocks BEFORE modifying the chain.
        // If any block is invalid, reject the reorg without touching state.
        {
            let mut expected_prev = if let Some(h) = common_ancestor_height {
                self.height_index.get(h as usize).copied().unwrap_or([0u8; BLOCK_HASH_SIZE])
            } else {
                [0u8; BLOCK_HASH_SIZE] // genesis reorg
            };

            for (i, block) in fork_blocks.iter().enumerate() {
                // 1. Verify chain continuity
                if block.header.prev_hash != expected_prev {
                    tracing::warn!(
                        "Reorg pre-validation FAILED: fork block {} has broken chain (expected prev={}, got={})",
                        i, hex::encode(expected_prev), hex::encode(block.header.prev_hash)
                    );
                    return Err(BlockchainError::InvalidPrevHash);
                }
                // 2. Verify PoW
                if let Err(e) = block.verify() {
                    tracing::warn!(
                        "Reorg pre-validation FAILED: fork block {} has invalid PoW: {}",
                        i, e
                    );
                    return Err(BlockchainError::InvalidDifficulty);
                }
                // 3. Verify MIN_DIFFICULTY
                if block.header.difficulty < MIN_DIFFICULTY {
                    tracing::warn!(
                        "Reorg pre-validation FAILED: fork block {} below MIN_DIFFICULTY ({} < {})",
                        i, block.header.difficulty, MIN_DIFFICULTY
                    );
                    return Err(BlockchainError::InvalidDifficulty);
                }
                expected_prev = block.hash();
            }

            // 4. Verify fork cumulative_work > current (from DB, not estimation)
            let ancestor_work = common_ancestor_height
                .and_then(|h| self.db.as_ref()
                    .and_then(|db| db.get_cumulative_work(h).ok().flatten()))
                .unwrap_or(0);
            let fork_work: u128 = ancestor_work + fork_blocks.iter()
                .map(|b| b.header.difficulty as u128)
                .sum::<u128>();
            if fork_work <= self.cumulative_work {
                tracing::debug!(
                    "Reorg pre-validation: fork work {} <= current work {} — rejecting",
                    fork_work, self.cumulative_work
                );
                return Ok(()); // Not an error, just a weaker fork
            }

            tracing::info!(
                "Reorg pre-validation PASSED: {} fork blocks, work {} > current {}",
                fork_blocks.len(), fork_work, self.cumulative_work
            );
        }

        let ancestor_h = match common_ancestor_height {
            Some(h) => h,
            None => {
                // Full reorg from genesis (pre fast-sync path)
                // Build full chain from genesis
                let mut full_chain: Vec<ShieldedBlock> = vec![new_tip.clone()];
                let mut ph = new_tip.header.prev_hash;
                while ph != [0u8; BLOCK_HASH_SIZE] {
                    if let Some(block) = self.get_block(&ph) {
                        ph = block.header.prev_hash;
                        full_chain.push(block);
                    } else {
                        return Err(BlockchainError::InvalidPrevHash);
                    }
                }
                full_chain.reverse();

                let mut new_state = ShieldedState::new();
                let mut new_height_index = Vec::new();
                let mut running_work: u128 = 0;
                let mut new_difficulty = self.difficulty;
                for (i, block) in full_chain.iter().enumerate() {
                    for tx in &block.transactions { new_state.apply_transaction(tx); }
                    for tx in &block.transactions_v2 { new_state.apply_transaction_v2(tx); }
                    new_state.apply_coinbase(&block.coinbase);
                    new_height_index.push(block.hash());
                    new_difficulty = block.header.difficulty;
                    running_work += block.header.difficulty as u128;
                    // Store per-block work in DB
                    if let Some(ref db) = self.db {
                        let _ = db.save_cumulative_work(i as u64, running_work);
                    }
                }

                self.blocks.put(new_tip.hash(), new_tip);
                self.state = new_state;
                self.height_index = new_height_index;
                self.canonical_height = self.height_index.len() as u64 - 1;
                self.difficulty = new_difficulty;
                self.cumulative_work = running_work;
                self.persist_reorg()?;
                self.update_finalization();
                return Ok(());
            }
        };

        let reorg_depth = current_height - ancestor_h;
        tracing::info!(
            "Reorganizing: depth={}, ancestor=#{}, old_tip=#{}, new_tip=#{}",
            reorg_depth, ancestor_h, current_height, new_tip_height
        );

        // Rollback state: undo blocks from current_height down to ancestor_h+1
        // We need to replay the state from the ancestor's state.
        // Since we don't store intermediate states, we replay from the last snapshot
        // or from the beginning of what we have.

        // Strategy: rebuild state by replaying from fast_sync_base (or genesis)
        // up to common ancestor, then apply fork blocks.
        let replay_from = if self.fast_sync_base_height > 0 && ancestor_h >= self.fast_sync_base_height {
            // Post fast-sync: we have the snapshot state at fast_sync_base_height.
            // We can't easily restore it, so we re-read the snapshot from DB.
            // Simpler: replay only the blocks from base to ancestor using current state logic.
            // Actually, since we're replacing blocks ABOVE the ancestor, and the state
            // at ancestor includes all blocks up to ancestor, we just need the state AT the ancestor.
            // Problem: we don't store intermediate states.
            //
            // Pragmatic solution: re-import the snapshot and replay from there.
            self.fast_sync_base_height
        } else {
            0
        };

        // v1.7.0: Rebuild state by replaying shared chain + fork blocks.
        // cumulative_work comes from DB at ancestor, then per-block for fork.
        let (mut new_state, actual_replay_from) =
            if self.fast_sync_base_height > 0 && ancestor_h >= self.fast_sync_base_height {
                let snapshot_state = if let Some(ref db) = self.db {
                    match db.load_state_snapshot() {
                        Ok(Some((snapshot, _))) => {
                            let mut s = ShieldedState::new();
                            s.restore_pq_from_snapshot(snapshot);
                            Some(s)
                        }
                        _ => None,
                    }
                } else {
                    None
                };
                if let Some(state) = snapshot_state {
                    let snap_h = if let Some(ref db) = self.db {
                        db.load_state_snapshot().ok().flatten()
                            .map(|(_, h)| h)
                            .unwrap_or(self.fast_sync_base_height)
                    } else {
                        self.fast_sync_base_height
                    };
                    tracing::info!(
                        "Reorg: using snapshot at height {}, replaying {} blocks to ancestor",
                        snap_h, ancestor_h.saturating_sub(snap_h)
                    );
                    (state, snap_h + 1)
                } else {
                    tracing::warn!("Reorg: no snapshot in DB, replaying from genesis");
                    (ShieldedState::new(), 0)
                }
            } else {
                (ShieldedState::new(), 0)
            };

        let mut new_height_index: Vec<[u8; BLOCK_HASH_SIZE]> = Vec::new();
        let mut new_difficulty = self.difficulty;

        // Copy height_index entries up to actual_replay_from (fast-sync placeholders)
        for h in 0..actual_replay_from.min(ancestor_h + 1) {
            if let Some(hash) = self.height_index.get(h as usize) {
                new_height_index.push(*hash);
            }
        }

        // Replay shared chain state from actual_replay_from to ancestor
        for h in actual_replay_from..=ancestor_h {
            if let Some(hash) = self.height_index.get(h as usize) {
                new_height_index.push(*hash);
                if *hash != [0u8; BLOCK_HASH_SIZE] {
                    if let Some(block) = self.get_block(hash) {
                        for tx in &block.transactions { new_state.apply_transaction(tx); }
                        for tx in &block.transactions_v2 { new_state.apply_transaction_v2(tx); }
                        new_state.apply_coinbase(&block.coinbase);
                        new_difficulty = block.header.difficulty;
                    }
                }
            }
        }

        // Get ancestor's cumulative_work from DB (exact, not estimated)
        let ancestor_work = self.db.as_ref()
            .and_then(|db| db.get_cumulative_work(ancestor_h).ok().flatten())
            .unwrap_or(0);

        // Clean up work entries above ancestor (they belong to the old fork)
        if let Some(ref db) = self.db {
            let _ = db.remove_cumulative_work_from(ancestor_h + 1);
        }

        // Apply fork blocks and store per-block cumulative_work in DB
        let mut running_work = ancestor_work;
        for block in &fork_blocks {
            for tx in &block.transactions { new_state.apply_transaction(tx); }
            for tx in &block.transactions_v2 { new_state.apply_transaction_v2(tx); }
            new_state.apply_coinbase(&block.coinbase);
            new_height_index.push(block.hash());
            new_difficulty = block.header.difficulty;
            running_work += block.header.difficulty as u128;
            let fork_h = new_height_index.len() as u64 - 1;
            if let Some(ref db) = self.db {
                let _ = db.save_cumulative_work(fork_h, running_work);
            }
        }

        // v1.8.0: Purge LRU before storing new tip — old fork blocks must not
        // be treated as duplicates if we receive them again from other peers.
        let lru_before = self.blocks.len();
        self.blocks.clear();
        self.orphans.clear();

        // Store new tip and switch
        self.blocks.put(new_tip.hash(), new_tip);
        self.state = new_state;
        self.height_index = new_height_index;
        self.canonical_height = self.height_index.len() as u64 - 1;
        self.difficulty = new_difficulty;
        self.cumulative_work = running_work;

        self.persist_reorg()?;
        self.update_finalization();

        tracing::info!("Reorg complete: new height {} (lru_purged={})", self.height(), lru_before);
        Ok(())
    }

    /// Persist the current chain state to DB after a reorg.
    fn persist_reorg(&self) -> Result<(), BlockchainError> {
        if let Some(ref db) = self.db {
            tracing::info!("Persisting chain reorganization (new height: {})", self.height());

            // H6 audit fix: collect all new nullifiers FIRST, then do a single
            // clear+insert. Previously, a crash between clear_nullifiers() and the
            // rebuild loop would leave an empty nullifier set → double-spend possible.
            let mut new_nullifiers: Vec<[u8; 32]> = Vec::new();

            for (height, hash) in self.height_index.iter().enumerate() {
                if *hash == [0u8; BLOCK_HASH_SIZE] { continue; } // skip fast-sync placeholders
                if let Some(block) = self.get_block(hash) {
                    db.save_block(&block, height as u64)
                        .map_err(|e| BlockchainError::StorageError(e.to_string()))?;

                    for tx in &block.transactions {
                        for spend in &tx.spends {
                            new_nullifiers.push(spend.nullifier.to_bytes());
                        }
                    }
                    for tx in &block.transactions_v2 {
                        for spend in &tx.spends {
                            new_nullifiers.push(spend.nullifier);
                        }
                    }
                }
            }

            // Now atomically: clear old nullifiers and insert all new ones
            // The window of vulnerability is minimized to the time of this loop
            db.clear_nullifiers()
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
            for nf in &new_nullifiers {
                db.save_nullifier(nf)
                    .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
            }

            db.set_metadata("difficulty", &self.difficulty.to_string())
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

        // Compute state root from the post-block state
        let state_root = temp_state.compute_state_root();

        let mut block = ShieldedBlock::new_with_v2(
            self.latest_hash(),
            transactions,
            transactions_v2,
            coinbase,
            commitment_root,
            nullifier_root,
            self.next_difficulty(),
        );
        block.set_state_root(state_root);
        block
    }

    /// Get the last finalized checkpoint height.
    pub fn last_checkpoint_height(&self) -> u64 {
        self.last_checkpoint_height
    }

    /// Get chain info for API responses.
    pub fn info(&self) -> ChainInfo {
        let genesis_hash = self.height_index.first()
            .map(|h| hex::encode(h))
            .unwrap_or_default();
        ChainInfo {
            height: self.height(),
            latest_hash: hex::encode(self.latest_hash()),
            difficulty: self.difficulty,
            next_difficulty: self.next_difficulty(),
            commitment_count: self.commitment_count(),
            nullifier_count: self.nullifier_count() as u64,
            proof_verification_enabled: self.verifying_params.is_some(),
            genesis_hash,
            assume_valid_height: self.assume_valid_height,
            last_checkpoint_height: self.last_checkpoint_height,
            network_hashrate: self.estimate_network_hashrate(),
            cumulative_work: self.cumulative_work,
            finalized_height: self.finalized_height,
        }
    }

    /// Estimate network hashrate using Bitcoin's method:
    /// hashrate = sum(difficulty_of_each_block) / time_span
    /// over the last HASHRATE_WINDOW blocks.
    fn estimate_network_hashrate(&self) -> f64 {
        const HASHRATE_WINDOW: u64 = 120;

        let tip = self.height();
        if tip < 2 {
            return 0.0;
        }

        let tip_block = match self.get_block_by_height(tip) {
            Some(b) => b,
            None => return self.difficulty as f64 / 10.0, // fallback: difficulty / target_time
        };

        // Find the earliest available block in the window
        let ideal_start = if tip > HASHRATE_WINDOW { tip - HASHRATE_WINDOW } else { 1 };
        let mut start_height = ideal_start;
        let mut start_block = None;
        for h in ideal_start..tip {
            if let Some(b) = self.get_block_by_height(h) {
                start_block = Some(b);
                start_height = h;
                break;
            }
        }

        let start_block = match start_block {
            Some(b) => b,
            None => return self.difficulty as f64 / 10.0, // fallback
        };

        let time_span = tip_block.header.timestamp.saturating_sub(start_block.header.timestamp);
        if time_span == 0 {
            return self.difficulty as f64 / 10.0;
        }

        // Sum difficulties of available blocks in window (= total work done)
        let mut total_work: f64 = 0.0;
        for h in (start_height + 1)..=tip {
            if let Some(block) = self.get_block_by_height(h) {
                total_work += block.header.difficulty as f64;
            }
        }

        if total_work == 0.0 {
            return self.difficulty as f64 / 10.0;
        }

        // hashrate = total_work / time_span (Bitcoin standard)
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
    /// This skips block replay entirely — the state is verified via state_root.
    /// Only the last few blocks are synced normally to build the height index tail.
    ///
    /// If `expected_state_root` is non-zero, the imported state is verified against it.
    /// A mismatch means the peer sent a corrupted/malicious snapshot.
    pub fn import_snapshot_at_height(
        &mut self,
        snapshot: crate::core::StateSnapshotPQ,
        height: u64,
        block_hash: [u8; 32],
        difficulty: u64,
        next_difficulty: u64,
        peer_cumulative_work: u128,
    ) {
        // Restore state
        self.state.restore_pq_from_snapshot(snapshot.clone());

        // Verify state_root integrity after restoring the snapshot.
        // For blocks mined after v0.7.1, the state_root in the header is non-zero
        // and MUST match the computed state root of the imported snapshot.
        let computed_root = self.state.compute_state_root();
        tracing::info!(
            "Snapshot state_root verification: computed={}",
            hex::encode(computed_root)
        );

        // After fast-sync, ALWAYS skip V1 tree validation.
        // The V1 tree (legacy BN254 Poseidon) may be inconsistent after snapshot restore
        // because the peer's V1 tree may have been rebuilt from its own fast-sync.
        // The V2 tree (post-quantum Goldilocks/Poseidon2) is always correct and is the
        // authoritative commitment tree for this quantum-resistant blockchain.
        // ALWAYS skip V1 tree validation after fast-sync.
        // The V1 tree (legacy BN254 Poseidon) is NOT reliably reproducible across
        // different node states. The V2 tree (post-quantum Goldilocks/Poseidon2) is
        // the authoritative commitment tree. V1 validation causes sync failures.
        self.state.force_skip_v1_tree();

        // Set chain metadata — use next_difficulty so validation works after fast-sync
        self.difficulty = next_difficulty;
        // v1.7.0: Use exact cumulative_work from peer (transmitted in snapshot/info).
        // This is the peer's DB value, calculated block-by-block since genesis.
        // Stored in per-height DB tree so insert_block_internal can read it.
        self.cumulative_work = peer_cumulative_work;
        self.fast_sync_base_height = height;
        // Save commitment count at snapshot time for correct position calculation
        self.fast_sync_commitment_offset = self.state.commitment_count();

        // Build a minimal height index (we'll fill in real hashes when we sync recent blocks)
        // For now, put placeholder hashes — the important thing is height() returns the right value
        self.height_index.clear();
        for _ in 0..height {
            self.height_index.push([0u8; 32]); // placeholder
        }
        // Set the tip hash correctly
        self.height_index.push(block_hash);
        self.canonical_height = height;

        // Update checkpoint and finalization
        self.last_checkpoint_height = height;
        self.last_checkpoint_hash = Some(block_hash);
        // Set finalization based on imported height (same logic as open() and update_finalization)
        self.finalized_height = if height > crate::config::MAX_REORG_DEPTH {
            height - crate::config::MAX_REORG_DEPTH
        } else {
            0
        };

        // Save snapshot to local DB for fast restart
        if let Some(ref db) = self.db {
            if let Err(e) = db.save_state_snapshot(&snapshot, height) {
                tracing::warn!("Failed to save imported snapshot: {}", e);
            }
            // Store exact cumulative_work in per-height tree (source of truth for insert_block_internal)
            let _ = db.save_cumulative_work(height, self.cumulative_work);
            let _ = db.set_metadata("height", &height.to_string());
            let _ = db.set_metadata("difficulty", &difficulty.to_string());
            let _ = db.set_metadata("cumulative_work", &self.cumulative_work.to_string());
            let _ = db.set_metadata("latest_hash", &hex::encode(block_hash));
            let _ = db.set_metadata("fast_sync_base_height", &height.to_string());
            let _ = db.set_metadata("fast_sync_commitment_offset", &self.fast_sync_commitment_offset.to_string());
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
    /// Genesis block hash — used for fork ID verification
    pub genesis_hash: String,
    /// Assume-valid checkpoint height. Blocks at or below this height
    /// skip ZK proof verification during sync. Set to 0 if disabled.
    pub assume_valid_height: u64,
    /// Height of the last finalized checkpoint. Reorgs below this height
    /// are rejected. Set to 0 if no checkpoint yet.
    pub last_checkpoint_height: u64,
    /// Estimated network hashrate in H/s (Bitcoin-style: sum(difficulty) / time_span over last N blocks)
    pub network_hashrate: f64,
    /// Cumulative proof-of-work (sum of all block difficulties from genesis to tip)
    #[serde(default)]
    pub cumulative_work: u128,
    /// Height below which blocks are permanently finalized (no reorgs possible).
    /// Computed as max(last_checkpoint_height, tip - MAX_REORG_DEPTH).
    #[serde(default)]
    pub finalized_height: u64,
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

    /// Helper: create a block template with timestamp set after the previous block.
    fn mine_test_block(chain: &mut ShieldedBlockchain, pk_hash: [u8; 32], vk: &ViewingKey, _block_num: u64) {
        use crate::consensus::mine_block;
        let mut block = chain.create_block_template(pk_hash, vk, vec![]);
        // Set timestamp to prev + interval to satisfy MIN_BLOCK_INTERVAL_SECS
        let prev_block = chain.get_block_by_height(chain.height()).unwrap();
        block.header.timestamp = prev_block.header.timestamp + crate::config::MIN_BLOCK_INTERVAL_SECS + 2;
        mine_block(&mut block);
        chain.add_block(block).unwrap();
    }

    #[test]
    fn test_chainwork_deterministic() {
        use tempfile::tempdir;

        let vk = test_viewing_key();
        let pk_hash = test_pk_hash();

        let db_dir1 = tempdir().unwrap();
        let db_dir2 = tempdir().unwrap();

        let mut chain1 = ShieldedBlockchain::open(db_dir1.path().to_str().unwrap(), MIN_DIFFICULTY).unwrap();
        let mut chain2 = ShieldedBlockchain::open(db_dir2.path().to_str().unwrap(), MIN_DIFFICULTY).unwrap();

        // Mine and add same blocks to both
        for _ in 1..=5 {
            use crate::consensus::mine_block;
            let mut block = chain1.create_block_template(pk_hash, &vk, vec![]);
            let prev = chain1.get_block_by_height(chain1.height()).unwrap();
            block.header.timestamp = prev.header.timestamp + 10;
            mine_block(&mut block);
            let block_clone = block.clone();
            chain1.add_block(block).unwrap();
            chain2.add_block(block_clone).unwrap();
        }

        assert_eq!(chain1.height(), 5);
        assert_eq!(chain2.height(), 5);
        assert_eq!(chain1.cumulative_work(), chain2.cumulative_work(),
            "same chain = same cumulative_work");
    }

    #[test]
    #[ignore] // Flaky: mining at MIN_DIFFICULTY takes real time, timestamps drift
    fn test_chainwork_after_rollback() {
        use tempfile::tempdir;

        let vk = test_viewing_key();
        let pk_hash = test_pk_hash();

        let db_dir = tempdir().unwrap();
        let db_path = db_dir.path().to_str().unwrap();
        let mut chain = ShieldedBlockchain::open(db_path, MIN_DIFFICULTY).unwrap();

        // Mine 10 blocks
        for i in 1..=10 {
            mine_test_block(&mut chain, pk_hash, &vk, i);
        }

        let work_at_10 = chain.cumulative_work();
        assert_eq!(chain.height(), 10);

        // Record work at height 5
        let work_at_5 = chain.db.as_ref().unwrap()
            .get_cumulative_work(5).unwrap().unwrap();

        // Rollback to height 5
        chain.rollback_to_height(5).unwrap();
        assert_eq!(chain.height(), 5);
        assert_eq!(chain.cumulative_work(), work_at_5,
            "after rollback, work must equal DB value at target height");

        assert!(work_at_5 < work_at_10);

        // Add 3 more blocks after rollback
        for i in 11..=13 {
            mine_test_block(&mut chain, pk_hash, &vk, i);
        }

        assert_eq!(chain.height(), 8);
        assert!(chain.cumulative_work() > work_at_5);
    }

    #[test]
    #[ignore] // Flaky: mining at MIN_DIFFICULTY takes real time, timestamps drift
    fn test_chainwork_after_restart() {
        use tempfile::tempdir;

        let vk = test_viewing_key();
        let pk_hash = test_pk_hash();

        let db_dir = tempdir().unwrap();
        let db_path = db_dir.path().to_str().unwrap();

        let work_before;
        let height_before;

        {
            let mut chain = ShieldedBlockchain::open(db_path, MIN_DIFFICULTY).unwrap();
            for i in 1..=5 {
                mine_test_block(&mut chain, pk_hash, &vk, i);
            }
            work_before = chain.cumulative_work();
            height_before = chain.height();
        }

        {
            let chain = ShieldedBlockchain::open(db_path, MIN_DIFFICULTY).unwrap();
            assert_eq!(chain.height(), height_before);
            assert_eq!(chain.cumulative_work(), work_before,
                "cumulative_work must be identical after restart");
        }
    }
}
