use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::core::{Account, ShieldedBlock};
use crate::crypto::Address;

/// Faucet claim record stored in the database.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FaucetClaim {
    /// Unix timestamp of last claim
    pub last_claim_timestamp: u64,
    /// Total amount claimed all-time (in base units)
    pub total_claimed: u64,
    /// Consecutive day streak
    pub streak: u32,
    /// Last streak date in "YYYY-MM-DD" format (UTC)
    pub last_streak_date: String,
}

impl Default for FaucetClaim {
    fn default() -> Self {
        Self {
            last_claim_timestamp: 0,
            total_claimed: 0,
            streak: 0,
            last_streak_date: String::new(),
        }
    }
}

/// Sled-based key-value database for persistent storage.
///
/// Uses separate trees for different data types:
/// - blocks: hash -> block data
/// - block_heights: height -> hash
/// - nullifiers: nullifier -> () (existence check)
/// - accounts: address -> account data
/// - metadata: key -> value
/// - faucet_claims: pk_hash -> FaucetClaim
pub struct Database {
    db: sled::Db,
    blocks: sled::Tree,
    block_heights: sled::Tree,
    nullifiers: sled::Tree,
    accounts: sled::Tree,
    metadata: sled::Tree,
    faucet_claims: sled::Tree,
}

impl Database {
    /// Open or create a database at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, DatabaseError> {
        let db = sled::open(path)?;
        let blocks = db.open_tree("blocks")?;
        let block_heights = db.open_tree("block_heights")?;
        let nullifiers = db.open_tree("nullifiers")?;
        let accounts = db.open_tree("accounts")?;
        let metadata = db.open_tree("metadata")?;
        let faucet_claims = db.open_tree("faucet_claims")?;

        Ok(Self {
            db,
            blocks,
            block_heights,
            nullifiers,
            accounts,
            metadata,
            faucet_claims,
        })
    }

    /// Create a temporary in-memory database (for testing).
    pub fn in_memory() -> Result<Self, DatabaseError> {
        let config = sled::Config::new().temporary(true);
        let db = config.open()?;
        let blocks = db.open_tree("blocks")?;
        let block_heights = db.open_tree("block_heights")?;
        let nullifiers = db.open_tree("nullifiers")?;
        let accounts = db.open_tree("accounts")?;
        let metadata = db.open_tree("metadata")?;
        let faucet_claims = db.open_tree("faucet_claims")?;

        Ok(Self {
            db,
            blocks,
            block_heights,
            nullifiers,
            accounts,
            metadata,
            faucet_claims,
        })
    }

    /// Save a block to the database.
    pub fn save_block(&self, block: &ShieldedBlock, height: u64) -> Result<(), DatabaseError> {
        let hash = block.hash();
        let data = serde_json::to_vec(block)?;

        // Store block by hash
        self.blocks.insert(&hash, data)?;

        // Store hash by height
        self.block_heights.insert(&height.to_be_bytes(), &hash)?;

        Ok(())
    }

    /// Load a block by hash.
    pub fn load_block(&self, hash: &[u8; 32]) -> Result<Option<ShieldedBlock>, DatabaseError> {
        match self.blocks.get(hash)? {
            Some(data) => {
                let block: ShieldedBlock = serde_json::from_slice(&data)?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Load a block by height.
    pub fn load_block_by_height(&self, height: u64) -> Result<Option<ShieldedBlock>, DatabaseError> {
        match self.block_heights.get(&height.to_be_bytes())? {
            Some(hash) => {
                let hash: [u8; 32] = hash
                    .as_ref()
                    .try_into()
                    .map_err(|_| DatabaseError::InvalidData("invalid hash length".into()))?;
                self.load_block(&hash)
            }
            None => Ok(None),
        }
    }

    /// Get the latest block height.
    pub fn get_height(&self) -> Result<Option<u64>, DatabaseError> {
        // Get the last key in the block_heights tree
        match self.block_heights.last()? {
            Some((key, _)) => {
                let bytes: [u8; 8] = key
                    .as_ref()
                    .try_into()
                    .map_err(|_| DatabaseError::InvalidData("invalid height".into()))?;
                Ok(Some(u64::from_be_bytes(bytes)))
            }
            None => Ok(None),
        }
    }

    /// Save a nullifier to the database.
    pub fn save_nullifier(&self, nullifier: &[u8; 32]) -> Result<(), DatabaseError> {
        self.nullifiers.insert(nullifier, &[])?;
        Ok(())
    }

    /// Check if a nullifier exists in the database.
    pub fn has_nullifier(&self, nullifier: &[u8; 32]) -> Result<bool, DatabaseError> {
        Ok(self.nullifiers.contains_key(nullifier)?)
    }

    /// Load all nullifiers from the database.
    pub fn load_all_nullifiers(&self) -> Result<Vec<[u8; 32]>, DatabaseError> {
        let mut nullifiers = Vec::new();
        for item in self.nullifiers.iter() {
            let (key, _) = item?;
            let nf: [u8; 32] = key
                .as_ref()
                .try_into()
                .map_err(|_| DatabaseError::InvalidData("invalid nullifier length".into()))?;
            nullifiers.push(nf);
        }
        Ok(nullifiers)
    }

    /// Get the count of stored nullifiers.
    pub fn nullifier_count(&self) -> Result<u64, DatabaseError> {
        Ok(self.nullifiers.len() as u64)
    }

    /// Clear all nullifiers (used during reorg).
    pub fn clear_nullifiers(&self) -> Result<(), DatabaseError> {
        self.nullifiers.clear()?;
        Ok(())
    }

    /// Remove blocks from a given height onwards (used during reorg).
    pub fn remove_blocks_from(&self, height: u64) -> Result<Vec<ShieldedBlock>, DatabaseError> {
        let mut removed = Vec::new();
        let current_height = self.get_height()?.unwrap_or(0);

        for h in height..=current_height {
            if let Some(block) = self.load_block_by_height(h)? {
                removed.push(block);
            }
            // Remove height index
            self.block_heights.remove(&h.to_be_bytes())?;
        }

        // Note: We don't remove blocks by hash since they might be needed for orphan processing
        Ok(removed)
    }

    /// Save an account state.
    pub fn save_account(&self, account: &Account) -> Result<(), DatabaseError> {
        let data = serde_json::to_vec(account)?;
        self.accounts.insert(account.address.as_bytes(), data)?;
        Ok(())
    }

    /// Load an account by address.
    pub fn load_account(&self, address: &Address) -> Result<Option<Account>, DatabaseError> {
        match self.accounts.get(address.as_bytes())? {
            Some(data) => {
                let account: Account = serde_json::from_slice(&data)?;
                Ok(Some(account))
            }
            None => Ok(None),
        }
    }

    /// Save metadata.
    pub fn set_metadata(&self, key: &str, value: &str) -> Result<(), DatabaseError> {
        self.metadata.insert(key.as_bytes(), value.as_bytes())?;
        Ok(())
    }

    /// Load metadata.
    pub fn get_metadata(&self, key: &str) -> Result<Option<String>, DatabaseError> {
        match self.metadata.get(key.as_bytes())? {
            Some(data) => {
                let value = String::from_utf8(data.to_vec())
                    .map_err(|_| DatabaseError::InvalidData("invalid utf8".into()))?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    /// Get a reference to the underlying Sled database.
    /// Used by subsystems like ContractExecutor that need their own trees.
    pub fn sled_db(&self) -> &sled::Db {
        &self.db
    }

    /// Flush all pending writes to disk.
    pub fn flush(&self) -> Result<(), DatabaseError> {
        self.db.flush()?;
        Ok(())
    }

    /// Save a state snapshot for fast loading.
    pub fn save_state_snapshot(&self, snapshot: &crate::core::StateSnapshotPQ, height: u64) -> Result<(), DatabaseError> {
        let data = serde_json::to_vec(snapshot)?;
        self.metadata.insert("state_snapshot_pq", data)?;
        self.metadata.insert("state_snapshot_height", &height.to_be_bytes())?;
        self.db.flush()?;
        Ok(())
    }

    /// Load the state snapshot if available.
    pub fn load_state_snapshot(&self) -> Result<Option<(crate::core::StateSnapshotPQ, u64)>, DatabaseError> {
        let snapshot_data = match self.metadata.get("state_snapshot_pq")? {
            Some(data) => data,
            None => return Ok(None),
        };

        let height_data = match self.metadata.get("state_snapshot_height")? {
            Some(data) => data,
            None => return Ok(None),
        };

        let snapshot: crate::core::StateSnapshotPQ = serde_json::from_slice(&snapshot_data)?;
        let height = u64::from_be_bytes(height_data.as_ref().try_into().map_err(|_| {
            DatabaseError::InvalidData("invalid snapshot height".into())
        })?);

        Ok(Some((snapshot, height)))
    }

    /// Get the height at which the snapshot was taken.
    pub fn get_snapshot_height(&self) -> Result<Option<u64>, DatabaseError> {
        match self.metadata.get("state_snapshot_height")? {
            Some(data) => {
                let height = u64::from_be_bytes(data.as_ref().try_into().map_err(|_| {
                    DatabaseError::InvalidData("invalid snapshot height".into())
                })?);
                Ok(Some(height))
            }
            None => Ok(None),
        }
    }

    // ============ Faucet Claims ============

    /// Get a faucet claim record by pk_hash.
    pub fn get_faucet_claim(&self, pk_hash: &[u8; 32]) -> Result<Option<FaucetClaim>, DatabaseError> {
        match self.faucet_claims.get(pk_hash)? {
            Some(data) => {
                let claim: FaucetClaim = serde_json::from_slice(&data)?;
                Ok(Some(claim))
            }
            None => Ok(None),
        }
    }

    /// Save a faucet claim record.
    pub fn save_faucet_claim(&self, pk_hash: &[u8; 32], claim: &FaucetClaim) -> Result<(), DatabaseError> {
        let data = serde_json::to_vec(claim)?;
        self.faucet_claims.insert(pk_hash, data)?;
        Ok(())
    }

    /// Get total amount distributed by the faucet.
    pub fn get_faucet_total_distributed(&self) -> Result<u64, DatabaseError> {
        let mut total = 0u64;
        for item in self.faucet_claims.iter() {
            let (_, data) = item?;
            let claim: FaucetClaim = serde_json::from_slice(&data)?;
            total = total.saturating_add(claim.total_claimed);
        }
        Ok(total)
    }

    /// Get count of unique faucet claimants.
    pub fn get_faucet_claimant_count(&self) -> Result<u64, DatabaseError> {
        Ok(self.faucet_claims.len() as u64)
    }

    /// Get count of active streaks (streak > 0).
    pub fn get_faucet_active_streaks(&self) -> Result<u64, DatabaseError> {
        let mut count = 0u64;
        for item in self.faucet_claims.iter() {
            let (_, data) = item?;
            let claim: FaucetClaim = serde_json::from_slice(&data)?;
            if claim.streak > 0 {
                count += 1;
            }
        }
        Ok(count)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("Sled error: {0}")]
    Sled(#[from] sled::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::CoinbaseTransaction;
    use crate::crypto::commitment::NoteCommitment;
    use crate::crypto::note::EncryptedNote;

    fn dummy_coinbase(height: u64) -> CoinbaseTransaction {
        CoinbaseTransaction::new(
            NoteCommitment([1u8; 32]),
            [1u8; 32], // V2/PQ commitment (dummy for tests)
            EncryptedNote {
                ciphertext: vec![0; 64],
                ephemeral_pk: vec![0; 32],
            },
            50,
            height,
        )
    }

    #[test]
    fn test_database_creation() {
        let db = Database::in_memory().unwrap();
        assert!(db.get_height().unwrap().is_none());
    }

    #[test]
    fn test_save_and_load_block() {
        let db = Database::in_memory().unwrap();

        let coinbase = dummy_coinbase(0);
        let block = ShieldedBlock::new(
            [0u8; 32],
            vec![],
            coinbase,
            [0u8; 32],
            [0u8; 32],
            0,
        );
        let hash = block.hash();

        db.save_block(&block, 0).unwrap();

        let loaded = db.load_block(&hash).unwrap().unwrap();
        assert_eq!(loaded.hash(), hash);
    }

    #[test]
    fn test_load_block_by_height() {
        let db = Database::in_memory().unwrap();

        let coinbase = dummy_coinbase(42);
        let block = ShieldedBlock::new(
            [0u8; 32],
            vec![],
            coinbase,
            [0u8; 32],
            [0u8; 32],
            0,
        );

        db.save_block(&block, 42).unwrap();

        let loaded = db.load_block_by_height(42).unwrap().unwrap();
        assert_eq!(loaded.hash(), block.hash());
    }

    #[test]
    fn test_get_height() {
        let db = Database::in_memory().unwrap();

        let coinbase = dummy_coinbase(0);
        let block = ShieldedBlock::new(
            [0u8; 32],
            vec![],
            coinbase,
            [0u8; 32],
            [0u8; 32],
            0,
        );

        db.save_block(&block, 0).unwrap();
        assert_eq!(db.get_height().unwrap(), Some(0));

        let coinbase2 = dummy_coinbase(1);
        let block2 = ShieldedBlock::new(
            block.hash(),
            vec![],
            coinbase2,
            [0u8; 32],
            [0u8; 32],
            0,
        );
        db.save_block(&block2, 1).unwrap();
        assert_eq!(db.get_height().unwrap(), Some(1));
    }

    #[test]
    fn test_save_and_load_account() {
        let db = Database::in_memory().unwrap();

        let addr = Address::from_bytes([1u8; 20]);
        let account = Account::with_balance(addr, 1000);

        db.save_account(&account).unwrap();

        let loaded = db.load_account(&addr).unwrap().unwrap();
        assert_eq!(loaded.balance, 1000);
    }

    #[test]
    fn test_metadata() {
        let db = Database::in_memory().unwrap();

        db.set_metadata("difficulty", "8").unwrap();
        assert_eq!(
            db.get_metadata("difficulty").unwrap(),
            Some("8".to_string())
        );
    }
}
