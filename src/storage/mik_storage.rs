//! Persistent storage for Mining Identity Keys (MIKs).
//!
//! This module provides persistent storage capabilities for the MIK system,
//! including serialization, indexing, and efficient retrieval of MIK data.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use sled::{Db, Tree};
use thiserror::Error;

use crate::core::mik_manager::{MikState, MikConfig};
use crate::crypto::mik::{MikId, MiningIdentityKey};
use crate::crypto::keys::PublicKey;

/// Errors related to MIK storage operations.
#[derive(Error, Debug)]
pub enum MikStorageError {
    #[error("Database error: {0}")]
    Database(#[from] sled::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    
    #[error("MIK not found: {id}")]
    MikNotFound { id: String },
    
    #[error("Invalid data format in storage")]
    InvalidDataFormat,
    
    #[error("Storage corruption detected")]
    StorageCorruption,
}

/// Storage keys for different MIK data types.
mod storage_keys {
    pub const MIK_PREFIX: &[u8] = b"mik:";
    pub const MIK_BY_PUBKEY_PREFIX: &[u8] = b"mik_by_pubkey:";
    pub const MIK_CONFIG_KEY: &[u8] = b"mik_config";
    pub const MIK_STATE_METADATA_KEY: &[u8] = b"mik_state_metadata";
    pub const ACTIVE_MIKS_KEY: &[u8] = b"active_miks";
}

/// Metadata about the stored MIK state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MikStateMetadata {
    /// Version of the MIK storage format.
    pub version: u32,
    
    /// Last block height at which the state was updated.
    pub last_updated_block: u64,
    
    /// Total number of MIKs stored.
    pub total_miks: usize,
    
    /// Number of active MIKs.
    pub active_miks: usize,
    
    /// Timestamp of last update.
    pub last_update_timestamp: u64,
}

impl Default for MikStateMetadata {
    fn default() -> Self {
        Self {
            version: 1,
            last_updated_block: 0,
            total_miks: 0,
            active_miks: 0,
            last_update_timestamp: 0,
        }
    }
}

/// Persistent storage for MIK data.
pub struct MikStorage {
    /// Main database handle.
    db: Db,
    
    /// Tree for storing MIKs by ID.
    miks_tree: Tree,
    
    /// Tree for storing MIK ID by public key.
    pubkey_index_tree: Tree,
    
    /// Tree for storing configuration and metadata.
    config_tree: Tree,
}

impl MikStorage {
    /// Open or create MIK storage at the given path.
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Self, MikStorageError> {
        let db = sled::open(path)?;
        
        let miks_tree = db.open_tree("miks")?;
        let pubkey_index_tree = db.open_tree("mik_pubkey_index")?;
        let config_tree = db.open_tree("mik_config")?;

        Ok(Self {
            db,
            miks_tree,
            pubkey_index_tree,
            config_tree,
        })
    }

    /// Store a MIK in the database.
    pub fn store_mik(&self, mik: &MiningIdentityKey) -> Result<(), MikStorageError> {
        let mik_key = Self::mik_key(&mik.id);
        let mik_data = bincode::serialize(mik)?;
        
        // Store the MIK
        self.miks_tree.insert(&mik_key, mik_data)?;
        
        // Update public key index
        let pubkey_key = Self::pubkey_key(&mik.public_key);
        let mik_id_data = bincode::serialize(&mik.id)?;
        self.pubkey_index_tree.insert(&pubkey_key, mik_id_data)?;
        
        Ok(())
    }

    /// Retrieve a MIK by its ID.
    pub fn get_mik(&self, mik_id: &MikId) -> Result<Option<MiningIdentityKey>, MikStorageError> {
        let mik_key = Self::mik_key(mik_id);
        
        if let Some(mik_data) = self.miks_tree.get(&mik_key)? {
            let mik: MiningIdentityKey = bincode::deserialize(&mik_data)?;
            Ok(Some(mik))
        } else {
            Ok(None)
        }
    }

    /// Retrieve a MIK by public key.
    pub fn get_mik_by_public_key(
        &self,
        public_key: &PublicKey,
    ) -> Result<Option<MiningIdentityKey>, MikStorageError> {
        let pubkey_key = Self::pubkey_key(public_key);
        
        if let Some(mik_id_data) = self.pubkey_index_tree.get(&pubkey_key)? {
            let mik_id: MikId = bincode::deserialize(&mik_id_data)?;
            self.get_mik(&mik_id)
        } else {
            Ok(None)
        }
    }

    /// Store the complete MIK state.
    pub fn store_mik_state(&self, state: &MikState) -> Result<(), MikStorageError> {
        // Store each MIK
        for mik in state.miks.values() {
            self.store_mik(mik)?;
        }

        // Store configuration
        let config_data = bincode::serialize(&state.config)?;
        self.config_tree.insert(storage_keys::MIK_CONFIG_KEY, config_data)?;

        // Store active MIKs set
        let active_miks_data = bincode::serialize(&state.active_miks)?;
        self.config_tree.insert(storage_keys::ACTIVE_MIKS_KEY, active_miks_data)?;

        // Store metadata
        let metadata = MikStateMetadata {
            version: 1,
            last_updated_block: 0, // This should be set by the caller
            total_miks: state.miks.len(),
            active_miks: state.active_miks.len(),
            last_update_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        let metadata_data = bincode::serialize(&metadata)?;
        self.config_tree.insert(storage_keys::MIK_STATE_METADATA_KEY, metadata_data)?;

        // Flush to disk
        self.db.flush()?;

        Ok(())
    }

    /// Load the complete MIK state.
    pub fn load_mik_state(&self) -> Result<MikState, MikStorageError> {
        // Load configuration
        let config = if let Some(config_data) = self.config_tree.get(storage_keys::MIK_CONFIG_KEY)? {
            bincode::deserialize(&config_data)?
        } else {
            MikConfig::default()
        };

        // Load all MIKs
        let mut miks = HashMap::new();
        let mut public_key_to_mik = HashMap::new();

        for result in self.miks_tree.iter() {
            let (key, value) = result?;
            
            // Skip if not a MIK key
            if !key.starts_with(storage_keys::MIK_PREFIX) {
                continue;
            }

            let mik: MiningIdentityKey = bincode::deserialize(&value)?;
            
            // Verify consistency
            let expected_key = Self::mik_key(&mik.id);
            if key != expected_key {
                return Err(MikStorageError::StorageCorruption);
            }

            public_key_to_mik.insert(mik.public_key.clone(), mik.id);
            miks.insert(mik.id, mik);
        }

        // Load active MIKs set
        let active_miks = if let Some(active_data) = self.config_tree.get(storage_keys::ACTIVE_MIKS_KEY)? {
            bincode::deserialize(&active_data)?
        } else {
            // Rebuild active set if not stored
            miks.keys().cloned().collect()
        };

        Ok(MikState {
            miks,
            public_key_to_mik,
            active_miks,
            config,
        })
    }

    /// Get storage metadata.
    pub fn get_metadata(&self) -> Result<MikStateMetadata, MikStorageError> {
        if let Some(metadata_data) = self.config_tree.get(storage_keys::MIK_STATE_METADATA_KEY)? {
            let metadata: MikStateMetadata = bincode::deserialize(&metadata_data)?;
            Ok(metadata)
        } else {
            Ok(MikStateMetadata::default())
        }
    }

    /// Update metadata with current block information.
    pub fn update_metadata(&self, current_block: u64, state: &MikState) -> Result<(), MikStorageError> {
        let metadata = MikStateMetadata {
            version: 1,
            last_updated_block: current_block,
            total_miks: state.miks.len(),
            active_miks: state.active_miks.len(),
            last_update_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        let metadata_data = bincode::serialize(&metadata)?;
        self.config_tree.insert(storage_keys::MIK_STATE_METADATA_KEY, metadata_data)?;
        
        Ok(())
    }

    /// Remove a MIK from storage.
    pub fn remove_mik(&self, mik_id: &MikId) -> Result<bool, MikStorageError> {
        // Get the MIK first to remove from public key index
        if let Some(mik) = self.get_mik(mik_id)? {
            let pubkey_key = Self::pubkey_key(&mik.public_key);
            self.pubkey_index_tree.remove(&pubkey_key)?;
        }

        let mik_key = Self::mik_key(mik_id);
        let removed = self.miks_tree.remove(&mik_key)?.is_some();
        
        Ok(removed)
    }

    /// Get all MIK IDs in storage.
    pub fn get_all_mik_ids(&self) -> Result<Vec<MikId>, MikStorageError> {
        let mut mik_ids = Vec::new();

        for result in self.miks_tree.iter() {
            let (key, _) = result?;
            
            if key.starts_with(storage_keys::MIK_PREFIX) {
                // Extract MIK ID from key
                if key.len() >= storage_keys::MIK_PREFIX.len() + 32 {
                    let id_bytes = &key[storage_keys::MIK_PREFIX.len()..storage_keys::MIK_PREFIX.len() + 32];
                    let mut mik_id = [0u8; 32];
                    mik_id.copy_from_slice(id_bytes);
                    mik_ids.push(mik_id);
                }
            }
        }

        Ok(mik_ids)
    }

    /// Compact the database to reclaim space.
    pub fn compact(&self) -> Result<(), MikStorageError> {
        // Sled doesn't have explicit compaction, but we can flush
        self.db.flush()?;
        Ok(())
    }

    /// Get storage statistics.
    pub fn get_storage_stats(&self) -> Result<MikStorageStats, MikStorageError> {
        let mik_count = self.miks_tree.len();
        let pubkey_index_count = self.pubkey_index_tree.len();
        
        // Calculate approximate storage size
        let mut total_size = 0usize;
        for result in self.miks_tree.iter() {
            let (key, value) = result?;
            total_size += key.len() + value.len();
        }

        Ok(MikStorageStats {
            mik_count,
            pubkey_index_count,
            total_size_bytes: total_size,
        })
    }

    /// Verify storage integrity.
    pub fn verify_integrity(&self) -> Result<(), MikStorageError> {
        let mut mik_count = 0;
        let mut pubkey_count = 0;

        // Check all MIKs
        for result in self.miks_tree.iter() {
            let (key, value) = result?;
            
            if !key.starts_with(storage_keys::MIK_PREFIX) {
                continue;
            }

            // Deserialize and verify
            let mik: MiningIdentityKey = bincode::deserialize(&value)
                .map_err(|_| MikStorageError::StorageCorruption)?;
            
            // Verify key matches MIK ID
            let expected_key = Self::mik_key(&mik.id);
            if key != expected_key {
                return Err(MikStorageError::StorageCorruption);
            }

            mik_count += 1;
        }

        // Check public key index
        for result in self.pubkey_index_tree.iter() {
            let (_, value) = result?;
            
            // Verify MIK ID can be deserialized
            let _mik_id: MikId = bincode::deserialize(&value)
                .map_err(|_| MikStorageError::StorageCorruption)?;
            
            pubkey_count += 1;
        }

        // The counts should match (one pubkey entry per MIK)
        if mik_count != pubkey_count {
            return Err(MikStorageError::StorageCorruption);
        }

        Ok(())
    }

    /// Generate storage key for a MIK.
    fn mik_key(mik_id: &MikId) -> Vec<u8> {
        let mut key = Vec::with_capacity(storage_keys::MIK_PREFIX.len() + 32);
        key.extend_from_slice(storage_keys::MIK_PREFIX);
        key.extend_from_slice(mik_id);
        key
    }

    /// Generate storage key for public key index.
    fn pubkey_key(public_key: &PublicKey) -> Vec<u8> {
        let mut key = Vec::with_capacity(storage_keys::MIK_BY_PUBKEY_PREFIX.len() + 32);
        key.extend_from_slice(storage_keys::MIK_BY_PUBKEY_PREFIX);
        key.extend_from_slice(&public_key.as_bytes());
        key
    }
}

/// Statistics about MIK storage usage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MikStorageStats {
    pub mik_count: usize,
    pub pubkey_index_count: usize,
    pub total_size_bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyPair;
    use tempfile::TempDir;

    fn create_test_mik(keypair: &KeyPair, creation_block: u64) -> MiningIdentityKey {
        MiningIdentityKey::new(
            keypair.public_key(),
            creation_block,
            Some(creation_block + 1000),
            None,
        ).unwrap()
    }

    #[test]
    fn test_mik_storage_basic_operations() {
        let temp_dir = TempDir::new().unwrap();
        let storage = MikStorage::open(temp_dir.path().join("test_miks")).unwrap();

        let keypair = KeyPair::generate();
        let mik = create_test_mik(&keypair, 100);

        // Store MIK
        assert!(storage.store_mik(&mik).is_ok());

        // Retrieve by ID
        let retrieved = storage.get_mik(&mik.id).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, mik.id);

        // Retrieve by public key
        let retrieved_by_pubkey = storage.get_mik_by_public_key(&mik.public_key).unwrap();
        assert!(retrieved_by_pubkey.is_some());
        assert_eq!(retrieved_by_pubkey.unwrap().id, mik.id);
    }

    #[test]
    fn test_mik_state_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let storage = MikStorage::open(temp_dir.path().join("test_state")).unwrap();

        // Create test state
        let mut state = MikState::default();
        let keypair = KeyPair::generate();
        let mik = create_test_mik(&keypair, 100);
        
        state.miks.insert(mik.id, mik.clone());
        state.public_key_to_mik.insert(mik.public_key.clone(), mik.id);
        state.active_miks.insert(mik.id);

        // Store state
        assert!(storage.store_mik_state(&state).is_ok());

        // Load state
        let loaded_state = storage.load_mik_state().unwrap();
        assert_eq!(loaded_state.miks.len(), 1);
        assert_eq!(loaded_state.active_miks.len(), 1);
        assert!(loaded_state.miks.contains_key(&mik.id));
    }

    #[test]
    fn test_storage_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let storage = MikStorage::open(temp_dir.path().join("test_metadata")).unwrap();

        let state = MikState::default();
        let current_block = 42;

        // Update metadata
        assert!(storage.update_metadata(current_block, &state).is_ok());

        // Retrieve metadata
        let metadata = storage.get_metadata().unwrap();
        assert_eq!(metadata.last_updated_block, current_block);
        assert_eq!(metadata.total_miks, 0);
        assert_eq!(metadata.active_miks, 0);
    }

    #[test]
    fn test_storage_integrity_verification() {
        let temp_dir = TempDir::new().unwrap();
        let storage = MikStorage::open(temp_dir.path().join("test_integrity")).unwrap();

        let keypair = KeyPair::generate();
        let mik = create_test_mik(&keypair, 100);

        // Store MIK
        storage.store_mik(&mik).unwrap();

        // Verify integrity
        assert!(storage.verify_integrity().is_ok());
    }

    #[test]
    fn test_mik_removal() {
        let temp_dir = TempDir::new().unwrap();
        let storage = MikStorage::open(temp_dir.path().join("test_removal")).unwrap();

        let keypair = KeyPair::generate();
        let mik = create_test_mik(&keypair, 100);

        // Store and then remove MIK
        storage.store_mik(&mik).unwrap();
        assert!(storage.remove_mik(&mik.id).unwrap());

        // Should not be found after removal
        assert!(storage.get_mik(&mik.id).unwrap().is_none());
        assert!(storage.get_mik_by_public_key(&mik.public_key).unwrap().is_none());
    }

    #[test]
    fn test_get_all_mik_ids() {
        let temp_dir = TempDir::new().unwrap();
        let storage = MikStorage::open(temp_dir.path().join("test_all_ids")).unwrap();

        let mut expected_ids = Vec::new();

        // Store multiple MIKs
        for i in 0..5 {
            let keypair = KeyPair::generate();
            let mik = create_test_mik(&keypair, 100 + i);
            expected_ids.push(mik.id);
            storage.store_mik(&mik).unwrap();
        }

        // Get all IDs
        let mut stored_ids = storage.get_all_mik_ids().unwrap();
        stored_ids.sort();
        expected_ids.sort();

        assert_eq!(stored_ids, expected_ids);
    }
}