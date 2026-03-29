//! UTXO (Unspent Transaction Output) management for shielded notes.
//!
//! In a shielded blockchain, UTXOs are represented as encrypted notes
//! that can be decrypted by the recipient's viewing key. This module
//! tracks which notes are unspent and their association with addresses.
//!
//! # Design Invariants
//!
//! 1. A note is either spent (has a nullifier in the nullifier set) or unspent.
//! 2. Each UTXO entry contains the note data needed for spending.
//! 3. UTXOs are indexed by nullifier for quick spend detection.
//! 4. UTXOs are also indexed by viewing key for wallet balance queries.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::crypto::{
    note::{EncryptedNote, Note, ViewingKey},
    nullifier::{Nullifier, NullifierKey},
    Address,
};

/// A UTXO entry representing an unspent shielded note.
///
/// This contains all data needed to spend the note: the note itself
/// (which includes the value and recipient), the nullifier key,
/// and metadata for tracking.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoEntry {
    /// The nullifier that will be revealed when this note is spent.
    /// This acts as the UTXO identifier.
    pub nullifier: Nullifier,
    /// The encrypted note data (ciphertext + ephemeral public key).
    pub encrypted_note: EncryptedNote,
    /// Block height at which this UTXO was created.
    pub block_height: u64,
    /// Transaction hash that created this UTXO.
    pub tx_hash: [u8; 32],
    /// Output index in the transaction.
    pub output_index: u32,
    /// Commitment to this note (in the commitment tree).
    pub commitment: [u8; 32],
}

impl UtxoEntry {
    /// Create a new UTXO entry.
    pub fn new(
        nullifier: Nullifier,
        encrypted_note: EncryptedNote,
        block_height: u64,
        tx_hash: [u8; 32],
        output_index: u32,
        commitment: [u8; 32],
    ) -> Self {
        Self {
            nullifier,
            encrypted_note,
            block_height,
            tx_hash,
            output_index,
            commitment,
        }
    }

    /// Attempt to decrypt this UTXO's note with the given viewing key.
    ///
    /// Returns `Some(Note)` if the viewing key can decrypt this note,
    /// `None` otherwise.
    pub fn decrypt_note(&self, viewing_key: &ViewingKey) -> Option<Note> {
        self.encrypted_note.decrypt(viewing_key)
    }

    /// Check if this UTXO belongs to the given viewing key.
    ///
    /// This attempts decryption - if successful, the note belongs to this key.
    pub fn belongs_to(&self, viewing_key: &ViewingKey) -> bool {
        self.decrypt_note(viewing_key).is_some()
    }
}

/// The UTXO set tracking all unspent notes.
///
/// This provides O(1) lookups by nullifier and efficient queries
/// by viewing key for wallet operations.
#[derive(Clone, Debug, Default)]
pub struct UtxoSet {
    /// All unspent outputs indexed by nullifier.
    utxos: HashMap<Nullifier, UtxoEntry>,
    /// Index of UTXOs by viewing key (for wallet queries).
    /// Note: This is a cache - can be rebuilt by scanning all UTXOs.
    by_viewing_key: HashMap<[u8; 32], HashSet<Nullifier>>,
    /// Total number of UTXOs (for stats).
    total_count: u64,
}

impl UtxoSet {
    /// Create a new empty UTXO set.
    pub fn new() -> Self {
        Self {
            utxos: HashMap::new(),
            by_viewing_key: HashMap::new(),
            total_count: 0,
        }
    }

    /// Add a new UTXO to the set.
    ///
    /// # Errors
    /// Returns `UtxoError::AlreadyExists` if this nullifier is already tracked.
    pub fn add(&mut self, entry: UtxoEntry) -> Result<(), UtxoError> {
        if self.utxos.contains_key(&entry.nullifier) {
            return Err(UtxoError::AlreadyExists(entry.nullifier));
        }

        self.total_count += 1;
        self.utxos.insert(entry.nullifier, entry);
        Ok(())
    }

    /// Mark a UTXO as spent by its nullifier.
    ///
    /// Returns the removed UTXO entry if found.
    pub fn spend(&mut self, nullifier: &Nullifier) -> Option<UtxoEntry> {
        let entry = self.utxos.remove(nullifier)?;
        self.total_count -= 1;

        // Remove from viewing key index if present
        // Note: We need to know the viewing key to remove from index.
        // In practice, this requires scanning or maintaining a reverse index.
        // For now, we leave stale entries that will be cleaned up on rebuild.
        
        Some(entry)
    }

    /// Check if a UTXO exists (is unspent).
    pub fn contains(&self, nullifier: &Nullifier) -> bool {
        self.utxos.contains_key(nullifier)
    }

    /// Get a UTXO by its nullifier.
    pub fn get(&self, nullifier: &Nullifier) -> Option<&UtxoEntry> {
        self.utxos.get(nullifier)
    }

    /// Get all UTXOs that belong to a given viewing key.
    ///
    /// This scans all UTXOs and attempts decryption - O(n) operation.
    /// For production use, maintain the by_viewing_key index.
    pub fn get_by_viewing_key(&self, viewing_key: &ViewingKey) -> Vec<&UtxoEntry> {
        self.utxos
            .values()
            .filter(|entry| entry.belongs_to(viewing_key))
            .collect()
    }

    /// Get the total number of UTXOs.
    pub fn len(&self) -> usize {
        self.utxos.len()
    }

    /// Check if the UTXO set is empty.
    pub fn is_empty(&self) -> bool {
        self.utxos.is_empty()
    }

    /// Get an iterator over all UTXOs.
    pub fn iter(&self) -> impl Iterator<Item = &UtxoEntry> {
        self.utxos.values()
    }

    /// Create a snapshot of the current UTXO set.
    pub fn snapshot(&self) -> UtxoSnapshot {
        UtxoSnapshot {
            utxos: self.utxos.clone(),
            total_count: self.total_count,
        }
    }

    /// Restore from a snapshot.
    pub fn restore_from_snapshot(&mut self, snapshot: UtxoSnapshot) {
        self.utxos = snapshot.utxos;
        self.total_count = snapshot.total_count;
        // Rebuild viewing key index
        self.by_viewing_key.clear();
    }

    /// Rebuild the viewing key index by scanning all UTXOs.
    ///
    /// This is expensive and should be done lazily or in background.
    pub fn rebuild_viewing_key_index(&mut self, known_viewing_keys: &[ViewingKey]) {
        self.by_viewing_key.clear();
        
        for (nullifier, entry) in &self.utxos {
            for vk in known_viewing_keys {
                if entry.belongs_to(vk) {
                    let vk_hash = hash_viewing_key(vk);
                    self.by_viewing_key
                        .entry(vk_hash)
                        .or_default()
                        .insert(*nullifier);
                }
            }
        }
    }
}

/// Snapshot of the UTXO set for rollback support.
#[derive(Clone, Debug)]
pub struct UtxoSnapshot {
    utxos: HashMap<Nullifier, UtxoEntry>,
    total_count: u64,
}

/// Errors that can occur during UTXO operations.
#[derive(thiserror::Error, Debug, Clone)]
pub enum UtxoError {
    #[error("UTXO with nullifier {0:?} already exists")]
    AlreadyExists(Nullifier),
    
    #[error("UTXO with nullifier {0:?} not found")]
    NotFound(Nullifier),
    
    #[error("Decryption failed: invalid viewing key")]
    DecryptionFailed,
}

/// Hash a viewing key for use as a map key.
fn hash_viewing_key(vk: &ViewingKey) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    // SAFETY: ViewingKey serialization is infallible for this use
    hasher.update(&vk.to_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::note::{Note, ViewingKey};
    use crate::crypto::Address;

    fn create_test_encrypted_note() -> EncryptedNote {
        EncryptedNote {
            ciphertext: vec![1u8; 64],
            ephemeral_pk: vec![2u8; 32],
        }
    }

    fn create_test_nullifier() -> Nullifier {
        Nullifier::from_bytes([3u8; 32])
    }

    #[test]
    fn test_utxo_entry_creation() {
        let entry = UtxoEntry::new(
            create_test_nullifier(),
            create_test_encrypted_note(),
            100,
            [4u8; 32],
            0,
            [5u8; 32],
        );

        assert_eq!(entry.block_height, 100);
        assert_eq!(entry.output_index, 0);
    }

    #[test]
    fn test_utxo_set_add_and_get() {
        let mut set = UtxoSet::new();
        let nf = create_test_nullifier();
        let entry = UtxoEntry::new(
            nf,
            create_test_encrypted_note(),
            100,
            [4u8; 32],
            0,
            [5u8; 32],
        );

        // Add UTXO
        set.add(entry.clone()).unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.contains(&nf));

        // Get UTXO
        let retrieved = set.get(&nf).unwrap();
        assert_eq!(retrieved.block_height, 100);

        // Duplicate add should fail
        assert!(matches!(set.add(entry), Err(UtxoError::AlreadyExists(_))));
    }

    #[test]
    fn test_utxo_set_spend() {
        let mut set = UtxoSet::new();
        let nf = create_test_nullifier();
        let entry = UtxoEntry::new(
            nf,
            create_test_encrypted_note(),
            100,
            [4u8; 32],
            0,
            [5u8; 32],
        );

        set.add(entry).unwrap();
        assert_eq!(set.len(), 1);

        // Spend the UTXO
        let spent = set.spend(&nf).unwrap();
        assert_eq!(spent.block_height, 100);
        assert_eq!(set.len(), 0);
        assert!(!set.contains(&nf));

        // Spending again returns None
        assert!(set.spend(&nf).is_none());
    }

    #[test]
    fn test_utxo_snapshot() {
        let mut set = UtxoSet::new();
        let nf = create_test_nullifier();
        let entry = UtxoEntry::new(
            nf,
            create_test_encrypted_note(),
            100,
            [4u8; 32],
            0,
            [5u8; 32],
        );

        set.add(entry).unwrap();
        let snapshot = set.snapshot();

        // Modify set
        set.spend(&nf);
        assert!(set.is_empty());

        // Restore
        set.restore_from_snapshot(snapshot);
        assert_eq!(set.len(), 1);
        assert!(set.contains(&nf));
    }
}
