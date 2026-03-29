//! Balance tracking for shielded accounts.
//!
//! This module provides balance calculation and tracking for shielded
//! addresses. Since TSN uses a shielded model, balances are computed
//! by decrypting UTXOs with the viewing key, not stored on-chain.
//!
//! # Design Invariants
//!
//! 1. Balances are always derived from UTXOs, never stored directly.
//! 2. The balance tracker maintains a cache for performance.
//! 3. All balance calculations are verified against the UTXO set.
//! 4. Negative balances are impossible by construction.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::crypto::note::{Note, ViewingKey};
use crate::crypto::nullifier::Nullifier;

use super::utxo::{UtxoEntry, UtxoSet};

/// Balance information for a shielded account.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Balance {
    /// Total confirmed balance (all UTXOs).
    pub total: u64,
    /// Available balance (confirmed - pending spends).
    pub available: u64,
    /// Pending incoming balance (from mempool).
    pub pending_incoming: u64,
    /// Pending outgoing balance (spends in mempool).
    pub pending_outgoing: u64,
    /// Number of UTXOs contributing to this balance.
    pub utxo_count: u32,
}

impl Balance {
    /// Create a new zero balance.
    pub fn zero() -> Self {
        Self::default()
    }

    /// Check if balance is zero.
    pub fn is_zero(&self) -> bool {
        self.total == 0 && self.pending_incoming == 0 && self.pending_outgoing == 0
    }

    /// Get the effective balance (available + pending_incoming - pending_outgoing).
    pub fn effective(&self) -> u64 {
        self.available.saturating_add(self.pending_incoming)
            .saturating_sub(self.pending_outgoing)
    }
}

/// Tracks balances for shielded accounts.
///
/// This maintains a cache of balances by viewing key for fast lookups.
/// The cache is invalidated when UTXOs are added or spent.
#[derive(Clone, Debug, Default)]
pub struct BalanceTracker {
    /// Cached balances by viewing key hash.
    balances: HashMap<[u8; 32], Balance>,
    /// Map of which viewing keys own which UTXOs (for cache invalidation).
    /// nullifier -> viewing_key_hash
    ownership_index: HashMap<Nullifier, [u8; 32]>,
}

impl BalanceTracker {
    /// Create a new balance tracker.
    pub fn new() -> Self {
        Self {
            balances: HashMap::new(),
            ownership_index: HashMap::new(),
        }
    }

    /// Calculate balance for a viewing key from the UTXO set.
    ///
    /// This scans all UTXOs and decrypts them with the viewing key.
    /// O(n) where n is the number of UTXOs.
    pub fn calculate_balance(
        &self,
        viewing_key: &ViewingKey,
        utxo_set: &UtxoSet,
    ) -> Balance {
        let mut balance = Balance::zero();

        for entry in utxo_set.iter() {
            if let Some(note) = entry.decrypt_note(viewing_key) {
                balance.total += note.value;
                balance.available += note.value;
                balance.utxo_count += 1;
            }
        }

        balance
    }

    /// Get cached balance for a viewing key.
    ///
    /// Returns `None` if no cached balance exists.
    pub fn get_balance(&self, viewing_key: &ViewingKey) -> Option<&Balance> {
        let vk_hash = hash_viewing_key(viewing_key);
        self.balances.get(&vk_hash)
    }

    /// Update cached balance for a viewing key.
    ///
    /// This recalculates from the UTXO set and updates the cache.
    pub fn update_balance(
        &mut self,
        viewing_key: &ViewingKey,
        utxo_set: &UtxoSet,
    ) -> Balance {
        let balance = self.calculate_balance(viewing_key, utxo_set);
        let vk_hash = hash_viewing_key(viewing_key);
        
        // Update ownership index
        for entry in utxo_set.iter() {
            if entry.belongs_to(viewing_key) {
                self.ownership_index.insert(entry.nullifier, vk_hash);
            }
        }
        
        self.balances.insert(vk_hash, balance.clone());
        balance
    }

    /// Add a UTXO and update affected balances.
    ///
    /// This checks if the UTXO belongs to any known viewing key
    /// and updates their cached balance.
    pub fn add_utxo(
        &mut self,
        entry: &UtxoEntry,
        known_viewing_keys: &[ViewingKey],
    ) {
        for vk in known_viewing_keys {
            if entry.belongs_to(vk) {
                let vk_hash = hash_viewing_key(vk);
                
                // Update ownership index
                self.ownership_index.insert(entry.nullifier, vk_hash);
                
                // Update cached balance
                let balance = self.balances.entry(vk_hash).or_default();
                if let Some(note) = entry.decrypt_note(vk) {
                    balance.total += note.value;
                    balance.available += note.value;
                    balance.utxo_count += 1;
                }
            }
        }
    }

    /// Remove a UTXO (when spent) and update affected balances.
    ///
    /// Returns the viewing key hash that owned this UTXO, if known.
    pub fn remove_utxo(
        &mut self,
        nullifier: &Nullifier,
        utxo_value: u64,
    ) -> Option<[u8; 32]> {
        if let Some(vk_hash) = self.ownership_index.remove(nullifier) {
            if let Some(balance) = self.balances.get_mut(&vk_hash) {
                balance.total = balance.total.saturating_sub(utxo_value);
                balance.available = balance.available.saturating_sub(utxo_value);
                if balance.utxo_count > 0 {
                    balance.utxo_count -= 1;
                }
            }
            Some(vk_hash)
        } else {
            None
        }
    }

    /// Set pending outgoing amount for a viewing key.
    ///
    /// This is used when a transaction is created but not yet confirmed.
    pub fn set_pending_outgoing(
        &mut self,
        viewing_key: &ViewingKey,
        amount: u64,
    ) {
        let vk_hash = hash_viewing_key(viewing_key);
        let balance = self.balances.entry(vk_hash).or_default();
        balance.pending_outgoing = amount;
        balance.available = balance.total.saturating_sub(amount);
    }

    /// Clear pending outgoing amount for a viewing key.
    pub fn clear_pending_outgoing(&mut self, viewing_key: &ViewingKey) {
        let vk_hash = hash_viewing_key(viewing_key);
        if let Some(balance) = self.balances.get_mut(&vk_hash) {
            balance.pending_outgoing = 0;
            balance.available = balance.total;
        }
    }

    /// Set pending incoming amount for a viewing key.
    pub fn set_pending_incoming(
        &mut self,
        viewing_key: &ViewingKey,
        amount: u64,
    ) {
        let vk_hash = hash_viewing_key(viewing_key);
        let balance = self.balances.entry(vk_hash).or_default();
        balance.pending_incoming = amount;
    }

    /// Clear pending incoming amount for a viewing key.
    pub fn clear_pending_incoming(&mut self, viewing_key: &ViewingKey) {
        let vk_hash = hash_viewing_key(viewing_key);
        if let Some(balance) = self.balances.get_mut(&vk_hash) {
            balance.pending_incoming = 0;
        }
    }

    /// Get all tracked viewing key hashes.
    pub fn tracked_keys(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.balances.keys()
    }

    /// Create a snapshot of the balance tracker.
    pub fn snapshot(&self) -> BalanceSnapshot {
        BalanceSnapshot {
            balances: self.balances.clone(),
            ownership_index: self.ownership_index.clone(),
        }
    }

    /// Restore from a snapshot.
    pub fn restore_from_snapshot(&mut self, snapshot: BalanceSnapshot) {
        self.balances = snapshot.balances;
        self.ownership_index = snapshot.ownership_index;
    }

    /// Clear all cached balances.
    pub fn clear(&mut self) {
        self.balances.clear();
        self.ownership_index.clear();
    }
}

/// Snapshot of balance tracker for rollback support.
#[derive(Clone, Debug)]
pub struct BalanceSnapshot {
    balances: HashMap<[u8; 32], Balance>,
    ownership_index: HashMap<Nullifier, [u8; 32]>,
}

/// Errors that can occur during balance operations.
#[derive(thiserror::Error, Debug, Clone)]
pub enum BalanceError {
    #[error("Viewing key not found")]
    ViewingKeyNotFound,
    
    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u64, available: u64 },
    
    #[error("Invalid amount: {0}")]
    InvalidAmount(u64),
    
    #[error("Cache inconsistency detected")]
    CacheInconsistency,
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
    use crate::crypto::note::{EncryptedNote, Note};
    use crate::crypto::nullifier::Nullifier;

    fn create_test_utxo(value: u64) -> (UtxoEntry, Note) {
        // Create a note with the given value
        // For testing, we use dummy data
        let note = Note {
            value,
            recipient: [0u8; 32],
            rho: [0u8; 32],
            rcm: [0u8; 32],
        };
        
        let entry = UtxoEntry::new(
            Nullifier::from_bytes([1u8; 32]),
            EncryptedNote {
                ciphertext: vec![1u8; 64],
                ephemeral_pk: vec![2u8; 32],
            },
            100,
            [3u8; 32],
            0,
            [4u8; 32],
        );
        
        (entry, note)
    }

    #[test]
    fn test_balance_creation() {
        let balance = Balance::zero();
        assert!(balance.is_zero());
        assert_eq!(balance.total, 0);
        assert_eq!(balance.available, 0);
    }

    #[test]
    fn test_balance_effective() {
        let balance = Balance {
            total: 1000,
            available: 800,
            pending_incoming: 200,
            pending_outgoing: 100,
            utxo_count: 5,
        };
        
        assert_eq!(balance.effective(), 900);
    }

    #[test]
    fn test_balance_tracker_snapshot() {
        let mut tracker = BalanceTracker::new();
        let vk = ViewingKey::from_bytes([1u8; 32]);
        
        // Manually insert a balance
        let vk_hash = hash_viewing_key(&vk);
        tracker.balances.insert(vk_hash, Balance {
            total: 1000,
            available: 1000,
            pending_incoming: 0,
            pending_outgoing: 0,
            utxo_count: 1,
        });
        
        let snapshot = tracker.snapshot();
        
        // Modify tracker
        tracker.clear();
        assert!(tracker.balances.is_empty());
        
        // Restore
        tracker.restore_from_snapshot(snapshot);
        assert_eq!(tracker.get_balance(&vk).unwrap().total, 1000);
    }

    #[test]
    fn test_pending_operations() {
        let mut tracker = BalanceTracker::new();
        let vk = ViewingKey::from_bytes([1u8; 32]);
        
        // Set up initial balance
        let vk_hash = hash_viewing_key(&vk);
        tracker.balances.insert(vk_hash, Balance {
            total: 1000,
            available: 1000,
            pending_incoming: 0,
            pending_outgoing: 0,
            utxo_count: 1,
        });
        
        // Set pending outgoing
        tracker.set_pending_outgoing(&vk, 300);
        let balance = tracker.get_balance(&vk).unwrap();
        assert_eq!(balance.pending_outgoing, 300);
        assert_eq!(balance.available, 700);
        
        // Clear pending
        tracker.clear_pending_outgoing(&vk);
        let balance = tracker.get_balance(&vk).unwrap();
        assert_eq!(balance.pending_outgoing, 0);
        assert_eq!(balance.available, 1000);
    }
}
