//! Transaction mempool for shielded transactions.
//!
//! Supports both V1 (legacy) and V2 (post-quantum) transactions.

use std::collections::{HashMap, HashSet};

use crate::core::{ShieldedState, ShieldedTransaction, Transaction};

/// The mempool holds pending shielded transactions waiting to be mined.
#[derive(Debug, Default)]
pub struct Mempool {
    /// Pending V1 transactions by hash (for mining compatibility).
    v1_transactions: HashMap<[u8; 32], ShieldedTransaction>,
    /// Pending V2/Migration transactions by hash.
    v2_transactions: HashMap<[u8; 32], Transaction>,
    /// Pending nullifiers (to detect double-spends before confirmation).
    pending_nullifiers: HashSet<[u8; 32]>,
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            v1_transactions: HashMap::new(),
            v2_transactions: HashMap::new(),
            pending_nullifiers: HashSet::new(),
        }
    }

    /// Add a V1 transaction to the mempool.
    /// Returns false if transaction already exists or would cause double-spend.
    pub fn add(&mut self, tx: ShieldedTransaction) -> bool {
        let hash = tx.hash();
        if self.v1_transactions.contains_key(&hash) || self.v2_transactions.contains_key(&hash) {
            return false;
        }

        // Check for nullifier conflicts
        for nullifier in tx.nullifiers() {
            if self.pending_nullifiers.contains(&nullifier.0) {
                return false; // Double-spend attempt
            }
        }

        // Add nullifiers to pending set
        for nullifier in tx.nullifiers() {
            self.pending_nullifiers.insert(nullifier.0);
        }

        self.v1_transactions.insert(hash, tx);
        true
    }

    /// Add a V2 or Migration transaction to the mempool.
    /// Returns false if transaction already exists or would cause double-spend.
    pub fn add_v2(&mut self, tx: Transaction) -> bool {
        let hash = tx.hash();
        if self.v1_transactions.contains_key(&hash) || self.v2_transactions.contains_key(&hash) {
            return false;
        }

        // Check for nullifier conflicts
        for nullifier in tx.nullifiers() {
            if self.pending_nullifiers.contains(&nullifier) {
                return false; // Double-spend attempt
            }
        }

        // Add nullifiers to pending set
        for nullifier in tx.nullifiers() {
            self.pending_nullifiers.insert(nullifier);
        }

        self.v2_transactions.insert(hash, tx);
        true
    }

    /// Remove a V1 transaction from the mempool.
    pub fn remove(&mut self, hash: &[u8; 32]) -> Option<ShieldedTransaction> {
        if let Some(tx) = self.v1_transactions.remove(hash) {
            // Remove associated nullifiers
            for nullifier in tx.nullifiers() {
                self.pending_nullifiers.remove(&nullifier.0);
            }
            Some(tx)
        } else {
            None
        }
    }

    /// Remove a V2 transaction from the mempool.
    pub fn remove_v2(&mut self, hash: &[u8; 32]) -> Option<Transaction> {
        if let Some(tx) = self.v2_transactions.remove(hash) {
            // Remove associated nullifiers
            for nullifier in tx.nullifiers() {
                self.pending_nullifiers.remove(&nullifier);
            }
            Some(tx)
        } else {
            None
        }
    }

    /// Get a V1 transaction by hash.
    pub fn get(&self, hash: &[u8; 32]) -> Option<&ShieldedTransaction> {
        self.v1_transactions.get(hash)
    }

    /// Get a V2 transaction by hash.
    pub fn get_v2(&self, hash: &[u8; 32]) -> Option<&Transaction> {
        self.v2_transactions.get(hash)
    }

    /// Check if a transaction is in the mempool.
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.v1_transactions.contains_key(hash) || self.v2_transactions.contains_key(hash)
    }

    /// Check if a nullifier is pending in the mempool.
    pub fn has_pending_nullifier(&self, nullifier: &[u8; 32]) -> bool {
        self.pending_nullifiers.contains(nullifier)
    }

    /// Get all V1 transactions, sorted by fee (highest first).
    pub fn get_transactions(&self, limit: usize) -> Vec<ShieldedTransaction> {
        let mut txs: Vec<_> = self.v1_transactions.values().cloned().collect();
        txs.sort_by(|a, b| b.fee.cmp(&a.fee));
        txs.truncate(limit);
        txs
    }

    /// Get all V2 transactions, sorted by fee (highest first).
    pub fn get_v2_transactions(&self, limit: usize) -> Vec<Transaction> {
        let mut txs: Vec<_> = self.v2_transactions.values().cloned().collect();
        txs.sort_by(|a, b| b.fee().cmp(&a.fee()));
        txs.truncate(limit);
        txs
    }

    /// Get only ShieldedTransactionV2 transactions for mining.
    pub fn get_shielded_v2_transactions(&self, limit: usize) -> Vec<crate::core::ShieldedTransactionV2> {
        use crate::core::Transaction as TxEnum;
        let mut txs: Vec<_> = self.v2_transactions.values()
            .filter_map(|tx| match tx {
                TxEnum::V2(v2) => Some(v2.clone()),
                _ => None,
            })
            .collect();
        txs.sort_by(|a, b| b.fee.cmp(&a.fee));
        txs.truncate(limit);
        txs
    }

    /// Number of transactions in the mempool.
    pub fn len(&self) -> usize {
        self.v1_transactions.len() + self.v2_transactions.len()
    }

    /// Check if the mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.v1_transactions.is_empty() && self.v2_transactions.is_empty()
    }

    /// Remove transactions that are now in a block.
    pub fn remove_confirmed(&mut self, tx_hashes: &[[u8; 32]]) {
        for hash in tx_hashes {
            self.remove(hash);
            self.remove_v2(hash);
        }
    }

    /// Remove transactions with nullifiers that are now spent on-chain.
    pub fn remove_spent_nullifiers(&mut self, spent_nullifiers: &[[u8; 32]]) {
        let mut to_remove_v1 = Vec::new();
        let mut to_remove_v2 = Vec::new();

        for (hash, tx) in &self.v1_transactions {
            for nullifier in tx.nullifiers() {
                if spent_nullifiers.contains(&nullifier.0) {
                    to_remove_v1.push(*hash);
                    break;
                }
            }
        }

        for (hash, tx) in &self.v2_transactions {
            for nullifier in tx.nullifiers() {
                if spent_nullifiers.contains(&nullifier) {
                    to_remove_v2.push(*hash);
                    break;
                }
            }
        }

        for hash in to_remove_v1 {
            self.remove(&hash);
        }
        for hash in to_remove_v2 {
            self.remove_v2(&hash);
        }
    }

    /// Clear all transactions.
    pub fn clear(&mut self) {
        self.v1_transactions.clear();
        self.v2_transactions.clear();
        self.pending_nullifiers.clear();
    }

    /// Re-validate all V1 transactions against the current chain state.
    /// Returns the number of transactions removed.
    pub fn revalidate(&mut self, state: &ShieldedState) -> usize {
        let mut invalid_hashes = Vec::new();

        for (hash, tx) in &self.v1_transactions {
            // Check anchors are still valid
            for anchor in tx.anchors() {
                if !state.is_valid_anchor(anchor) {
                    invalid_hashes.push(*hash);
                    break;
                }
            }

            // Check nullifiers aren't spent
            for nullifier in tx.nullifiers() {
                if state.is_nullifier_spent(nullifier) {
                    invalid_hashes.push(*hash);
                    break;
                }
            }
        }

        let removed = invalid_hashes.len();
        for hash in invalid_hashes {
            self.remove(&hash);
        }

        removed
    }

    /// Get all transaction hashes.
    pub fn get_hashes(&self) -> Vec<[u8; 32]> {
        let mut hashes: Vec<_> = self.v1_transactions.keys().cloned().collect();
        hashes.extend(self.v2_transactions.keys().cloned());
        hashes
    }

    /// Get total fees in the mempool.
    pub fn total_fees(&self) -> u64 {
        let v1_fees: u64 = self.v1_transactions.values().map(|tx| tx.fee).sum();
        let v2_fees: u64 = self.v2_transactions.values().map(|tx| tx.fee()).sum();
        v1_fees + v2_fees
    }

    /// Get the pending nullifiers set (for conflict checking).
    pub fn pending_nullifiers(&self) -> &HashSet<[u8; 32]> {
        &self.pending_nullifiers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::BindingSignature;

    fn dummy_v1_tx(fee: u64) -> ShieldedTransaction {
        ShieldedTransaction::new(vec![], vec![], fee, BindingSignature::new(vec![1; 64]))
    }

    #[test]
    fn test_mempool_add_and_get() {
        let mut mempool = Mempool::new();

        let tx = dummy_v1_tx(10);
        let hash = tx.hash();

        assert!(mempool.add(tx));
        assert!(mempool.contains(&hash));
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_mempool_no_duplicates() {
        let mut mempool = Mempool::new();

        let tx = dummy_v1_tx(10);
        assert!(mempool.add(tx.clone()));
        assert!(!mempool.add(tx)); // Should fail, duplicate
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_mempool_sorted_by_fee() {
        let mut mempool = Mempool::new();

        let tx1 = dummy_v1_tx(1);
        let tx2 = dummy_v1_tx(5);
        let tx3 = dummy_v1_tx(3);

        mempool.add(tx1);
        mempool.add(tx2);
        mempool.add(tx3);

        let txs = mempool.get_transactions(10);
        assert_eq!(txs[0].fee, 5);
        assert_eq!(txs[1].fee, 3);
        assert_eq!(txs[2].fee, 1);
    }

    #[test]
    fn test_mempool_total_fees() {
        let mut mempool = Mempool::new();

        mempool.add(dummy_v1_tx(10));
        mempool.add(dummy_v1_tx(20));
        mempool.add(dummy_v1_tx(30));

        assert_eq!(mempool.total_fees(), 60);
    }
}
