//! Transaction mempool for shielded transactions.
//!
//! Supports both V1 (legacy) and V2 (post-quantum) transactions.

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::{info, warn};

use crate::core::{ShieldedState, ShieldedTransaction, Transaction};
use crate::contract::{ContractDeployTransaction, ContractCallTransaction};

/// Maximum number of transactions in the mempool.
const MAX_MEMPOOL_SIZE: usize = 5000;

/// Minimum transaction fee (anti-spam). 1000 sats.
const MIN_TX_FEE: u64 = 1000;

/// Maximum age of a transaction in seconds (1 hour).
const MAX_TX_AGE_SECS: u64 = 3600;

/// Transaction metadata for eviction decisions.
#[derive(Debug, Clone)]
struct TxMeta {
    fee: u64,
    added_at: u64,
}

/// The mempool holds pending shielded transactions waiting to be mined.
#[derive(Debug, Default)]
pub struct Mempool {
    /// Pending V1 transactions by hash (for mining compatibility).
    v1_transactions: HashMap<[u8; 32], ShieldedTransaction>,
    /// Pending V2/Migration transactions by hash.
    v2_transactions: HashMap<[u8; 32], Transaction>,
    /// Pending contract deploy transactions by hash.
    contract_deploys: HashMap<[u8; 32], ContractDeployTransaction>,
    /// Pending contract call transactions by hash.
    contract_calls: HashMap<[u8; 32], ContractCallTransaction>,
    /// Pending nullifiers (to detect double-spends before confirmation).
    pending_nullifiers: HashSet<[u8; 32]>,
    /// Transaction metadata for eviction (fee + timestamp).
    tx_meta: HashMap<[u8; 32], TxMeta>,
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            v1_transactions: HashMap::new(),
            v2_transactions: HashMap::new(),
            contract_deploys: HashMap::new(),
            contract_calls: HashMap::new(),
            pending_nullifiers: HashSet::new(),
            tx_meta: HashMap::new(),
        }
    }

    fn now_secs() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
    }

    /// Total transaction count across all types.
    fn total_count(&self) -> usize {
        self.v1_transactions.len() + self.v2_transactions.len()
            + self.contract_deploys.len() + self.contract_calls.len()
    }

    /// Evict the lowest-fee transaction to make room. Returns true if eviction succeeded.
    fn evict_lowest_fee(&mut self) -> bool {
        // Find the tx with the lowest fee
        let lowest = self.tx_meta.iter()
            .min_by_key(|(_, meta)| meta.fee)
            .map(|(hash, _)| *hash);

        if let Some(hash) = lowest {
            self.remove(&hash);
            self.remove_v2(&hash);
            self.remove_contract_tx(&hash);
            self.tx_meta.remove(&hash);
            true
        } else {
            false
        }
    }

    /// Evict transactions older than MAX_TX_AGE_SECS. Returns count removed.
    pub fn evict_expired(&mut self) -> usize {
        let now = Self::now_secs();
        let expired: Vec<[u8; 32]> = self.tx_meta.iter()
            .filter(|(_, meta)| now.saturating_sub(meta.added_at) > MAX_TX_AGE_SECS)
            .map(|(hash, _)| *hash)
            .collect();

        let count = expired.len();
        for hash in &expired {
            self.remove(hash);
            self.remove_v2(hash);
            self.remove_contract_tx(hash);
            self.tx_meta.remove(hash);
        }
        if count > 0 {
            info!("Mempool: evicted {} expired transactions", count);
        }
        count
    }

    /// Add a V1 transaction to the mempool.
    /// Returns false if transaction already exists, would cause double-spend,
    /// fee is too low, or mempool is full and can't evict.
    pub fn add(&mut self, tx: ShieldedTransaction) -> bool {
        let hash = tx.hash();
        if self.v1_transactions.contains_key(&hash) || self.v2_transactions.contains_key(&hash) {
            return false;
        }

        // Enforce minimum fee
        if tx.fee < MIN_TX_FEE {
            warn!("Mempool: rejected tx {} — fee {} < min {}", hex::encode(&hash[..4]), tx.fee, MIN_TX_FEE);
            return false;
        }

        // Check for nullifier conflicts
        for nullifier in tx.nullifiers() {
            if self.pending_nullifiers.contains(&nullifier.0) {
                return false; // Double-spend attempt
            }
        }

        // Enforce size limit — evict expired first, then lowest-fee
        if self.total_count() >= MAX_MEMPOOL_SIZE {
            self.evict_expired();
            if self.total_count() >= MAX_MEMPOOL_SIZE {
                // Only accept if fee is higher than the lowest in pool
                let min_fee = self.tx_meta.values().map(|m| m.fee).min().unwrap_or(0);
                if tx.fee <= min_fee {
                    warn!("Mempool full: rejected tx {} (fee {} <= min {})", hex::encode(&hash[..4]), tx.fee, min_fee);
                    return false;
                }
                self.evict_lowest_fee();
            }
        }

        let fee = tx.fee;

        // Add nullifiers to pending set
        for nullifier in tx.nullifiers() {
            self.pending_nullifiers.insert(nullifier.0);
        }

        self.v1_transactions.insert(hash, tx);
        self.tx_meta.insert(hash, TxMeta { fee, added_at: Self::now_secs() });
        true
    }

    /// Add a V2 or Migration transaction to the mempool.
    /// Returns false if transaction already exists, would cause double-spend,
    /// fee is too low, or mempool is full and can't evict.
    pub fn add_v2(&mut self, tx: Transaction) -> bool {
        let hash = tx.hash();
        if self.v1_transactions.contains_key(&hash) || self.v2_transactions.contains_key(&hash) {
            return false;
        }

        let fee = tx.fee();

        // Enforce minimum fee
        if fee < MIN_TX_FEE {
            warn!("Mempool: rejected v2 tx {} — fee {} < min {}", hex::encode(&hash[..4]), fee, MIN_TX_FEE);
            return false;
        }

        // Check for nullifier conflicts
        for nullifier in tx.nullifiers() {
            if self.pending_nullifiers.contains(&nullifier) {
                return false; // Double-spend attempt
            }
        }

        // Enforce size limit
        if self.total_count() >= MAX_MEMPOOL_SIZE {
            self.evict_expired();
            if self.total_count() >= MAX_MEMPOOL_SIZE {
                let min_fee = self.tx_meta.values().map(|m| m.fee).min().unwrap_or(0);
                if fee <= min_fee {
                    warn!("Mempool full: rejected v2 tx {} (fee {} <= min {})", hex::encode(&hash[..4]), fee, min_fee);
                    return false;
                }
                self.evict_lowest_fee();
            }
        }

        // Add nullifiers to pending set
        for nullifier in tx.nullifiers() {
            self.pending_nullifiers.insert(nullifier);
        }

        self.v2_transactions.insert(hash, tx);
        self.tx_meta.insert(hash, TxMeta { fee, added_at: Self::now_secs() });
        true
    }

    /// Remove a V1 transaction from the mempool.
    pub fn remove(&mut self, hash: &[u8; 32]) -> Option<ShieldedTransaction> {
        if let Some(tx) = self.v1_transactions.remove(hash) {
            // Remove associated nullifiers
            for nullifier in tx.nullifiers() {
                self.pending_nullifiers.remove(&nullifier.0);
            }
            self.tx_meta.remove(hash);
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
            self.tx_meta.remove(hash);
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
            + self.contract_deploys.len() + self.contract_calls.len()
    }

    /// Check if the mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.v1_transactions.is_empty() && self.v2_transactions.is_empty()
            && self.contract_deploys.is_empty() && self.contract_calls.is_empty()
    }

    /// Remove transactions that are now in a block.
    pub fn remove_confirmed(&mut self, tx_hashes: &[[u8; 32]]) {
        for hash in tx_hashes {
            self.remove(hash);
            self.remove_v2(hash);
            self.remove_contract_tx(hash);
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

    /// Add a contract deploy transaction.
    pub fn add_contract_deploy(&mut self, tx: ContractDeployTransaction) -> bool {
        let hash = tx.hash();
        if self.contract_deploys.contains_key(&hash) {
            return false;
        }
        self.contract_deploys.insert(hash, tx);
        true
    }

    /// Add a contract call transaction.
    pub fn add_contract_call(&mut self, tx: ContractCallTransaction) -> bool {
        let hash = tx.hash();
        if self.contract_calls.contains_key(&hash) {
            return false;
        }
        self.contract_calls.insert(hash, tx);
        true
    }

    /// Get pending contract deploy transactions sorted by fee (highest first).
    pub fn get_contract_deploys(&self, limit: usize) -> Vec<ContractDeployTransaction> {
        let mut txs: Vec<_> = self.contract_deploys.values().cloned().collect();
        txs.sort_by(|a, b| b.fee.cmp(&a.fee));
        txs.truncate(limit);
        txs
    }

    /// Get pending contract call transactions sorted by fee (highest first).
    pub fn get_contract_calls(&self, limit: usize) -> Vec<ContractCallTransaction> {
        let mut txs: Vec<_> = self.contract_calls.values().cloned().collect();
        txs.sort_by(|a, b| b.fee.cmp(&a.fee));
        txs.truncate(limit);
        txs
    }

    /// Remove a confirmed contract transaction by hash.
    pub fn remove_contract_tx(&mut self, hash: &[u8; 32]) {
        self.contract_deploys.remove(hash);
        self.contract_calls.remove(hash);
    }

    /// Clear all transactions.
    pub fn clear(&mut self) {
        self.v1_transactions.clear();
        self.v2_transactions.clear();
        self.contract_deploys.clear();
        self.contract_calls.clear();
        self.pending_nullifiers.clear();
        self.tx_meta.clear();
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
        hashes.extend(self.contract_deploys.keys().cloned());
        hashes.extend(self.contract_calls.keys().cloned());
        hashes
    }

    /// Get total fees in the mempool.
    pub fn total_fees(&self) -> u64 {
        let v1_fees: u64 = self.v1_transactions.values().map(|tx| tx.fee).sum();
        let v2_fees: u64 = self.v2_transactions.values().map(|tx| tx.fee()).sum();
        let deploy_fees: u64 = self.contract_deploys.values().map(|tx| tx.fee).sum();
        let call_fees: u64 = self.contract_calls.values().map(|tx| tx.fee).sum();
        v1_fees + v2_fees + deploy_fees + call_fees
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

        let tx = dummy_v1_tx(5000); // Above MIN_TX_FEE
        let hash = tx.hash();

        assert!(mempool.add(tx));
        assert!(mempool.contains(&hash));
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_mempool_rejects_low_fee() {
        let mut mempool = Mempool::new();
        let tx = dummy_v1_tx(500); // Below MIN_TX_FEE
        assert!(!mempool.add(tx));
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn test_mempool_no_duplicates() {
        let mut mempool = Mempool::new();

        let tx = dummy_v1_tx(5000);
        assert!(mempool.add(tx.clone()));
        assert!(!mempool.add(tx)); // Should fail, duplicate
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_mempool_sorted_by_fee() {
        let mut mempool = Mempool::new();

        let tx1 = dummy_v1_tx(1000);
        let tx2 = dummy_v1_tx(5000);
        let tx3 = dummy_v1_tx(3000);

        mempool.add(tx1);
        mempool.add(tx2);
        mempool.add(tx3);

        let txs = mempool.get_transactions(10);
        assert_eq!(txs[0].fee, 5000);
        assert_eq!(txs[1].fee, 3000);
        assert_eq!(txs[2].fee, 1000);
    }

    #[test]
    fn test_mempool_total_fees() {
        let mut mempool = Mempool::new();

        mempool.add(dummy_v1_tx(10000));
        mempool.add(dummy_v1_tx(20000));
        mempool.add(dummy_v1_tx(30000));

        assert_eq!(mempool.total_fees(), 60000);
    }
}
