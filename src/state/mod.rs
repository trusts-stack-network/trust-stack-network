//! State management module for TSN blockchain.
//!
//! This module provides:
//! - UTXO tracking for shielded notes
//! - Balance calculation by viewing key
//! - Transaction history indexing by address
//! - Rollback mechanism for chain reorganizations
//!
//! The state model is privacy-preserving: balances are computed from
//! decrypted notes, not stored on-chain.

pub mod balance;
pub mod history;
pub mod rollback;
pub mod utxo;

// Re-export main types
pub use balance::{BalanceTracker, BalanceError};
pub use history::{TransactionHistory, HistoryEntry, HistoryError};
pub use rollback::{RollbackManager, StateSnapshot, RollbackError};
pub use utxo::{UtxoSet, UtxoEntry, UtxoError};

use crate::core::state::ShieldedState as CoreShieldedState;

/// Complete blockchain state combining all subsystems.
///
/// This wraps the core ShieldedState and adds:
/// - UTXO tracking for wallet operations
/// - Balance indexing for fast lookups
/// - Transaction history for explorers/wallets
/// - Rollback capability for reorgs
#[derive(Clone, Debug)]
pub struct BlockchainState {
    /// Core shielded state (commitment tree, nullifier set)
    pub core: CoreShieldedState,
    /// UTXO set tracking spendable notes
    pub utxos: UtxoSet,
    /// Balance tracker by viewing key
    pub balances: BalanceTracker,
    /// Transaction history index
    pub history: TransactionHistory,
    /// Rollback manager for snapshots
    pub rollback: RollbackManager,
}

impl BlockchainState {
    /// Create a new empty blockchain state.
    pub fn new() -> Self {
        Self {
            core: CoreShieldedState::new(),
            utxos: UtxoSet::new(),
            balances: BalanceTracker::new(),
            history: TransactionHistory::new(),
            rollback: RollbackManager::new(),
        }
    }

    /// Create a snapshot of the current state at the given height.
    ///
    /// This is used before applying a block to enable rollback
    /// in case of chain reorganizations.
    pub fn snapshot(&self, height: u64, block_hash: [u8; 32]) -> StateSnapshot {
        StateSnapshot {
            height,
            block_hash,
            core_state: self.core.snapshot(),
            utxo_snapshot: self.utxos.snapshot(),
            balance_snapshot: self.balances.snapshot(),
            history_snapshot: self.history.snapshot(),
        }
    }

    /// Restore state from a snapshot.
    ///
    /// # Safety
    /// This should only be called during chain reorganization when
    /// we need to revert to a previous state.
    pub fn restore_from_snapshot(&mut self, snapshot: StateSnapshot) {
        self.core = snapshot.core_state;
        self.utxos.restore_from_snapshot(snapshot.utxo_snapshot);
        self.balances.restore_from_snapshot(snapshot.balance_snapshot);
        self.history.restore_from_snapshot(snapshot.history_snapshot);
    }
}

impl Default for BlockchainState {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur during state operations.
#[derive(thiserror::Error, Debug, Clone)]
pub enum StateError {
    #[error("UTXO error: {0}")]
    Utxo(#[from] UtxoError),
    
    #[error("Balance error: {0}")]
    Balance(#[from] BalanceError),
    
    #[error("History error: {0}")]
    History(#[from] HistoryError),
    
    #[error("Rollback error: {0}")]
    Rollback(#[from] RollbackError),
    
    #[error("Core state error: {0}")]
    Core(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blockchain_state_new() {
        let state = BlockchainState::new();
        assert_eq!(state.core.nullifier_count(), 0);
        assert!(state.utxos.is_empty());
    }

    #[test]
    fn test_snapshot_and_restore() {
        let mut state = BlockchainState::new();
        let snapshot = state.snapshot(0, [0u8; 32]);
        
        // Restore should work
        state.restore_from_snapshot(snapshot);
        assert_eq!(state.core.nullifier_count(), 0);
    }
}
