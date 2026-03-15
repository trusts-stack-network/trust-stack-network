//! Core blockchain data structures.
//!
//! This module contains the fundamental types for the privacy-preserving blockchain:
//! - ShieldedBlock: Block containing shielded transactions
//! - ShieldedTransaction: Private transaction with zk-SNARK proofs
//! - ShieldedState: Commitment tree and nullifier set (no visible balances)
//! - CoinbaseTransaction: Mining reward transaction

mod block;
mod transaction;
mod state;
mod blockchain;

// Shielded types (primary)
pub use block::{
    BlockError, BlockHeader, BlockHeaderHashPrefix, ShieldedBlock, BLOCK_HASH_SIZE,
};
pub use transaction::{
    BindingSignature, CoinbaseTransaction, LegacyTransaction, OutputDescription,
    ShieldedTransaction, SpendDescription, TransactionError,
    // V2 (Post-Quantum) types
    SpendDescriptionV2, OutputDescriptionV2, ShieldedTransactionV2,
    MigrationTransaction, Transaction,
};
pub use state::{ShieldedState, StateError, StateSnapshotPQ};
pub use blockchain::{ShieldedBlockchain, ChainInfo};

// Legacy types (for migration)
pub use state::{Account, LegacyState};

/// Compute the Merkle root of a list of transaction hashes.
pub fn merkle_root(tx_hashes: &[[u8; 32]]) -> [u8; 32] {
    if tx_hashes.is_empty() {
        return [0u8; 32];
    }

    if tx_hashes.len() == 1 {
        return tx_hashes[0];
    }

    use sha2::{Digest, Sha256};

    let mut current_level: Vec<[u8; 32]> = tx_hashes.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in current_level.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(&chunk[0]);

            // If odd number, duplicate the last hash
            if chunk.len() == 2 {
                hasher.update(&chunk[1]);
            } else {
                hasher.update(&chunk[0]);
            }

            let hash: [u8; 32] = hasher.finalize().into();
            next_level.push(hash);
        }

        current_level = next_level;
    }

    current_level[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn hash(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    #[test]
    fn test_merkle_root_empty() {
        let root = merkle_root(&[]);
        assert_eq!(root, [0u8; 32]);
    }

    #[test]
    fn test_merkle_root_single() {
        let h1 = hash(b"tx1");
        let root = merkle_root(&[h1]);
        assert_eq!(root, h1);
    }

    #[test]
    fn test_merkle_root_two() {
        let h1 = hash(b"tx1");
        let h2 = hash(b"tx2");

        let root = merkle_root(&[h1, h2]);

        // Manual calculation: SHA256(h1 || h2)
        let mut expected_hasher = Sha256::new();
        expected_hasher.update(&h1);
        expected_hasher.update(&h2);
        let expected: [u8; 32] = expected_hasher.finalize().into();

        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_three() {
        let h1 = hash(b"tx1");
        let h2 = hash(b"tx2");
        let h3 = hash(b"tx3");

        let root = merkle_root(&[h1, h2, h3]);

        // Level 1: hash(h1||h2), hash(h3||h3)
        // Level 0: hash(hash(h1||h2) || hash(h3||h3))
        assert_ne!(root, [0u8; 32]); // Just verify it computed something
    }
}
