//! Block structure for the shielded blockchain.
//!
//! Blocks contain shielded transactions (private) and coinbase (reward).
//! The header includes commitment and nullifier roots for light client verification.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::transaction::{CoinbaseTransaction, ShieldedTransaction, ShieldedTransactionV2};
use crate::consensus::poseidon_pow;

pub const BLOCK_HASH_SIZE: usize = 32;

/// Block header containing metadata, proof-of-work, and privacy roots.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block version (for future upgrades).
    pub version: u32,

    /// Hash of the previous block.
    #[serde(with = "hex_array")]
    pub prev_hash: [u8; BLOCK_HASH_SIZE],

    /// Merkle root of transaction hashes.
    #[serde(with = "hex_array")]
    pub merkle_root: [u8; BLOCK_HASH_SIZE],

    /// Commitment tree root after applying this block.
    /// Allows light clients to verify note existence.
    #[serde(with = "hex_array")]
    pub commitment_root: [u8; BLOCK_HASH_SIZE],

    /// Nullifier set root after applying this block (optional).
    /// For light client double-spend verification.
    #[serde(with = "hex_array")]
    pub nullifier_root: [u8; BLOCK_HASH_SIZE],

    /// Block creation timestamp (Unix timestamp).
    pub timestamp: u64,

    /// Mining difficulty target.
    pub difficulty: u64,

    /// Nonce for proof-of-work.
    pub nonce: u64,
}

impl BlockHeader {
    /// Compute the hash of this block header using Poseidon (ZK-friendly PoW).
    /// NOTE: This uses Poseidon v1. For height-aware hashing (hard fork support),
    /// use `hash_for_height()` instead.
    pub fn hash(&self) -> [u8; BLOCK_HASH_SIZE] {
        poseidon_pow::poseidon_hash_header_parts(
            self.version,
            &self.prev_hash,
            &self.merkle_root,
            &self.commitment_root,
            &self.nullifier_root,
            self.timestamp,
            self.difficulty,
            self.nonce,
        )
    }

    /// Compute the hash using the appropriate algorithm for the given block height.
    /// Routes to legacy BN254, Poseidon v1, or Poseidon2 v2 based on activation heights.
    pub fn hash_for_height(&self, height: u64) -> [u8; BLOCK_HASH_SIZE] {
        poseidon_pow::poseidon_hash_header_parts_for_height(
            self.version,
            &self.prev_hash,
            &self.merkle_root,
            &self.commitment_root,
            &self.nullifier_root,
            self.timestamp,
            self.difficulty,
            self.nonce,
            height,
        )
    }

    /// Get the header hash as a hex string.
    pub fn hash_hex(&self) -> String {
        hex::encode(self.hash())
    }

    /// Get the header hash as a hex string, height-aware.
    pub fn hash_hex_for_height(&self, height: u64) -> String {
        hex::encode(self.hash_for_height(height))
    }

    /// Check if the header hash meets the difficulty target.
    /// The hash must have at least `difficulty` leading zero bits.
    pub fn meets_difficulty(&self) -> bool {
        let hash = self.hash();
        count_leading_zeros(&hash) >= self.difficulty as usize
    }

    /// Check if the header hash meets the difficulty target, height-aware.
    pub fn meets_difficulty_for_height(&self, height: u64) -> bool {
        let hash = self.hash_for_height(height);
        count_leading_zeros(&hash) >= self.difficulty as usize
    }
}

/// Precomputed hash prefix for block headers to speed up mining.
/// Uses Poseidon (ZK-friendly) hash function.
#[derive(Clone)]
pub struct BlockHeaderHashPrefix {
    version: u32,
    prev_hash: [u8; 32],
    merkle_root: [u8; 32],
    commitment_root: [u8; 32],
    nullifier_root: [u8; 32],
    height: u64,
}

impl BlockHeaderHashPrefix {
    /// Build a prefix from the header + block height (height lives in coinbase).
    pub fn new_with_height(header: &BlockHeader, height: u64) -> Self {
        Self {
            version: header.version,
            prev_hash: header.prev_hash,
            merkle_root: header.merkle_root,
            commitment_root: header.commitment_root,
            nullifier_root: header.nullifier_root,
            height,
        }
    }

    /// Build a prefix from header fields (uses height 0 as default for new blocks).
    /// For mining new blocks, prefer `new_with_height`.
    pub fn new(header: &BlockHeader) -> Self {
        Self::new_with_height(header, u64::MAX) // u64::MAX > any activation height = always Goldilocks
    }

    /// Hash a header using the stored prefix + variable fields.
    /// Uses height-aware hashing: legacy BN254 for old blocks, Goldilocks for new.
    pub fn hash(&self, timestamp: u64, difficulty: u64, nonce: u64) -> [u8; BLOCK_HASH_SIZE] {
        poseidon_pow::poseidon_hash_header_parts_for_height(
            self.version,
            &self.prev_hash,
            &self.merkle_root,
            &self.commitment_root,
            &self.nullifier_root,
            timestamp,
            difficulty,
            nonce,
            self.height,
        )
    }

    /// Check difficulty using the stored prefix.
    pub fn meets_difficulty(&self, timestamp: u64, difficulty: u64, nonce: u64) -> bool {
        count_leading_zeros(&self.hash(timestamp, difficulty, nonce)) >= difficulty as usize
    }
}

/// A complete shielded block with header, transactions, and coinbase.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedBlock {
    pub header: BlockHeader,
    pub transactions: Vec<ShieldedTransaction>,
    pub transactions_v2: Vec<ShieldedTransactionV2>,
    pub coinbase: CoinbaseTransaction,
}

impl ShieldedBlock {
    /// Create a new shielded block.
    pub fn new(
        prev_hash: [u8; BLOCK_HASH_SIZE],
        transactions: Vec<ShieldedTransaction>,
        coinbase: CoinbaseTransaction,
        commitment_root: [u8; BLOCK_HASH_SIZE],
        nullifier_root: [u8; BLOCK_HASH_SIZE],
        difficulty: u64,
    ) -> Self {
        // Compute merkle root of all transaction hashes + coinbase
        let mut tx_hashes: Vec<[u8; 32]> = transactions.iter().map(|tx| tx.hash()).collect();
        tx_hashes.push(coinbase.hash());
        let merkle_root = compute_merkle_root(&tx_hashes);

        let header = BlockHeader {
            version: 3,
            prev_hash,
            merkle_root,
            commitment_root,
            nullifier_root,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            difficulty,
            nonce: 0,
        };

        Self {
            header,
            transactions,
            transactions_v2: Vec::new(),
            coinbase,
        }
    }

    /// Create a new shielded block with V2 transactions.
    pub fn new_with_v2(
        prev_hash: [u8; BLOCK_HASH_SIZE],
        transactions: Vec<ShieldedTransaction>,
        transactions_v2: Vec<ShieldedTransactionV2>,
        coinbase: CoinbaseTransaction,
        commitment_root: [u8; BLOCK_HASH_SIZE],
        nullifier_root: [u8; BLOCK_HASH_SIZE],
        difficulty: u64,
    ) -> Self {
        // Compute merkle root of all transaction hashes + coinbase
        let mut tx_hashes: Vec<[u8; 32]> = transactions.iter().map(|tx| tx.hash()).collect();
        tx_hashes.extend(transactions_v2.iter().map(|tx| tx.hash()));
        tx_hashes.push(coinbase.hash());
        let merkle_root = compute_merkle_root(&tx_hashes);

        let header = BlockHeader {
            version: 3,
            prev_hash,
            merkle_root,
            commitment_root,
            nullifier_root,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            difficulty,
            nonce: 0,
        };

        Self {
            header,
            transactions,
            transactions_v2,
            coinbase,
        }
    }

    /// Get the signal bits from the version field (bits 29-31)
    pub fn signal_bits(&self) -> u8 {
        ((self.header.version >> 29) & 0x07) as u8
    }

    /// Get the base version number without signal bits
    pub fn base_version(&self) -> u32 {
        self.header.version & 0x1FFFFFFF
    }

    /// Get the block hash (height-aware for hard fork compatibility).
    pub fn hash(&self) -> [u8; BLOCK_HASH_SIZE] {
        self.header.hash_for_height(self.height())
    }

    /// Get the block hash as a hex string (height-aware).
    pub fn hash_hex(&self) -> String {
        self.header.hash_hex_for_height(self.height())
    }

    /// Create the genesis block (first block in the chain).
    pub fn genesis(difficulty: u64, coinbase: CoinbaseTransaction) -> Self {
        let commitment_root = crate::crypto::merkle_tree::CommitmentTree::empty_root();

        let header = BlockHeader {
            version: 3,
            prev_hash: [0u8; BLOCK_HASH_SIZE],
            merkle_root: coinbase.hash(),
            commitment_root,
            nullifier_root: [0u8; BLOCK_HASH_SIZE], // Empty nullifier set
            timestamp: 0, // The beginning of time
            difficulty,
            nonce: 0,
        };

        Self {
            header,
            transactions: Vec::new(),
            transactions_v2: Vec::new(),
            coinbase,
        }
    }

    /// Verify the block's structure and proof-of-work.
    pub fn verify(&self) -> Result<(), BlockError> {
        // Verify merkle root
        let mut tx_hashes: Vec<[u8; 32]> = self.transactions.iter().map(|tx| tx.hash()).collect();
        tx_hashes.extend(self.transactions_v2.iter().map(|tx| tx.hash()));
        tx_hashes.push(self.coinbase.hash());
        let computed_root = compute_merkle_root(&tx_hashes);
        if computed_root != self.header.merkle_root {
            return Err(BlockError::InvalidMerkleRoot);
        }

        // Verify proof-of-work (height-aware for hard fork compatibility)
        if !self.header.meets_difficulty_for_height(self.height()) {
            return Err(BlockError::InsufficientProofOfWork);
        }

        Ok(())
    }

    /// Get the total fees from all transactions in this block.
    pub fn total_fees(&self) -> u64 {
        let v1_fees: u64 = self.transactions.iter().map(|tx| tx.fee).sum();
        let v2_fees: u64 = self.transactions_v2.iter().map(|tx| tx.fee).sum();
        v1_fees + v2_fees
    }

    /// Get all nullifiers introduced by this block.
    pub fn nullifiers(&self) -> Vec<crate::crypto::nullifier::Nullifier> {
        let mut nullifiers = Vec::new();
        
        // V1 transactions - clone the referenced nullifiers
        for tx in &self.transactions {
            for nullifier_ref in tx.nullifiers() {
                nullifiers.push(nullifier_ref.clone());
            }
        }
        
        // V2 transactions - convert from bytes to Nullifier
        for tx in &self.transactions_v2 {
            for nullifier in tx.nullifiers() {
                nullifiers.push(crate::crypto::nullifier::Nullifier(nullifier));
            }
        }
        
        nullifiers
    }

    /// Get all note commitments created by this block.
    pub fn note_commitments(&self) -> Vec<crate::crypto::commitment::NoteCommitment> {
        let mut commitments = Vec::new();
        
        // V1 transactions - clone the referenced commitments
        for tx in &self.transactions {
            for commitment_ref in tx.note_commitments() {
                commitments.push(commitment_ref.clone());
            }
        }
        
        // V2 transactions - convert from bytes to NoteCommitment
        for tx in &self.transactions_v2 {
            for commitment in tx.note_commitments() {
                commitments.push(crate::crypto::commitment::NoteCommitment(commitment));
            }
        }
        
        commitments.push(self.coinbase.note_commitment.clone());
        commitments
    }

    /// Get the number of transactions (excluding coinbase).
    pub fn transaction_count(&self) -> usize {
        self.transactions.len() + self.transactions_v2.len()
    }

    /// Get the block height from coinbase.
    pub fn height(&self) -> u64 {
        self.coinbase.height
    }

    /// Get the block size in bytes (approximate).
    pub fn size(&self) -> usize {
        let header_size = 8 * 8; // 8 fields * 8 bytes each (rough estimate)
        let tx_size: usize = self.transactions.iter().map(|tx| tx.size()).sum();
        let coinbase_size = 32 + 32 + 8 + 8; // rough estimate
        header_size + tx_size + coinbase_size
    }

    /// Check if this is the genesis block.
    pub fn is_genesis(&self) -> bool {
        self.header.prev_hash == [0u8; BLOCK_HASH_SIZE]
    }

    /// Get the block reward (coinbase amount).
    pub fn reward(&self) -> u64 {
        self.coinbase.reward
    }

    /// Mine this block by finding a valid nonce.
    /// Returns the nonce that satisfies the difficulty target.
    pub fn mine(&mut self) -> u64 {
        let prefix = BlockHeaderHashPrefix::new(&self.header);
        let mut nonce = 0u64;

        loop {
            if prefix.meets_difficulty(self.header.timestamp, self.header.difficulty, nonce) {
                self.header.nonce = nonce;
                return nonce;
            }
            nonce += 1;
        }
    }

    /// Set the block timestamp to current time.
    pub fn update_timestamp(&mut self) {
        self.header.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

/// Block validation errors.
#[derive(Debug, thiserror::Error)]
pub enum BlockError {
    #[error("Invalid merkle root")]
    InvalidMerkleRoot,

    #[error("Insufficient proof-of-work")]
    InsufficientProofOfWork,

    #[error("Invalid timestamp")]
    InvalidTimestamp,

    #[error("Invalid difficulty")]
    InvalidDifficulty,

    #[error("Invalid coinbase")]
    InvalidCoinbase,

    #[error("Block too large")]
    BlockTooLarge,

    #[error("Invalid transaction")]
    InvalidTransaction,
}

/// Compute the merkle root of a list of hashes.
/// Uses a simple binary tree approach.
fn compute_merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }

    if hashes.len() == 1 {
        return hashes[0];
    }

    let mut level = hashes.to_vec();

    while level.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in level.chunks(2) {
            let hash = if chunk.len() == 2 {
                // Hash pair
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);
                hasher.update(&chunk[1]);
                hasher.finalize().into()
            } else {
                // Odd number - hash with itself
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);
                hasher.update(&chunk[0]);
                hasher.finalize().into()
            };
            next_level.push(hash);
        }

        level = next_level;
    }

    level[0]
}

/// Count the number of leading zero bits in a hash.
fn count_leading_zeros(hash: &[u8; 32]) -> usize {
    let mut count = 0;
    for &byte in hash {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros() as usize;
            break;
        }
    }
    count
}

/// Helper module for hex serialization of byte arrays.
mod hex_array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        if bytes.len() != N {
            return Err(serde::de::Error::custom(format!("Expected {} bytes", N)));
        }
        let mut array = [0u8; N];
        array.copy_from_slice(&bytes);
        Ok(array)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{commitment::NoteCommitment, note::EncryptedNote};

    #[test]
    fn test_block_header_hash() {
        let header = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            commitment_root: [2u8; 32],
            nullifier_root: [3u8; 32],
            timestamp: 1234567890,
            difficulty: 20,
            nonce: 42,
        };

        let hash = header.hash();
        assert_eq!(hash.len(), 32);
        
        // Hash should be deterministic
        assert_eq!(hash, header.hash());
    }

    #[test]
    fn test_merkle_root_computation() {
        // Empty list
        let empty_root = compute_merkle_root(&[]);
        assert_eq!(empty_root, [0u8; 32]);

        // Single hash
        let single = [[1u8; 32]];
        let single_root = compute_merkle_root(&single);
        assert_eq!(single_root, [1u8; 32]);

        // Two hashes
        let pair = [[1u8; 32], [2u8; 32]];
        let pair_root = compute_merkle_root(&pair);
        assert_ne!(pair_root, [0u8; 32]);
        assert_ne!(pair_root, [1u8; 32]);
        assert_ne!(pair_root, [2u8; 32]);
    }

    #[test]
    fn test_leading_zeros() {
        assert_eq!(count_leading_zeros(&[0u8; 32]), 256);
        assert_eq!(count_leading_zeros(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 0);
        assert_eq!(count_leading_zeros(&[0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 7);
    }

    #[test]
    fn test_genesis_block() {
        let coinbase = CoinbaseTransaction::new(
            NoteCommitment::from_bytes([1u8; 32]),
            [2u8; 32],
            EncryptedNote { ciphertext: vec![0u8; 48], ephemeral_pk: vec![0u8; 32] },
            5000000000, // 50 TSN
            0,
        );

        let genesis = ShieldedBlock::genesis(20, coinbase);
        assert!(genesis.is_genesis());
        assert_eq!(genesis.height(), 0);
        assert_eq!(genesis.transaction_count(), 0);
        assert_eq!(genesis.reward(), 5000000000);
    }

    #[test]
    fn test_block_verification() {
        let coinbase = CoinbaseTransaction::new(
            NoteCommitment::from_bytes([1u8; 32]),
            [2u8; 32],
            EncryptedNote { ciphertext: vec![0u8; 48], ephemeral_pk: vec![0u8; 32] },
            5000000000,
            0,
        );

        let mut block = ShieldedBlock::genesis(0, coinbase); // Zero difficulty for testing
        
        // Should verify with correct merkle root and zero difficulty
        assert!(block.verify().is_ok());

        // Break the merkle root
        block.header.merkle_root = [0u8; 32];
        assert!(matches!(block.verify(), Err(BlockError::InvalidMerkleRoot)));
    }
}