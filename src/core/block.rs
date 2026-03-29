//! Block structure for the shielded blockchain.
//!
//! Blocks contain shielded transactions (private) and coinbase (reward).
//! The header includes commitment and nullifier roots for light client verification.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::transaction::{CoinbaseTransaction, ShieldedTransaction, ShieldedTransactionV2};
use crate::consensus::poseidon_pow;
use crate::contract::{ContractDeployTransaction, ContractCallTransaction, ContractReceipt};

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

    /// Hash of the full chain state after applying this block.
    /// Used for snapshot validation: a peer providing a snapshot must prove
    /// that the state matches the state_root committed in the block header.
    /// Blake2s(commitment_count || nullifier_count || commitment_root || nullifier_root || balance_root)
    #[serde(with = "hex_array", default = "default_hash")]
    pub state_root: [u8; BLOCK_HASH_SIZE],

    /// Block creation timestamp (Unix timestamp).
    pub timestamp: u64,

    /// Mining difficulty target (numeric: hash_prefix < u64::MAX / difficulty).
    pub difficulty: u64,

    /// Nonce for proof-of-work (512 bits).
    /// First 56 bytes are random per-thread, last 8 bytes are a counter.
    #[serde(with = "hex_nonce")]
    pub nonce: [u8; 64],
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
            &self.nonce,
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
            &self.nonce,
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

    /// Check if the header hash meets the numeric difficulty target.
    /// The first 8 bytes of the hash (big-endian u64) must be < u64::MAX / difficulty.
    pub fn meets_difficulty(&self) -> bool {
        let hash = self.hash();
        poseidon_pow::hash_meets_difficulty(&hash, self.difficulty)
    }

    /// Check if the header hash meets the difficulty target, height-aware.
    pub fn meets_difficulty_for_height(&self, height: u64) -> bool {
        let hash = self.hash_for_height(height);
        poseidon_pow::hash_meets_difficulty(&hash, self.difficulty)
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
    pub fn hash(&self, timestamp: u64, difficulty: u64, nonce: &[u8; 64]) -> [u8; BLOCK_HASH_SIZE] {
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

    /// Check numeric difficulty using the stored prefix.
    pub fn meets_difficulty(&self, timestamp: u64, difficulty: u64, nonce: &[u8; 64]) -> bool {
        poseidon_pow::hash_meets_difficulty(&self.hash(timestamp, difficulty, nonce), difficulty)
    }
}

/// A complete shielded block with header, transactions, and coinbase.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedBlock {
    pub header: BlockHeader,
    pub transactions: Vec<ShieldedTransaction>,
    pub transactions_v2: Vec<ShieldedTransactionV2>,
    /// Smart contract deployment transactions.
    #[serde(default)]
    pub contract_deploys: Vec<ContractDeployTransaction>,
    /// Smart contract call transactions.
    #[serde(default)]
    pub contract_calls: Vec<ContractCallTransaction>,
    /// Contract execution receipts (one per contract tx, in order: deploys then calls).
    #[serde(default)]
    pub contract_receipts: Vec<ContractReceipt>,
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
            state_root: [0u8; BLOCK_HASH_SIZE], // Will be set by set_state_root()
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            difficulty,
            nonce: [0u8; 64],
        };

        Self {
            header,
            transactions,
            transactions_v2: Vec::new(),
            contract_deploys: Vec::new(),
            contract_calls: Vec::new(),
            contract_receipts: Vec::new(),
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
            state_root: [0u8; BLOCK_HASH_SIZE], // Will be set by set_state_root()
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            difficulty,
            nonce: [0u8; 64],
        };

        Self {
            header,
            transactions,
            transactions_v2,
            contract_deploys: Vec::new(),
            contract_calls: Vec::new(),
            contract_receipts: Vec::new(),
            coinbase,
        }
    }

    /// Set the state root for this block (called after state is computed).
    pub fn set_state_root(&mut self, state_root: [u8; BLOCK_HASH_SIZE]) {
        self.header.state_root = state_root;
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
            state_root: [0u8; BLOCK_HASH_SIZE],      // Genesis has no state_root
            timestamp: 0, // The beginning of time
            difficulty,
            nonce: [0u8; 64],
        };

        Self {
            header,
            transactions: Vec::new(),
            transactions_v2: Vec::new(),
            contract_deploys: Vec::new(),
            contract_calls: Vec::new(),
            contract_receipts: Vec::new(),
            coinbase,
        }
    }

    /// Verify the block's structure and proof-of-work.
    pub fn verify(&self) -> Result<(), BlockError> {
        // Verify merkle root
        let mut tx_hashes: Vec<[u8; 32]> = self.transactions.iter().map(|tx| tx.hash()).collect();
        tx_hashes.extend(self.transactions_v2.iter().map(|tx| tx.hash()));
        tx_hashes.extend(self.contract_deploys.iter().map(|tx| tx.hash()));
        tx_hashes.extend(self.contract_calls.iter().map(|tx| tx.hash()));
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
        // M2 audit fix: use saturating_add to prevent overflow
        let v1_fees: u64 = self.transactions.iter().map(|tx| tx.fee).sum();
        let v2_fees: u64 = self.transactions_v2.iter().map(|tx| tx.fee).sum();
        let deploy_fees: u64 = self.contract_deploys.iter().map(|tx| tx.fee).sum();
        let call_fees: u64 = self.contract_calls.iter().map(|tx| tx.fee).sum();
        v1_fees.saturating_add(v2_fees).saturating_add(deploy_fees).saturating_add(call_fees)
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
            + self.contract_deploys.len() + self.contract_calls.len()
    }

    /// Get the block height from coinbase.
    pub fn height(&self) -> u64 {
        self.coinbase.height
    }

    /// Get the block size in bytes (approximate).
    pub fn size(&self) -> usize {
        let header_size = 4 + 32*4 + 8 + 8 + 64; // version + hashes + timestamp + difficulty + nonce
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
    /// Returns the number of attempts made.
    pub fn mine(&mut self) -> u64 {
        let prefix = BlockHeaderHashPrefix::new(&self.header);
        let mut attempts = 0u64;

        // Use zeros for the random part, increment counter in last 8 bytes
        let mut nonce = [0u8; 64];

        loop {
            if prefix.meets_difficulty(self.header.timestamp, self.header.difficulty, &nonce) {
                self.header.nonce = nonce;
                return attempts;
            }
            attempts += 1;
            // Increment the counter in the last 8 bytes
            let counter = u64::from_le_bytes(nonce[56..64].try_into().unwrap());
            nonce[56..64].copy_from_slice(&counter.wrapping_add(1).to_le_bytes());
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

/// Default state_root for backward compatibility with pre-v0.7.1 blocks.
fn default_hash() -> [u8; BLOCK_HASH_SIZE] {
    [0u8; BLOCK_HASH_SIZE]
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

/// Helper module for hex serialization of the 64-byte nonce.
mod hex_nonce {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "Expected 64 bytes for nonce, got {}",
                bytes.len()
            )));
        }
        let mut array = [0u8; 64];
        array.copy_from_slice(&bytes);
        Ok(array)
    }
}

/// Get the nonce as a hex string (for display/API purposes).
pub fn nonce_to_hex(nonce: &[u8; 64]) -> String {
    hex::encode(nonce)
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
            state_root: [0u8; 32],
            timestamp: 1234567890,
            difficulty: 10000,
            nonce: [42u8; 64],
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
    fn test_numeric_difficulty() {
        // Zero difficulty is invalid (M1 audit fix) — always rejects
        let mut hash = [0xFF; 32];
        assert!(!poseidon_pow::hash_meets_difficulty(&hash, 0));

        // Very low hash should pass high difficulty
        hash = [0u8; 32];
        assert!(poseidon_pow::hash_meets_difficulty(&hash, 1000000));

        // Very high hash should fail even low difficulty
        hash = [0xFF; 32];
        assert!(!poseidon_pow::hash_meets_difficulty(&hash, 2));
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

        let genesis = ShieldedBlock::genesis(10000, coinbase);
        assert!(genesis.is_genesis());
        assert_eq!(genesis.height(), 0);
        assert_eq!(genesis.transaction_count(), 0);
        assert_eq!(genesis.reward(), 5000000000);
        assert_eq!(genesis.header.nonce, [0u8; 64]);
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

        let block = ShieldedBlock::genesis(1, coinbase); // Min difficulty for testing

        // Should verify with correct merkle root and minimum difficulty
        assert!(block.verify().is_ok());
    }

    #[test]
    fn test_nonce_serde() {
        let header = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            commitment_root: [2u8; 32],
            nullifier_root: [3u8; 32],
            state_root: [0u8; 32],
            timestamp: 1234567890,
            difficulty: 10000,
            nonce: [0xAB; 64],
        };

        let serialized = serde_json::to_string(&header).unwrap();
        let deserialized: BlockHeader = serde_json::from_str(&serialized).unwrap();
        assert_eq!(header.nonce, deserialized.nonce);
    }

    #[test]
    fn test_nonce_hex_display() {
        let nonce = [0u8; 64];
        let hex_str = nonce_to_hex(&nonce);
        assert_eq!(hex_str.len(), 128); // 64 bytes = 128 hex chars
    }
}
