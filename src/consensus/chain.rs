//! Fork choice rule and chain selection for the shielded blockchain.
//!
//! This module implements the "longest chain" rule with cumulative work comparison.
//! When multiple valid chains exist (forks), the chain with the most cumulative work
//! is selected as the canonical chain.
//!
//! ## Invariants
//! 
//! 1. **Chain Weight**: The cumulative work of a chain is the sum of difficulties of all blocks.
//! 2. **Fork Detection**: A fork occurs when two blocks have the same parent but different hashes.
//! 3. **Reorganization**: When a competing chain has more cumulative work, we reorganize to it.
//! 4. **Orphan Handling**: Blocks without known parents are stored as orphans until their chain arrives.

use std::collections::HashMap;
use crate::core::{ShieldedBlock, BLOCK_HASH_SIZE};
use crate::config;
use thiserror::Error;

/// Errors that can occur during fork choice and chain selection.
#[derive(Debug, Error)]
pub enum ChainError {
    #[error("Block not found: {0}")]
    BlockNotFound(String),
    
    #[error("Invalid chain: missing parent block")]
    MissingParent,
    
    #[error("Chain reorganization failed: {0}")]
    ReorganizationFailed(String),
    
    #[error("Circular chain detected")]
    CircularChain,
    
    #[error("Invalid genesis block")]
    InvalidGenesis,

    #[error("Checkpoint violation: cannot reorganize below finalized height {0}")]
    CheckpointViolation(u64),
}

/// Represents a chain of blocks with metadata for fork choice.
#[derive(Debug, Clone)]
pub struct ChainInfo {
    /// The tip block hash of this chain.
    pub tip_hash: [u8; BLOCK_HASH_SIZE],
    
    /// The height of the tip block.
    pub height: u64,
    
    /// The cumulative work (sum of difficulties) from genesis to tip.
    pub cumulative_work: u128,
    
    /// The difficulty of the tip block.
    pub tip_difficulty: u64,
    
    /// Timestamp of the tip block.
    pub tip_timestamp: u64,
}

impl ChainInfo {
    /// Create a new ChainInfo for a single block (genesis case).
    pub fn new_genesis(block: &ShieldedBlock) -> Self {
        Self {
            tip_hash: block.hash(),
            height: block.height(),
            cumulative_work: block.header.difficulty as u128,
            tip_difficulty: block.header.difficulty,
            tip_timestamp: block.header.timestamp,
        }
    }
    
    /// Extend this chain with a new block.
    pub fn extend_with(&self, block: &ShieldedBlock) -> Self {
        Self {
            tip_hash: block.hash(),
            height: block.height(),
            cumulative_work: self.cumulative_work + block.header.difficulty as u128,
            tip_difficulty: block.header.difficulty,
            tip_timestamp: block.header.timestamp,
        }
    }
}

/// Fork choice engine that implements the "longest chain" rule.
/// 
/// This engine maintains information about all known chains and selects
/// the one with the most cumulative work as the canonical chain.
pub struct ForkChoice {
    /// All known blocks indexed by hash.
    blocks: HashMap<[u8; BLOCK_HASH_SIZE], ShieldedBlock>,
    
    /// Chain information for all known chain tips.
    chains: HashMap<[u8; BLOCK_HASH_SIZE], ChainInfo>,
    
    /// The currently selected canonical chain tip.
    canonical_tip: Option<[u8; BLOCK_HASH_SIZE]>,
    
    /// Orphan blocks (blocks whose parent we don't have yet).
    orphans: HashMap<[u8; BLOCK_HASH_SIZE], ShieldedBlock>,
    
    /// Genesis block hash for validation.
    genesis_hash: [u8; BLOCK_HASH_SIZE],

    /// Height of the last finalized checkpoint.
    /// Reorgs below this height are rejected when checkpoint finality is enabled.
    last_checkpoint_height: u64,

    /// Hash of the block at the last checkpoint height.
    last_checkpoint_hash: Option<[u8; BLOCK_HASH_SIZE]>,
}

impl ForkChoice {
    /// Create a new fork choice engine with a genesis block.
    pub fn new(genesis: ShieldedBlock) -> Self {
        let genesis_hash = genesis.hash();
        let genesis_info = ChainInfo::new_genesis(&genesis);
        
        let mut blocks = HashMap::new();
        let mut chains = HashMap::new();
        
        blocks.insert(genesis_hash, genesis);
        chains.insert(genesis_hash, genesis_info);
        
        Self {
            blocks,
            chains,
            canonical_tip: Some(genesis_hash),
            orphans: HashMap::new(),
            genesis_hash,
            last_checkpoint_height: 0,
            last_checkpoint_hash: None,
        }
    }
    
    /// Get the current canonical chain tip.
    pub fn canonical_tip(&self) -> Option<&ChainInfo> {
        self.canonical_tip
            .and_then(|tip| self.chains.get(&tip))
    }
    
    /// Get information about a specific chain.
    pub fn get_chain_info(&self, tip_hash: &[u8; BLOCK_HASH_SIZE]) -> Option<&ChainInfo> {
        self.chains.get(tip_hash)
    }
    
    /// Get a block by hash.
    pub fn get_block(&self, hash: &[u8; BLOCK_HASH_SIZE]) -> Option<&ShieldedBlock> {
        self.blocks.get(hash)
    }
    
    /// Get all orphan blocks.
    pub fn orphans(&self) -> &HashMap<[u8; BLOCK_HASH_SIZE], ShieldedBlock> {
        &self.orphans
    }
    
    /// Add a new block and potentially reorganize the chain.
    /// 
    /// Returns `Ok(true)` if the block was added and became the new canonical tip,
    /// `Ok(false)` if the block was added but didn't change the canonical chain,
    /// or an error if the block couldn't be processed.
    pub fn add_block(&mut self, block: ShieldedBlock) -> Result<bool, ChainError> {
        let block_hash = block.hash();
        let parent_hash = block.header.prev_hash;
        
        // Check if we already have this block
        if self.blocks.contains_key(&block_hash) {
            return Ok(false);
        }
        
        // Check if this is an orphan (parent not known)
        if !self.blocks.contains_key(&parent_hash) && parent_hash != [0u8; 32] {
            tracing::debug!(
                "Adding orphan block {} (parent: {})",
                hex::encode(block_hash),
                hex::encode(parent_hash)
            );
            self.orphans.insert(block_hash, block);
            return Ok(false);
        }
        
        // Validate that this block extends a known chain
        let parent_chain = if parent_hash == [0u8; 32] {
            // This should be genesis, but we already have genesis
            return Err(ChainError::InvalidGenesis);
        } else {
            self.find_chain_containing_block(&parent_hash)
                .ok_or(ChainError::MissingParent)?
        };
        
        // Add the block to our block store
        self.blocks.insert(block_hash, block.clone());
        
        // Create new chain info by extending the parent chain
        let new_chain_info = parent_chain.extend_with(&block);
        
        // Remove the old chain tip (it's no longer a tip)
        self.chains.remove(&parent_chain.tip_hash);
        
        // Add the new chain tip
        self.chains.insert(block_hash, new_chain_info.clone());
        
        // Check if this becomes the new canonical chain
        let should_reorganize = self.should_reorganize_to(&new_chain_info)?;

        if should_reorganize {
            tracing::info!(
                "Reorganizing to new chain tip {} (height: {}, work: {})",
                hex::encode(block_hash),
                new_chain_info.height,
                new_chain_info.cumulative_work
            );
            self.canonical_tip = Some(block_hash);

            // Update checkpoint if this block's height is a multiple of CHECKPOINT_INTERVAL
            if config::CHECKPOINT_ENABLED
                && new_chain_info.height > 0
                && new_chain_info.height % config::CHECKPOINT_INTERVAL == 0
                && new_chain_info.height > self.last_checkpoint_height
            {
                self.last_checkpoint_height = new_chain_info.height;
                self.last_checkpoint_hash = Some(block_hash);
                tracing::info!(
                    "Checkpoint finalized at height {} (hash: {})",
                    new_chain_info.height,
                    hex::encode(block_hash)
                );
            }

            // Try to connect any orphans that might now have their parent
            self.try_connect_orphans()?;

            Ok(true)
        } else {
            tracing::debug!(
                "Added block {} to side chain (height: {}, work: {})",
                hex::encode(block_hash),
                new_chain_info.height,
                new_chain_info.cumulative_work
            );
            
            // Still try to connect orphans
            self.try_connect_orphans()?;
            
            Ok(false)
        }
    }
    
    /// Find the chain that contains a specific block.
    fn find_chain_containing_block(&self, block_hash: &[u8; BLOCK_HASH_SIZE]) -> Option<ChainInfo> {
        // If this block is a current chain tip, return its info
        if let Some(chain_info) = self.chains.get(block_hash) {
            return Some(chain_info.clone());
        }
        
        // Otherwise, we need to reconstruct the chain info by walking back from any tip
        // that contains this block in its history
        for chain_info in self.chains.values() {
            if self.chain_contains_block(chain_info, block_hash) {
                // Reconstruct chain info up to the requested block
                return self.reconstruct_chain_info_to_block(block_hash);
            }
        }
        
        None
    }
    
    /// Check if a chain contains a specific block in its history.
    fn chain_contains_block(&self, chain_info: &ChainInfo, target_hash: &[u8; BLOCK_HASH_SIZE]) -> bool {
        let mut current_hash = chain_info.tip_hash;
        
        // Walk back through the chain
        while let Some(block) = self.blocks.get(&current_hash) {
            if current_hash == *target_hash {
                return true;
            }
            
            if block.header.prev_hash == [0u8; 32] {
                // Reached genesis
                break;
            }
            
            current_hash = block.header.prev_hash;
        }
        
        false
    }
    
    /// Reconstruct chain info up to a specific block.
    fn reconstruct_chain_info_to_block(&self, target_hash: &[u8; BLOCK_HASH_SIZE]) -> Option<ChainInfo> {
        let target_block = self.blocks.get(target_hash)?;
        
        // Build the chain from genesis to target
        let mut chain_blocks = Vec::new();
        let mut current_hash = *target_hash;
        
        // Walk back to genesis
        while let Some(block) = self.blocks.get(&current_hash) {
            chain_blocks.push(block);
            
            if block.header.prev_hash == [0u8; 32] {
                break;
            }
            
            current_hash = block.header.prev_hash;
        }
        
        // Reverse to get genesis-to-target order
        chain_blocks.reverse();
        
        // Calculate cumulative work
        let mut cumulative_work = 0u128;
        for block in &chain_blocks {
            cumulative_work += block.header.difficulty as u128;
        }
        
        Some(ChainInfo {
            tip_hash: *target_hash,
            height: target_block.height(),
            cumulative_work,
            tip_difficulty: target_block.header.difficulty,
            tip_timestamp: target_block.header.timestamp,
        })
    }
    
    /// Determine if we should reorganize to a new chain.
    ///
    /// Returns `Err(CheckpointViolation)` if the reorg would go below the
    /// last finalized checkpoint height.
    fn should_reorganize_to(&self, new_chain: &ChainInfo) -> Result<bool, ChainError> {
        match self.canonical_tip() {
            None => Ok(true), // No current canonical chain
            Some(current) => {
                if new_chain.cumulative_work <= current.cumulative_work {
                    return Ok(false);
                }

                // If checkpoint finality is enabled, check that the reorg
                // doesn't go below the last checkpoint height.
                if config::CHECKPOINT_ENABLED && self.last_checkpoint_height > 0 {
                    // Find the fork point: walk back both chains to find common ancestor.
                    // If the new chain's height is below the checkpoint, reject immediately.
                    if new_chain.height < self.last_checkpoint_height {
                        tracing::warn!(
                            "Rejecting reorg: new chain height {} is below checkpoint at {}",
                            new_chain.height,
                            self.last_checkpoint_height
                        );
                        return Err(ChainError::CheckpointViolation(self.last_checkpoint_height));
                    }

                    // Check that the new chain includes the checkpoint block
                    if let Some(ref checkpoint_hash) = self.last_checkpoint_hash {
                        if !self.new_chain_contains_checkpoint(&new_chain.tip_hash, checkpoint_hash) {
                            tracing::warn!(
                                "Rejecting reorg: new chain does not include checkpoint block at height {}",
                                self.last_checkpoint_height
                            );
                            return Err(ChainError::CheckpointViolation(self.last_checkpoint_height));
                        }
                    }
                }

                Ok(true)
            }
        }
    }

    /// Check if a chain (identified by its tip hash) contains the checkpoint block
    /// in its ancestry.
    fn new_chain_contains_checkpoint(
        &self,
        tip_hash: &[u8; BLOCK_HASH_SIZE],
        checkpoint_hash: &[u8; BLOCK_HASH_SIZE],
    ) -> bool {
        let mut current_hash = *tip_hash;

        while let Some(block) = self.blocks.get(&current_hash) {
            if current_hash == *checkpoint_hash {
                return true;
            }
            if block.header.prev_hash == [0u8; BLOCK_HASH_SIZE] {
                break;
            }
            current_hash = block.header.prev_hash;
        }

        false
    }
    
    /// Try to connect orphan blocks that might now have their parent available.
    fn try_connect_orphans(&mut self) -> Result<(), ChainError> {
        let mut connected_any = true;
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 100; // Prevent infinite loops
        
        while connected_any && iterations < MAX_ITERATIONS {
            connected_any = false;
            iterations += 1;
            
            let orphan_hashes: Vec<_> = self.orphans.keys().cloned().collect();
            
            for orphan_hash in orphan_hashes {
                if let Some(orphan) = self.orphans.get(&orphan_hash).cloned() {
                    // Check if the parent is now available
                    if self.blocks.contains_key(&orphan.header.prev_hash) {
                        // Remove from orphans and try to add normally
                        self.orphans.remove(&orphan_hash);
                        
                        match self.add_block(orphan) {
                            Ok(_) => {
                                connected_any = true;
                                tracing::debug!(
                                    "Connected orphan block {}",
                                    hex::encode(orphan_hash)
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to connect orphan block {}: {}",
                                    hex::encode(orphan_hash),
                                    e
                                );
                            }
                        }
                    }
                }
            }
        }
        
        if iterations >= MAX_ITERATIONS {
            tracing::warn!("Orphan connection reached maximum iterations, possible circular dependency");
        }
        
        Ok(())
    }
    
    /// Get the canonical chain as a sequence of block hashes from genesis to tip.
    pub fn get_canonical_chain(&self) -> Result<Vec<[u8; BLOCK_HASH_SIZE]>, ChainError> {
        let tip_hash = self.canonical_tip
            .ok_or_else(|| ChainError::BlockNotFound("No canonical tip".to_string()))?;
        
        let mut chain = Vec::new();
        let mut current_hash = tip_hash;
        
        // Walk back to genesis
        while let Some(block) = self.blocks.get(&current_hash) {
            chain.push(current_hash);
            
            if block.header.prev_hash == [0u8; 32] {
                break;
            }
            
            current_hash = block.header.prev_hash;
        }
        
        // Reverse to get genesis-to-tip order
        chain.reverse();
        
        Ok(chain)
    }
    
    /// Get all known chain tips (for debugging and analysis).
    pub fn get_all_chain_tips(&self) -> Vec<&ChainInfo> {
        self.chains.values().collect()
    }
    
    /// Calculate the total number of blocks across all chains.
    pub fn total_blocks(&self) -> usize {
        self.blocks.len()
    }
    
    /// Calculate the number of orphan blocks.
    pub fn orphan_count(&self) -> usize {
        self.orphans.len()
    }
    
    /// Get the last finalized checkpoint height.
    pub fn last_checkpoint_height(&self) -> u64 {
        self.last_checkpoint_height
    }

    /// Get the last finalized checkpoint hash.
    pub fn last_checkpoint_hash(&self) -> Option<[u8; BLOCK_HASH_SIZE]> {
        self.last_checkpoint_hash
    }

    /// Get statistics about the current fork choice state.
    pub fn get_stats(&self) -> ForkChoiceStats {
        let canonical = self.canonical_tip();

        ForkChoiceStats {
            total_blocks: self.total_blocks(),
            orphan_count: self.orphan_count(),
            chain_count: self.chains.len(),
            canonical_height: canonical.map(|c| c.height).unwrap_or(0),
            canonical_work: canonical.map(|c| c.cumulative_work).unwrap_or(0),
            max_side_chain_height: self.chains.values()
                .filter(|c| Some(c.tip_hash) != self.canonical_tip)
                .map(|c| c.height)
                .max()
                .unwrap_or(0),
            last_checkpoint_height: self.last_checkpoint_height,
        }
    }
}

/// Statistics about the current fork choice state.
#[derive(Debug, Clone)]
pub struct ForkChoiceStats {
    /// Total number of blocks across all chains.
    pub total_blocks: usize,
    
    /// Number of orphan blocks.
    pub orphan_count: usize,
    
    /// Number of known chain tips.
    pub chain_count: usize,
    
    /// Height of the canonical chain.
    pub canonical_height: u64,
    
    /// Cumulative work of the canonical chain.
    pub canonical_work: u128,
    
    /// Maximum height among side chains.
    pub max_side_chain_height: u64,

    /// Height of the last finalized checkpoint.
    pub last_checkpoint_height: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{BlockHeader, CoinbaseTransaction};
    
    /// Create a test genesis block.
    fn create_genesis() -> ShieldedBlock {
        let header = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            commitment_root: [2u8; 32],
            nullifier_root: [3u8; 32],
            timestamp: 1000000,
            difficulty: 100,
            nonce: 0,
        };
        
        let coinbase = CoinbaseTransaction {
            outputs: vec![],
            reward: 5000000000, // 50 TSN
        };
        
        ShieldedBlock {
            header,
            transactions: vec![],
            transactions_v2: vec![],
            coinbase,
        }
    }
    
    /// Create a test block that extends a parent.
    fn create_block(parent: &ShieldedBlock, difficulty: u64, nonce: u64) -> ShieldedBlock {
        let header = BlockHeader {
            version: 1,
            prev_hash: parent.hash(),
            merkle_root: [1u8; 32],
            commitment_root: [2u8; 32],
            nullifier_root: [3u8; 32],
            timestamp: parent.header.timestamp + 600, // 10 minutes later
            difficulty,
            nonce,
        };
        
        let coinbase = CoinbaseTransaction {
            outputs: vec![],
            reward: 5000000000, // 50 TSN
        };
        
        ShieldedBlock {
            header,
            transactions: vec![],
            transactions_v2: vec![],
            coinbase,
        }
    }
    
    #[test]
    fn test_fork_choice_initialization() {
        let genesis = create_genesis();
        let genesis_hash = genesis.hash();
        let fork_choice = ForkChoice::new(genesis);
        
        // Should have genesis as canonical tip
        let canonical = fork_choice.canonical_tip().unwrap();
        assert_eq!(canonical.tip_hash, genesis_hash);
        assert_eq!(canonical.height, 0);
        assert_eq!(canonical.cumulative_work, 100);
        
        // Should have one block and one chain
        assert_eq!(fork_choice.total_blocks(), 1);
        assert_eq!(fork_choice.get_all_chain_tips().len(), 1);
        assert_eq!(fork_choice.orphan_count(), 0);
    }
    
    #[test]
    fn test_linear_chain_extension() {
        let genesis = create_genesis();
        let mut fork_choice = ForkChoice::new(genesis.clone());
        
        // Add block 1
        let block1 = create_block(&genesis, 150, 1);
        let block1_hash = block1.hash();
        let reorganized = fork_choice.add_block(block1).unwrap();
        assert!(reorganized); // Should become new canonical tip
        
        let canonical = fork_choice.canonical_tip().unwrap();
        assert_eq!(canonical.tip_hash, block1_hash);
        assert_eq!(canonical.height, 1);
        assert_eq!(canonical.cumulative_work, 250); // 100 + 150
        
        // Add block 2
        let block1_ref = fork_choice.get_block(&block1_hash).unwrap();
        let block2 = create_block(block1_ref, 200, 2);
        let block2_hash = block2.hash();
        let reorganized = fork_choice.add_block(block2).unwrap();
        assert!(reorganized);
        
        let canonical = fork_choice.canonical_tip().unwrap();
        assert_eq!(canonical.tip_hash, block2_hash);
        assert_eq!(canonical.height, 2);
        assert_eq!(canonical.cumulative_work, 450); // 100 + 150 + 200
        
        // Should have 3 blocks total, 1 chain tip
        assert_eq!(fork_choice.total_blocks(), 3);
        assert_eq!(fork_choice.get_all_chain_tips().len(), 1);
    }
    
    #[test]
    fn test_fork_detection_and_selection() {
        let genesis = create_genesis();
        let mut fork_choice = ForkChoice::new(genesis.clone());
        
        // Build main chain: genesis -> block1 -> block2
        let block1 = create_block(&genesis, 100, 1);
        let block1_hash = block1.hash();
        fork_choice.add_block(block1).unwrap();
        
        let block1_ref = fork_choice.get_block(&block1_hash).unwrap();
        let block2 = create_block(block1_ref, 100, 2);
        let block2_hash = block2.hash();
        fork_choice.add_block(block2).unwrap();
        
        // Current canonical: genesis(100) -> block1(100) -> block2(100) = 300 work
        assert_eq!(fork_choice.canonical_tip().unwrap().cumulative_work, 300);
        
        // Create a fork from block1 with higher difficulty
        let block1_alt = create_block(block1_ref, 150, 3); // Different nonce = different hash
        let block1_alt_hash = block1_alt.hash();
        let reorganized = fork_choice.add_block(block1_alt).unwrap();
        assert!(!reorganized); // Should not reorganize yet (250 < 300)
        
        // Should have 2 chain tips now
        assert_eq!(fork_choice.get_all_chain_tips().len(), 2);
        
        // Extend the fork to make it heavier
        let block1_alt_ref = fork_choice.get_block(&block1_alt_hash).unwrap();
        let block2_alt = create_block(block1_alt_ref, 200, 4);
        let block2_alt_hash = block2_alt.hash();
        let reorganized = fork_choice.add_block(block2_alt).unwrap();
        assert!(reorganized); // Should reorganize (350 > 300)
        
        // New canonical chain should be the heavier fork
        let canonical = fork_choice.canonical_tip().unwrap();
        assert_eq!(canonical.tip_hash, block2_alt_hash);
        assert_eq!(canonical.cumulative_work, 350); // 100 + 150 + 200
        
        // Should still have 2 chain tips (old main chain is now side chain)
        assert_eq!(fork_choice.get_all_chain_tips().len(), 2);
        assert_eq!(fork_choice.total_blocks(), 5); // genesis + 2 main + 2 fork
    }
    
    #[test]
    fn test_orphan_handling() {
        let genesis = create_genesis();
        let mut fork_choice = ForkChoice::new(genesis.clone());
        
        // Create a chain: genesis -> block1 -> block2
        let block1 = create_block(&genesis, 100, 1);
        let block2 = create_block(&block1, 100, 2);
        let block3 = create_block(&block2, 100, 3);
        
        // Add block3 first (orphan - parent not known)
        let reorganized = fork_choice.add_block(block3.clone()).unwrap();
        assert!(!reorganized);
        assert_eq!(fork_choice.orphan_count(), 1);
        assert_eq!(fork_choice.total_blocks(), 1); // Only genesis
        
        // Add block2 (still orphan - parent not known)
        let reorganized = fork_choice.add_block(block2.clone()).unwrap();
        assert!(!reorganized);
        assert_eq!(fork_choice.orphan_count(), 2);
        assert_eq!(fork_choice.total_blocks(), 1);
        
        // Add block1 - should connect all orphans
        let reorganized = fork_choice.add_block(block1).unwrap();
        assert!(reorganized);
        assert_eq!(fork_choice.orphan_count(), 0);
        assert_eq!(fork_choice.total_blocks(), 4); // genesis + 3 blocks
        
        // Should have extended to block3 as canonical tip
        let canonical = fork_choice.canonical_tip().unwrap();
        assert_eq!(canonical.tip_hash, block3.hash());
        assert_eq!(canonical.height, 3);
        assert_eq!(canonical.cumulative_work, 400); // 100 + 100 + 100 + 100
    }
    
    #[test]
    fn test_duplicate_block_handling() {
        let genesis = create_genesis();
        let mut fork_choice = ForkChoice::new(genesis.clone());
        
        let block1 = create_block(&genesis, 100, 1);
        
        // Add block1 first time
        let reorganized = fork_choice.add_block(block1.clone()).unwrap();
        assert!(reorganized);
        assert_eq!(fork_choice.total_blocks(), 2);
        
        // Add same block again - should be ignored
        let reorganized = fork_choice.add_block(block1).unwrap();
        assert!(!reorganized);
        assert_eq!(fork_choice.total_blocks(), 2); // No change
    }
    
    #[test]
    fn test_canonical_chain_retrieval() {
        let genesis = create_genesis();
        let genesis_hash = genesis.hash();
        let mut fork_choice = ForkChoice::new(genesis.clone());
        
        // Build a chain
        let block1 = create_block(&genesis, 100, 1);
        let block1_hash = block1.hash();
        fork_choice.add_block(block1).unwrap();
        
        let block1_ref = fork_choice.get_block(&block1_hash).unwrap();
        let block2 = create_block(block1_ref, 100, 2);
        let block2_hash = block2.hash();
        fork_choice.add_block(block2).unwrap();
        
        // Get canonical chain
        let chain = fork_choice.get_canonical_chain().unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0], genesis_hash);
        assert_eq!(chain[1], block1_hash);
        assert_eq!(chain[2], block2_hash);
    }
    
    #[test]
    fn test_fork_choice_stats() {
        let genesis = create_genesis();
        let mut fork_choice = ForkChoice::new(genesis.clone());
        
        // Build main chain
        let block1 = create_block(&genesis, 100, 1);
        let block1_hash = block1.hash();
        fork_choice.add_block(block1).unwrap();
        
        let block1_ref = fork_choice.get_block(&block1_hash).unwrap();
        let block2 = create_block(block1_ref, 100, 2);
        fork_choice.add_block(block2).unwrap();
        
        // Create side chain
        let block1_alt = create_block(block1_ref, 50, 3);
        fork_choice.add_block(block1_alt).unwrap();
        
        let stats = fork_choice.get_stats();
        assert_eq!(stats.total_blocks, 4);
        assert_eq!(stats.orphan_count, 0);
        assert_eq!(stats.chain_count, 2);
        assert_eq!(stats.canonical_height, 2);
        assert_eq!(stats.canonical_work, 300); // 100 + 100 + 100
        assert_eq!(stats.max_side_chain_height, 1);
    }
    
    #[test]
    fn test_equal_work_chains() {
        let genesis = create_genesis();
        let mut fork_choice = ForkChoice::new(genesis.clone());
        
        // Build main chain
        let block1 = create_block(&genesis, 100, 1);
        let block1_hash = block1.hash();
        fork_choice.add_block(block1).unwrap();
        
        // Create competing chain with equal work
        let block1_alt = create_block(&genesis, 100, 2); // Same difficulty, different nonce
        let reorganized = fork_choice.add_block(block1_alt).unwrap();
        
        // Should not reorganize when work is equal (first seen wins)
        assert!(!reorganized);
        
        let canonical = fork_choice.canonical_tip().unwrap();
        assert_eq!(canonical.tip_hash, block1_hash);
    }
    
    #[test]
    fn test_chain_info_extension() {
        let genesis = create_genesis();
        let genesis_info = ChainInfo::new_genesis(&genesis);
        
        assert_eq!(genesis_info.height, 0);
        assert_eq!(genesis_info.cumulative_work, 100);
        assert_eq!(genesis_info.tip_difficulty, 100);
        
        let block1 = create_block(&genesis, 150, 1);
        let extended_info = genesis_info.extend_with(&block1);
        
        assert_eq!(extended_info.height, 1);
        assert_eq!(extended_info.cumulative_work, 250);
        assert_eq!(extended_info.tip_difficulty, 150);
        assert_eq!(extended_info.tip_hash, block1.hash());
    }
}