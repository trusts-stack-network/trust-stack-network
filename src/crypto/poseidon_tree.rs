//! Poseidon2-based state tree for ZK-friendly state commitments.
//! Compatible with Halo2 proving system.

use anyhow::{ensure, Result};
use plonky2::field::goldilocks_fields::GoldilocksField as F;
use plonky2::hash::poseidon2::Poseidon2Hash;
use plonky2::plonk::config::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Depth of the tree (2^16 = 65536 leaves)
pub const TREE_DEPTH: usize = 16;
/// Width of Poseidon2 permutation
pub const WIDTH: usize = 4;
/// Domain separator for leaf hashing
pub const LEAF_DOMAIN: u64 = 0x01;
/// Domain separator for node hashing
pub const NODE_DOMAIN: u64 = 0x02;

/// Goldilocks field element type alias
pub type Field = F;

/// Sparse representation of the Poseidon2 tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoseidonTree {
    /// Current number of leaves
    pub(crate) leaf_count: u64,
    /// Cache of nodes by (depth, index)
    nodes: HashMap<(usize, u64), [Field; WIDTH]>,
    /// Current root hash
    root: [Field; WIDTH],
}

/// Inclusion proof for a leaf
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Leaf index
    pub index: u64,
    /// Sibling hashes from leaf to root
    pub siblings: Vec<[Field; WIDTH]>,
    /// Root hash
    pub root: [Field; WIDTH],
}

impl PoseidonTree {
    /// Create a new empty tree
    pub fn new() -> Self {
        let mut tree = Self {
            leaf_count: 0,
            nodes: HashMap::new(),
            root: [Field::ZERO; WIDTH],
        };
        tree.compute_root();
        tree
    }

    /// Insert a new leaf value
    pub fn insert(&mut self, value: [Field; WIDTH]) -> Result<u64> {
        ensure!(
            self.leaf_count < (1 << TREE_DEPTH),
            "Tree is full"
        );

        let index = self.leaf_count;
        self.leaf_count += 1;

        // Hash the leaf with domain separator
        let leaf_hash = self.hash_leaf(value);
        self.update_node(TREE_DEPTH, index, leaf_hash);

        // Update the root
        self.compute_root();

        Ok(index)
    }

    /// Get the current root hash
    pub fn root(&self) -> [Field; WIDTH] {
        self.root
    }

    /// Generate an inclusion proof for a leaf
    pub fn prove(&self, index: u64) -> Result<InclusionProof> {
        ensure!(index < self.leaf_count, "Index out of range");

        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        let mut current_index = index;
        let mut current_depth = TREE_DEPTH;

        while current_depth > 0 {
            let sibling_index = current_index ^ 1;
            let sibling_hash = self.get_node(current_depth, sibling_index);
            siblings.push(sibling_hash);

            current_index >>= 1;
            current_depth -= 1;
        }

        Ok(InclusionProof {
            index,
            siblings,
            root: self.root,
        })
    }

    /// Verify an inclusion proof
    pub fn verify_proof(
        &self,
        index: u64,
        leaf_value: [Field; WIDTH],
        proof: &InclusionProof,
    ) -> Result<bool> {
        ensure!(proof.index == index, "Index mismatch");
        ensure!(proof.siblings.len() == TREE_DEPTH, "Invalid proof length");

        let mut current_hash = self.hash_leaf(leaf_value);
        let mut current_index = index;

        for sibling in &proof.siblings {
            let (left, right) = if current_index & 1 == 0 {
                (current_hash, *sibling)
            } else {
                (*sibling, current_hash)
            };

            current_hash = self.hash_node(left, right);
            current_index >>= 1;
        }

        Ok(current_hash == proof.root)
    }

    /// Hash a leaf with domain separator
    fn hash_leaf(&self, value: [Field; WIDTH]) -> [Field; WIDTH] {
        let mut inputs = value;
        inputs[0] += Field::from_canonical_u64(LEAF_DOMAIN);
        Poseidon2Hash::hash_no_pad(&inputs)
    }

    /// Hash two nodes with domain separator
    fn hash_node(&self, left: [Field; WIDTH], right: [Field; WIDTH]) -> [Field; WIDTH] {
        let mut inputs = [Field::ZERO; WIDTH];
        inputs[0] = Field::from_canonical_u64(NODE_DOMAIN);
        inputs[1..WIDTH].copy_from_slice(&left[0..WIDTH-1]);
        
        // Combine with right node
        for i in 0..WIDTH-1 {
            inputs[i+1] += right[i];
        }
        
        Poseidon2Hash::hash_no_pad(&inputs)
    }

    /// Update a node in the tree
    fn update_node(&mut self, depth: usize, index: u64, hash: [Field; WIDTH]) {
        self.nodes.insert((depth, index), hash);
    }

    /// Get a node hash (returns zero if not present)
    fn get_node(&self, depth: usize, index: u64) -> [Field; WIDTH] {
        self.nodes.get(&(depth, index)).copied().unwrap_or([Field::ZERO; WIDTH])
    }

    /// Compute the root hash from the current state
    fn compute_root(&mut self) {
        let mut current_depth = TREE_DEPTH;
        let mut current_level_nodes = self.leaf_count;

        while current_depth > 0 {
            let mut next_level_nodes = 0;
            
            for i in 0..current_level_nodes {
                if i & 1 == 0 {
                    let left = self.get_node(current_depth, i);
                    let right = if i + 1 < current_level_nodes {
                        self.get_node(current_depth, i + 1)
                    } else {
                        [Field::ZERO; WIDTH]
                    };
                    
                    let parent_hash = self.hash_node(left, right);
                    self.update_node(current_depth - 1, i >> 1, parent_hash);
                }
            }
            
            next_level_nodes = (current_level_nodes + 1) >> 1;
            current_level_nodes = next_level_nodes;
            current_depth -= 1;
        }

        self.root = self.get_node(0, 0);
    }
}

impl Default for PoseidonTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    fn random_field_array() -> [Field; WIDTH] {
        let mut rng = rand::thread_rng();
        let mut arr = [Field::ZERO; WIDTH];
        for i in 0..WIDTH {
            arr[i] = Field::from_canonical_u64(rng.gen());
        }
        arr
    }

    #[test]
    fn test_empty_tree_root() {
        let tree = PoseidonTree::new();
        let root = tree.root();
        
        // Empty tree should have a deterministic root
        assert_eq!(root, [Field::ZERO; WIDTH]);
    }

    #[test]
    fn test_single_insert() {
        let mut tree = PoseidonTree::new();
        let value = random_field_array();
        
        let index = tree.insert(value).unwrap();
        assert_eq!(index, 0);
        assert_eq!(tree.leaf_count, 1);
        
        // Root should change after insert
        let root_after = tree.root();
        assert_ne!(root_after, [Field::ZERO; WIDTH]);
    }

    #[test]
    fn test_multiple_inserts() {
        let mut tree = PoseidonTree::new();
        let mut last_root = tree.root();
        
        for i in 0..10 {
            let value = random_field_array();
            let index = tree.insert(value).unwrap();
            assert_eq!(index, i as u64);
            
            let new_root = tree.root();
            assert_ne!(new_root, last_root, "Root should change after insert {}", i);
            last_root = new_root;
        }
        
        assert_eq!(tree.leaf_count, 10);
    }

    #[test]
    fn test_inclusion_proof() {
        let mut tree = PoseidonTree::new();
        let value = random_field_array();
        
        let index = tree.insert(value).unwrap();
        let proof = tree.prove(index).unwrap();
        
        // Verify the proof
        assert!(tree.verify_proof(index, value, &proof).unwrap());
    }

    #[test]
    fn test_invalid_proof() {
        let mut tree = PoseidonTree::new();
        let value1 = random_field_array();
        let value2 = random_field_array();
        
        let index = tree.insert(value1).unwrap();
        let proof = tree.prove(index).unwrap();
        
        // Try to verify with wrong value
        assert!(!tree.verify_proof(index, value2, &proof).unwrap());
    }

    #[test]
    fn test_tree_full() {
        let mut tree = PoseidonTree::new();
        
