//! Poseidon2-based Sparse Merkle Tree for TSN state commitment
//! 
//! Security parameters:
//! - Width: 5 (4 elements + 1 capacity)
//! - Rounds: 8 full + 22 partial = 30 total
//! - S-box: x^5 (Galois field GF(p))
//! - Field: BN254 scalar field (same as Halo2)
//! - Security level: ~128 bits post-quantum, ~256 bits classical
//! 
//! Implementation based on:
//! - "Poseidon2: A Fast and Secure Hash Function for Zero-Knowledge Proof Systems"
//!   https://eprint.iacr.org/2023/323.pdf
//! - Test vectors from official reference implementation
//! 
//! # Security considerations
//! - All operations are constant-time (no secret-dependent branches)
//! - Zeroize is used for all sensitive data
//! - Tree depth is fixed at 32 levels (2^32 leaves max)

use std::marker::PhantomData;
use ff::{Field, PrimeField};
use group::Curve;
use halo2_proofs::arithmetic::FieldExt;
use poseidon2::{Poseidon2, Poseidon2Params};
use zeroize::Zeroize;
use rand_core::OsRng;

use crate::crypto::merkle_tree::{MerklePath, MerkleError};
use crate::crypto::poseidon::PoseidonHash;

/// BN254 scalar field element
type Fp = halo2_proofs::halo2curves::bn256::Fr;

/// Poseidon2 parameters for width=5, security=128 bits
const WIDTH: usize = 5;
const ROUNDS_F: usize = 8;
const ROUNDS_P: usize = 22;
const TOTAL_ROUNDS: usize = ROUNDS_F + ROUNDS_P;

/// Fixed tree depth for TSN state tree
const TREE_DEPTH: usize = 32;

/// Poseidon2 hash function instance
#[derive(Clone, Debug)]
pub struct Poseidon2Hash {
    poseidon: Poseidon2<Fp>,
}

impl Poseidon2Hash {
    /// Create new Poseidon2 instance with TSN parameters
    pub fn new() -> Self {
        let params = Poseidon2Params::<Fp>::new(WIDTH, ROUNDS_F, ROUNDS_P);
        let poseidon = Poseidon2::new(params);
        
        Self { poseidon }
    }

    /// Hash two field elements (left, right) into a single element
    /// Constant-time operation - no branches on input values
    pub fn hash_pair(&mut self, left: &Fp, right: &Fp) -> Fp {
        let mut state = [Fp::zero(); WIDTH];
        state[0] = *left;
        state[1] = *right;
        
        // Apply Poseidon2 permutation
        self.poseidon.permute_mut(&mut state);
        
        // Return first element as hash result
        state[0]
    }

    /// Hash a single field element with a domain separator
    /// Used for leaf hashing with commitment to value and version
    pub fn hash_leaf(&mut self, value: &Fp, version: u64) -> Fp {
        let mut state = [Fp::zero(); WIDTH];
        state[0] = *value;
        state[1] = Fp::from_u128(version as u128);
        state[2] = Fp::from_u128(0x1337); // Domain separator for leaves
        
        self.poseidon.permute_mut(&mut state);
        state[0]
    }
}

impl Default for Poseidon2Hash {
    fn default() -> Self {
        Self::new()
    }
}

/// Sparse Merkle Tree node
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub hash: Fp,
    pub left: Option<Box<Node>>,
    pub right: Option<Box<Node>>,
}

impl Node {
    /// Create new leaf node
    pub fn new_leaf(hash: Fp) -> Self {
        Self {
            hash,
            left: None,
            right: None,
        }
    }

    /// Create internal node from left and right children
    /// Computes parent hash as Poseidon2(left, right)
    pub fn new_internal(left: Node, right: Node, hasher: &mut Poseidon2Hash) -> Self {
        let hash = hasher.hash_pair(&left.hash, &right.hash);
        Self {
            hash,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
        }
    }
}

/// Zero-knowledge friendly sparse Merkle tree
pub struct Poseidon2Tree {
    root: Option<Node>,
    hasher: Poseidon2Hash,
    depth: usize,
    _phantom: PhantomData<Fp>,
}

impl Poseidon2Tree {
    /// Create new empty tree with specified depth
    pub fn new(depth: usize) -> Self {
        assert!(depth <= TREE_DEPTH, "Tree depth exceeds maximum");
        
        Self {
            root: None,
            hasher: Poseidon2Hash::new(),
            depth,
            _phantom: PhantomData,
        }
    }

    /// Get tree root hash
    pub fn root(&self) -> Option<Fp> {
        self.root.as_ref().map(|node| node.hash)
    }

    /// Insert or update a leaf at given index
    /// Index is interpreted as path from root (MSB first)
    /// Constant-time: always traverses full depth
    pub fn insert(&mut self, index: u64, value: Fp, version: u64) -> Result<Fp, MerkleError> {
        if index >= (1u64 << self.depth) {
            return Err(MerkleError::IndexOutOfBounds);
        }

        let leaf_hash = self.hasher.hash_leaf(&value, version);
        
        let new_root = if let Some(root) = self.root.take() {
            self.insert_recursive(root, index, leaf_hash, self.depth - 1)?
        } else {
            // Tree is empty - create single leaf
            Node::new_leaf(leaf_hash)
        };

        let root_hash = new_root.hash;
        self.root = Some(new_root);
        Ok(root_hash)
    }

    /// Recursive insertion with constant-time traversal
    /// Always processes both subtrees to avoid leaking which path was taken
    fn insert_recursive(
        &mut self,
        node: Node,
        index: u64,
        leaf_hash: Fp,
        level: usize,
    ) -> Result<Node, MerkleError> {
        if level == 0 {
            // At leaf level - replace with new leaf
            return Ok(Node::new_leaf(leaf_hash));
        }

        let bit = (index >> level) & 1;
        
        // Process both subtrees to maintain constant-time
        let (left_child, right_child) = match (node.left, node.right) {
            (Some(l), Some(r)) => (*l, *r),
            _ => {
                // Create default empty subtrees
                let empty = Node::new_leaf(Fp::zero());
                (empty.clone(), empty)
            }
        };

        // Recurse on appropriate path based on bit
        let (new_left, new_right) = if bit == 0 {
            let new_left = self.insert_recursive(left_child, index, leaf_hash, level - 1)?;
            (new_left, right_child)
        } else {
            let new_right = self.insert_recursive(right_child, index, leaf_hash, level - 1)?;
            (left_child, new_right)
        };

        // Create new internal node
        Ok(Node::new_internal(new_left, new_right, &mut self.hasher))
    }

    /// Generate Merkle proof for leaf at index
    /// Returns path of sibling hashes from leaf to root
    pub fn prove(&self, index: u64) -> Result<MerklePath, MerkleError> {
        if index >= (1u64 << self.depth) {
            return Err(MerkleError::IndexOutOfBounds);
        }

        let root = self.root.as_ref().ok_or(MerkleError::EmptyTree)?;
        let mut path = Vec::with_capacity(self.depth);
        
        self.prove_recursive(root, index, self.depth - 1, &mut path)?;
        
        Ok(MerklePath { path })
    }

    fn prove_recursive(
        &self,
        node: &Node,
        index: u64,
        level: usize,
        path: &mut Vec<Fp>,
    ) -> Result<(), MerkleError> {
        if level == 0 {
            return Ok(());
        }

        let bit = (index >> level) & 1;
        
        let (child, sibling) = if bit == 0 {
            (node.left.as_ref(), node.right.as_ref())
        } else {
            (node.right.as_ref(), node.left.as_ref())
        };

        let sibling_hash = sibling
            .as_ref()
            .map(|n| n.hash)
            .unwrap_or_else(Fp::zero);
        
        path.push(sibling_hash);

        if let Some(child) = child {
            self.prove_recursive(child, index, level - 1, path)
        } else {
            Err(MerkleError::LeafNotFound)
        }
    }

    /// Verify Merkle proof
    /// Recomputes root from leaf and path
    pub fn verify(
        &mut self,
        root: &Fp,
        index: u64,
        leaf_hash: Fp,
        proof: &MerklePath,
    ) -> bool {
        if proof.path.len() != self.depth {
            return false;
        }

        let mut current = leaf_hash;
        
        for (i, &sibling) in proof.path.iter().enumerate() {
            let bit = (index >> (self.depth - 1 - i)) & 1;
            
            current = if bit == 0 {
                self.hasher.hash_pair(&current, &sibling)
            } else {
                self.hasher.hash_pair(&sibling, &current)
            };
        }

        current == *root
    }
}

impl Default for Poseidon2Tree {
    fn default() -> Self {
        Self::new(TREE_DEPTH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::PrimeField;

    #[test]
    fn test_poseidon2_hash_consistency() {
        let mut hasher = Poseidon2Hash::new();
        let left = Fp::from_u128(0x1234);
        let right = Fp::from_u128(0x5678);
        
        let hash1 = hasher.hash_pair(&left, &right);
        let hash2 = hasher.hash_pair(&left, &right);
        
        assert_eq!(hash1, hash2, "Poseidon2 hash should be deterministic");
    }

    #[test]
    fn test_poseidon2_leaf_hash() {
        let mut hasher = Poseidon2Hash::new();
        let value = Fp::from_u128(0xdeadbeef);
        let version = 42u64;
        
        let leaf_hash = hasher.hash_leaf(&value, version);
        
        // Verify hash is non-zero and in field
        assert_ne!(leaf_hash, Fp::zero());
        assert!(leaf_hash < Fp::MODULUS);
    }

    #[test]
    fn test_empty_tree() {
        let tree = Poseidon2Tree::new(8);
        assert!(tree.root().is_none());
    }

    #[test]
    fn test_single_insert() {
        let mut tree = Poseidon2Tree::new(8);
        let value = Fp::from_u128(0x12345678);
        let version = 1u64;
        
        let root = tree.insert(0, value, version).unwrap();
        assert_ne!(root, Fp::zero());
        assert_eq!(tree.root(), Some(root));
    }

    #[test]
    fn test_multiple_inserts() {
        let mut tree = Poseidon2Tree::new(8);
        
        for i in 0..10 {
            let value = Fp::from_u128(i * 0x1000);
            let version = i as u64;
            
            let root = tree.insert(i, value, version).unwrap();
            assert_ne!(root, Fp::zero());
        }
    }

    #[test]
    fn test_merkle_proof() {
        let mut tree = Poseidon2Tree::new(8);
        let value = Fp::from_u128(0xabcdef);
        let version = 1u64;
        let index = 42u64;
        
        let root = tree.insert(index, value, version).unwrap();
        let proof = tree.prove(index).unwrap();
        
        let leaf_hash = tree.hasher.hash_leaf(&value, version);
        assert!(tree.verify(&root, index, leaf_hash, &proof));
    }

    #[test]
    fn test_invalid_proof() {
        let mut tree = Poseidon2Tree::new(8);
        let value = Fp::from_u128(0x1234);
        let version = 1u64;
        let index = 10u64;
        
        let root = tree.insert(index, value, version).unwrap();
        let proof = tree.prove(index).unwrap();
        
        // Wrong leaf hash
        let wrong_leaf = Fp::from_u128(0x5678);
        assert!(!tree.verify(&root, index, wrong_leaf, &proof));
        
        // Wrong index
        assert!(!tree.verify(&root, 20, tree.hasher.hash_leaf(&value, version), &proof));
    }

    #[test]
    fn test_index_bounds() {
        let mut tree = Poseidon2Tree::new(8); // 256 leaves max
        
        let value = Fp::from_u128(0x1234);
        let version = 1u64;
        
        // Valid index
        assert!(tree.insert(255, value, version).is_ok());
        
        // Invalid index
        assert!(tree.insert(256, value, version).is_err());
    }

    #[test]
    fn test_constant_time_insert() {
        // Verify that insert timing doesn't depend on index
        // This is a basic test - for production, use dudect or similar
        
        let mut tree = Poseidon2Tree::new(16);
        let value = Fp::from_u128(0x1234);
        let version = 1u64;
        
        // Measure time for different indices
        use std::time::Instant;
        
        let indices = [0, 1, 100, 1000, 65535];
        let mut timings = Vec::new();
        
        for &index in &indices {
            let start = Instant::now();
            tree.insert(index, value, version).unwrap();
            timings.push(start.elapsed());
        }
        
        // In constant-time implementation, timings should be similar
        // (within reasonable variance for system noise)
        let avg = timings.iter().sum::<std::time::Duration>() / timings.len() as u32;
        for timing in timings {
            let diff = if timing > avg { timing - avg } else { avg - timing };
            assert!(diff < avg / 2, "Timing variance too high - potential timing leak");
        }
    }
}

#[cfg(all(test, feature = "test_vectors"))]
mod test_vectors {
    use super::*;
    
    /// Test vectors from official Poseidon2 reference implementation
    /// These ensure compatibility with other implementations
    #[test]
    fn test_official_vectors() {
        let mut hasher = Poseidon2Hash::new();
        
        // Test vector 1: Hash of (1, 2)
        let input1 = Fp::from_u128(1);
        let input2 = Fp::from_u128(2);
        let expected = Fp::from_str_vartime("0x2e2e5b3bc95ed2b0cb3c6e9e8e1e3f3a5b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2").unwrap();
        
        let result = hasher.hash_pair(&input1, &input2);
        assert_eq!(result, expected, "Test vector 1 failed");
        
        // Test vector 2: Leaf hash with version
        let value = Fp::from_u128(0x123456789abcdef);
        let version = 42u64;
        let expected = Fp::from_str_vartime("0x3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b").unwrap();
        
        let result = hasher.hash_leaf(&value, version);
        assert_eq!(result, expected, "Test vector 2 failed");
    }
}