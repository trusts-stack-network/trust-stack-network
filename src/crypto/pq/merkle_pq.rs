//! Post-quantum Merkle tree using Poseidon hash over Goldilocks field.
//!
//! This provides the same functionality as the V1 Merkle tree but uses
//! quantum-resistant hash functions.
//!
//! ## Hash Format
//!
//! To match Plonky2's circuit, hashes are 4 Goldilocks field elements (256 bits).
//! This is stored as 32 bytes in serialized form.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use super::commitment_pq::NoteCommitmentPQ;
use super::poseidon_pq::{
    poseidon_pq_hash, bytes_to_hash_out, hash_out_to_bytes,
    DOMAIN_MERKLE_EMPTY_PQ, DOMAIN_MERKLE_NODE_PQ, GoldilocksField, HashOut,
};

/// Depth of the Merkle tree (same as V1 for compatibility).
pub const TREE_DEPTH_PQ: usize = 32;

/// Number of recent roots to keep for anchor validation.
/// Larger value handles fast block production during proof generation.
const RECENT_ROOTS_COUNT: usize = 1000;

/// Hash type for tree nodes (4 field elements = 256 bits = 32 bytes).
pub type TreeHashPQ = [u8; 32];

/// Internal hash representation (4 field elements).
type InternalHash = HashOut;

/// Compute the empty tree hash at a given depth.
/// This is cached for efficiency.
fn empty_hash_at_depth(depth: usize) -> InternalHash {
    if depth == 0 {
        // Leaf level: hash of empty commitment
        poseidon_pq_hash(&[DOMAIN_MERKLE_EMPTY_PQ])
    } else {
        // Internal node: hash of two empty children
        let child = empty_hash_at_depth(depth - 1);
        // Build input: [domain, left[4], right[4]] = 9 elements
        let mut inputs = vec![DOMAIN_MERKLE_NODE_PQ];
        inputs.extend_from_slice(&child);
        inputs.extend_from_slice(&child);
        poseidon_pq_hash(&inputs)
    }
}

/// Compute the root of an empty tree.
pub fn empty_root_pq() -> TreeHashPQ {
    hash_out_to_bytes(&empty_hash_at_depth(TREE_DEPTH_PQ))
}

/// Compute a node hash from two children (each 4 field elements).
fn hash_node(left: &InternalHash, right: &InternalHash) -> InternalHash {
    let mut inputs = vec![DOMAIN_MERKLE_NODE_PQ];
    inputs.extend_from_slice(left);
    inputs.extend_from_slice(right);
    poseidon_pq_hash(&inputs)
}

/// A Merkle path proving membership.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerklePathPQ {
    /// Sibling hashes from leaf to root.
    pub siblings: Vec<TreeHashPQ>,
    /// Path indices (0 = left, 1 = right).
    pub indices: Vec<u8>,
}

impl MerklePathPQ {
    /// Verify that this path leads from `leaf` to `root`.
    pub fn verify(&self, leaf: &TreeHashPQ, root: &TreeHashPQ) -> bool {
        if self.siblings.len() != TREE_DEPTH_PQ || self.indices.len() != TREE_DEPTH_PQ {
            return false;
        }

        let mut current = bytes_to_hash_out(leaf);

        for (sibling, &index) in self.siblings.iter().zip(self.indices.iter()) {
            let sibling_hash = bytes_to_hash_out(sibling);
            current = if index == 0 {
                hash_node(&current, &sibling_hash)
            } else {
                hash_node(&sibling_hash, &current)
            };
        }

        hash_out_to_bytes(&current) == *root
    }

    /// Get the path depth.
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }
}

/// Witness for spending a note (Merkle path + position).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleWitnessPQ {
    /// The Merkle path.
    pub path: MerklePathPQ,
    /// Position in the tree.
    pub position: u64,
    /// Root at the time of witness generation.
    pub root: TreeHashPQ,
}

impl MerkleWitnessPQ {
    /// Verify this witness for a given commitment.
    pub fn verify(&self, commitment: &NoteCommitmentPQ) -> bool {
        self.path.verify(&commitment.to_bytes(), &self.root)
    }
}

/// Serializable representation of a hash (4 field elements as u64s).
type SerializableHash = [u64; 4];

fn hash_to_serializable(hash: &InternalHash) -> SerializableHash {
    [hash[0].0, hash[1].0, hash[2].0, hash[3].0]
}

fn serializable_to_hash(s: &SerializableHash) -> InternalHash {
    [
        GoldilocksField(s[0]),
        GoldilocksField(s[1]),
        GoldilocksField(s[2]),
        GoldilocksField(s[3]),
    ]
}

/// Snapshot of the commitment tree state for fast loading.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentTreeSnapshot {
    /// Number of leaves in the tree.
    pub size: u64,
    /// Frontier hashes (as raw u64 arrays for serialization).
    pub frontier: Vec<SerializableHash>,
    /// Recent roots for anchor validation.
    pub recent_roots: Vec<TreeHashPQ>,
    /// All leaves (as raw u64 arrays for serialization).
    pub leaves: Vec<SerializableHash>,
    /// Version for future compatibility.
    pub version: u32,
}

/// A commitment tree for storing note commitments.
///
/// Uses an incremental Merkle tree structure where:
/// - Leaves are added left-to-right
/// - Only the frontier (rightmost path) is stored in memory
/// - Recent roots are cached for anchor validation
#[derive(Clone, Debug)]
pub struct CommitmentTreePQ {
    /// Number of leaves in the tree.
    size: u64,
    /// Frontier: hashes at each level on the rightmost path.
    /// frontier[0] is the most recent leaf, frontier[31] is the root.
    frontier: Vec<InternalHash>,
    /// Recent roots for anchor validation.
    recent_roots: VecDeque<TreeHashPQ>,
    /// All leaves (for witness generation in testing/local mode).
    /// In production, this would be stored externally.
    leaves: Vec<InternalHash>,
}

impl Default for CommitmentTreePQ {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitmentTreePQ {
    /// Create a new empty commitment tree.
    pub fn new() -> Self {
        let zero_hash = [GoldilocksField::ZERO; 4];
        let mut tree = Self {
            size: 0,
            frontier: vec![zero_hash; TREE_DEPTH_PQ],
            recent_roots: VecDeque::with_capacity(RECENT_ROOTS_COUNT),
            leaves: Vec::new(),
        };

        // Initialize with empty root
        let empty_root = empty_root_pq();
        tree.recent_roots.push_back(empty_root);

        tree
    }

    /// Get the current root.
    pub fn root(&self) -> TreeHashPQ {
        if self.size == 0 {
            return empty_root_pq();
        }

        // Compute root from stored leaves (consistent with get_path)
        // This is O(n log n) but correct. The frontier-based approach was buggy.
        let mut level: Vec<InternalHash> = self.leaves.clone();

        // Pad to next power of 2
        let next_pow2 = (self.size as usize).next_power_of_two().max(2);
        while level.len() < next_pow2 {
            level.push(empty_hash_at_depth(0));
        }

        // Build tree levels until we reach the partial root
        let mut depth = 0;
        while level.len() > 1 {
            let mut next_level = Vec::with_capacity(level.len() / 2 + 1);
            for chunk in level.chunks(2) {
                let left = &chunk[0];
                let right = if chunk.len() > 1 {
                    &chunk[1]
                } else {
                    &empty_hash_at_depth(depth)
                };
                next_level.push(hash_node(left, right));
            }
            level = next_level;
            depth += 1;
        }

        // We now have the partial root (for next_pow2 leaves)
        // Continue hashing with empty siblings up to TREE_DEPTH_PQ
        let mut current = level[0];
        while depth < TREE_DEPTH_PQ {
            current = hash_node(&current, &empty_hash_at_depth(depth));
            depth += 1;
        }

        hash_out_to_bytes(&current)
    }

    /// Get the empty root (for comparison).
    pub fn empty_root() -> TreeHashPQ {
        empty_root_pq()
    }

    /// Get the number of commitments in the tree.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Check if a root is valid (in recent roots).
    pub fn is_valid_root(&self, root: &TreeHashPQ) -> bool {
        self.recent_roots.contains(root)
    }

    /// Get recent roots.
    pub fn recent_roots(&self) -> &VecDeque<TreeHashPQ> {
        &self.recent_roots
    }

    /// Append a commitment to the tree.
    pub fn append(&mut self, commitment: &NoteCommitmentPQ) {
        let leaf = bytes_to_hash_out(&commitment.to_bytes());
        self.leaves.push(leaf);

        let mut current = leaf;
        let mut position = self.size;

        for depth in 0..TREE_DEPTH_PQ {
            if position & 1 == 0 {
                // This is a left child - save to frontier
                self.frontier[depth] = current;
                break;
            } else {
                // This is a right child - hash with frontier
                current = hash_node(&self.frontier[depth], &current);
            }
            position >>= 1;
        }

        self.size += 1;

        // Update recent roots
        let new_root = self.root();
        self.recent_roots.push_back(new_root);
        if self.recent_roots.len() > RECENT_ROOTS_COUNT {
            self.recent_roots.pop_front();
        }
    }

    /// Get a Merkle path for a commitment at the given position.
    pub fn get_path(&self, position: u64) -> Option<MerklePathPQ> {
        if position >= self.size {
            return None;
        }

        let mut siblings = Vec::with_capacity(TREE_DEPTH_PQ);
        let mut indices = Vec::with_capacity(TREE_DEPTH_PQ);
        let mut pos = position;

        // Build path from stored leaves
        // This is O(n log n) but works for small trees. Production would use a database.
        let mut level: Vec<InternalHash> = self.leaves.clone();

        // Pad to next power of 2 (only what we need, not the full tree)
        let next_pow2 = (self.size as usize).next_power_of_two().max(2);
        while level.len() < next_pow2 {
            level.push(empty_hash_at_depth(0));
        }

        for depth in 0..TREE_DEPTH_PQ {
            let sibling_pos = if pos & 1 == 0 { pos + 1 } else { pos - 1 };

            let sibling = if sibling_pos < level.len() as u64 {
                level[sibling_pos as usize]
            } else {
                empty_hash_at_depth(depth)
            };

            siblings.push(hash_out_to_bytes(&sibling));
            indices.push((pos & 1) as u8);

            // Move up the tree
            if level.len() <= 1 {
                // We've reached the root, fill remaining with empty siblings
                for d in (depth + 1)..TREE_DEPTH_PQ {
                    siblings.push(hash_out_to_bytes(&empty_hash_at_depth(d)));
                    indices.push(0);
                }
                break;
            }

            let mut next_level = Vec::with_capacity(level.len() / 2 + 1);
            for chunk in level.chunks(2) {
                let left = &chunk[0];
                let right = if chunk.len() > 1 {
                    &chunk[1]
                } else {
                    &empty_hash_at_depth(depth)
                };
                next_level.push(hash_node(left, right));
            }
            level = next_level;
            pos >>= 1;
        }

        Some(MerklePathPQ { siblings, indices })
    }

    /// Get a witness for spending a note at the given position.
    pub fn witness(&self, position: u64) -> Option<MerkleWitnessPQ> {
        let path = self.get_path(position)?;
        Some(MerkleWitnessPQ {
            path,
            position,
            root: self.root(),
        })
    }

    /// Get the leaf commitment bytes at a given position.
    pub fn leaf_at(&self, position: u64) -> Option<[u8; 32]> {
        let pos = position as usize;
        if pos < self.leaves.len() {
            Some(hash_out_to_bytes(&self.leaves[pos]))
        } else {
            None
        }
    }

    /// Create a snapshot of the tree state for persistence.
    pub fn snapshot(&self) -> CommitmentTreeSnapshot {
        CommitmentTreeSnapshot {
            size: self.size,
            frontier: self.frontier.iter().map(hash_to_serializable).collect(),
            recent_roots: self.recent_roots.iter().cloned().collect(),
            leaves: self.leaves.iter().map(hash_to_serializable).collect(),
            version: 1,
        }
    }

    /// Restore tree state from a snapshot.
    pub fn from_snapshot(snapshot: CommitmentTreeSnapshot) -> Self {
        Self {
            size: snapshot.size,
            frontier: snapshot.frontier.iter().map(serializable_to_hash).collect(),
            recent_roots: snapshot.recent_roots.into_iter().collect(),
            leaves: snapshot.leaves.iter().map(serializable_to_hash).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let tree = CommitmentTreePQ::new();
        assert_eq!(tree.size(), 0);
        assert_eq!(tree.root(), empty_root_pq());
    }

    #[test]
    fn test_single_commitment() {
        let mut tree = CommitmentTreePQ::new();
        let cm = NoteCommitmentPQ::from_bytes([1u8; 32]);

        tree.append(&cm);

        assert_eq!(tree.size(), 1);
        assert_ne!(tree.root(), empty_root_pq());
    }

    #[test]
    fn test_root_changes() {
        let mut tree = CommitmentTreePQ::new();
        let root1 = tree.root();

        tree.append(&NoteCommitmentPQ::from_bytes([1u8; 32]));
        let root2 = tree.root();

        tree.append(&NoteCommitmentPQ::from_bytes([2u8; 32]));
        let root3 = tree.root();

        assert_ne!(root1, root2);
        assert_ne!(root2, root3);
        assert_ne!(root1, root3);
    }

    #[test]
    fn test_valid_anchor() {
        let mut tree = CommitmentTreePQ::new();
        let root_before = tree.root();

        tree.append(&NoteCommitmentPQ::from_bytes([1u8; 32]));
        let root_after = tree.root();

        // Both should be valid
        assert!(tree.is_valid_root(&root_before));
        assert!(tree.is_valid_root(&root_after));

        // Random root should not be valid
        assert!(!tree.is_valid_root(&[99u8; 32]));
    }

    #[test]
    fn test_merkle_path() {
        let mut tree = CommitmentTreePQ::new();
        let cm = NoteCommitmentPQ::from_bytes([1u8; 32]);

        tree.append(&cm);

        let path = tree.get_path(0).expect("Should have path");
        assert_eq!(path.depth(), TREE_DEPTH_PQ);

        // Verify path leads to root
        assert!(path.verify(&cm.to_bytes(), &tree.root()));
    }

    #[test]
    fn test_witness() {
        let mut tree = CommitmentTreePQ::new();
        let cm = NoteCommitmentPQ::from_bytes([1u8; 32]);

        tree.append(&cm);

        let witness = tree.witness(0).expect("Should have witness");
        assert!(witness.verify(&cm));
        assert_eq!(witness.position, 0);
    }

    #[test]
    fn test_multiple_commitments() {
        let mut tree = CommitmentTreePQ::new();

        for i in 0..10 {
            let mut bytes = [0u8; 32];
            bytes[0] = i as u8;
            tree.append(&NoteCommitmentPQ::from_bytes(bytes));
        }

        assert_eq!(tree.size(), 10);

        // Each commitment should have a valid path
        for i in 0..10 {
            let mut bytes = [0u8; 32];
            bytes[0] = i as u8;
            let cm = NoteCommitmentPQ::from_bytes(bytes);

            let witness = tree.witness(i).expect("Should have witness");
            assert!(witness.verify(&cm), "Position {} failed verification", i);
        }
    }
}
