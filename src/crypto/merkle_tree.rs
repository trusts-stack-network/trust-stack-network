//! Sparse Merkle tree for storing note commitments.
//!
//! The commitment tree is an append-only Merkle tree that stores all note commitments.
//! It provides:
//! - O(log n) proof generation for membership
//! - O(log n) insertions
//! - Deterministic root computation
//!
//! Uses Poseidon hash for efficient verification in zk-SNARK circuits.

use ark_bn254::Fr;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::commitment::NoteCommitment;
use super::poseidon::{
    poseidon_hash, bytes32_to_field, field_to_bytes32,
    DOMAIN_MERKLE_EMPTY, DOMAIN_MERKLE_NODE,
};

/// Tree depth (supports 2^32 notes).
pub const TREE_DEPTH: usize = 32;

/// A hash in the Merkle tree.
pub type TreeHash = [u8; 32];

lazy_static::lazy_static! {
    // Empty leaf value using Poseidon hash.
    static ref EMPTY_LEAVES: Vec<TreeHash> = {
        let mut leaves = Vec::with_capacity(TREE_DEPTH + 1);

        // Level 0: empty leaf = Poseidon(DOMAIN_MERKLE_EMPTY, 0)
        let empty_leaf_fe = poseidon_hash(DOMAIN_MERKLE_EMPTY, &[Fr::from(0u64)]);
        let empty_leaf = field_to_bytes32(&empty_leaf_fe);
        leaves.push(empty_leaf);

        // Higher levels: hash of two children
        for i in 0..TREE_DEPTH {
            let child = &leaves[i];
            let parent = hash_nodes(child, child);
            leaves.push(parent);
        }

        leaves
    };
}

/// Hash two sibling nodes to create parent using Poseidon.
fn hash_nodes(left: &TreeHash, right: &TreeHash) -> TreeHash {
    let left_fe = bytes32_to_field(left);
    let right_fe = bytes32_to_field(right);

    let hash = poseidon_hash(DOMAIN_MERKLE_NODE, &[left_fe, right_fe]);
    field_to_bytes32(&hash)
}

/// A Merkle path proving a leaf's inclusion in the tree.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerklePath {
    /// The leaf position (0-indexed).
    pub position: u64,
    /// The authentication path (sibling hashes from leaf to root).
    pub auth_path: Vec<TreeHash>,
}

impl MerklePath {
    /// Verify that this path leads from the commitment to the given root.
    pub fn verify(&self, commitment: &NoteCommitment, root: &TreeHash) -> bool {
        let mut current = commitment.0;

        for (depth, sibling) in self.auth_path.iter().enumerate() {
            let bit = (self.position >> depth) & 1;
            if bit == 0 {
                current = hash_nodes(&current, sibling);
            } else {
                current = hash_nodes(sibling, &current);
            }
        }

        current == *root
    }

    /// Get the position in the tree.
    pub fn leaf_position(&self) -> u64 {
        self.position
    }

    /// Get the depth of the path.
    pub fn depth(&self) -> usize {
        self.auth_path.len()
    }
}

/// The commitment tree storing all note commitments.
/// Uses a sparse representation - only stores non-empty nodes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentTree {
    /// Number of commitments in the tree.
    size: u64,
    /// Sparse storage: (level, index) -> hash.
    /// Level 0 is leaves, level TREE_DEPTH is root.
    /// Custom serialization to convert tuple keys to "level:index" strings for JSON compat.
    #[serde(with = "node_map_serde")]
    nodes: HashMap<(usize, u64), TreeHash>,
    /// Recent roots (for anchor validation - last N roots are valid).
    recent_roots: Vec<TreeHash>,
    /// Maximum number of recent roots to keep.
    max_recent_roots: usize,
}

/// Custom serialization for HashMap<(usize, u64), TreeHash> as JSON-compatible string keys.
mod node_map_serde {
    use super::*;
    use serde::{Serializer, Deserializer};
    use std::collections::HashMap;

    pub fn serialize<S>(map: &HashMap<(usize, u64), TreeHash>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        use serde::ser::SerializeMap;
        let mut ser_map = serializer.serialize_map(Some(map.len()))?;
        for ((level, index), hash) in map {
            let key = format!("{}:{}", level, index);
            ser_map.serialize_entry(&key, hash)?;
        }
        ser_map.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<(usize, u64), TreeHash>, D::Error>
    where D: Deserializer<'de> {
        use serde::de::Error;
        let string_map: HashMap<String, TreeHash> = HashMap::deserialize(deserializer)?;
        let mut result = HashMap::with_capacity(string_map.len());
        for (key, hash) in string_map {
            let parts: Vec<&str> = key.split(':').collect();
            if parts.len() != 2 {
                return Err(D::Error::custom(format!("invalid node key: {}", key)));
            }
            let level: usize = parts[0].parse().map_err(D::Error::custom)?;
            let index: u64 = parts[1].parse().map_err(D::Error::custom)?;
            result.insert((level, index), hash);
        }
        Ok(result)
    }
}

impl Default for CommitmentTree {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitmentTree {
    /// Create a new empty commitment tree.
    pub fn new() -> Self {
        Self {
            size: 0,
            nodes: HashMap::new(),
            recent_roots: vec![Self::empty_root()],
            max_recent_roots: 1000, // Increased for fast block production
        }
    }

    /// Get the root hash of an empty tree.
    pub fn empty_root() -> TreeHash {
        EMPTY_LEAVES[TREE_DEPTH]
    }

    /// Get the current root hash.
    pub fn root(&self) -> TreeHash {
        self.get_node(TREE_DEPTH, 0)
    }

    /// Get the number of commitments in the tree.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Check if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Get a node from the tree, returning the empty value if not set.
    fn get_node(&self, level: usize, index: u64) -> TreeHash {
        self.nodes
            .get(&(level, index))
            .copied()
            .unwrap_or_else(|| EMPTY_LEAVES[level])
    }

    /// Set a node in the tree.
    fn set_node(&mut self, level: usize, index: u64, hash: TreeHash) {
        // Don't store empty nodes to save space
        if hash != EMPTY_LEAVES[level] {
            self.nodes.insert((level, index), hash);
        } else {
            self.nodes.remove(&(level, index));
        }
    }

    /// Append a commitment to the tree.
    /// Returns the position where it was inserted.
    pub fn append(&mut self, commitment: &NoteCommitment) -> u64 {
        let position = self.size;
        self.size += 1;

        // Set the leaf
        self.set_node(0, position, commitment.0);

        // Update path to root
        let mut current_index = position;
        for level in 0..TREE_DEPTH {
            let parent_index = current_index / 2;
            let left_child = self.get_node(level, parent_index * 2);
            let right_child = self.get_node(level, parent_index * 2 + 1);
            let parent_hash = hash_nodes(&left_child, &right_child);
            self.set_node(level + 1, parent_index, parent_hash);
            current_index = parent_index;
        }

        // Save the new root as a recent root
        let new_root = self.root();
        self.recent_roots.push(new_root);
        if self.recent_roots.len() > self.max_recent_roots {
            self.recent_roots.remove(0);
        }

        position
    }

    /// Get a Merkle path for a commitment at the given position.
    pub fn get_path(&self, position: u64) -> Option<MerklePath> {
        if position >= self.size {
            return None;
        }

        let mut auth_path = Vec::with_capacity(TREE_DEPTH);
        let mut current_index = position;

        for level in 0..TREE_DEPTH {
            let sibling_index = current_index ^ 1;
            let sibling = self.get_node(level, sibling_index);
            auth_path.push(sibling);
            current_index /= 2;
        }

        Some(MerklePath {
            position,
            auth_path,
        })
    }

    /// Get the commitment at a position.
    pub fn get_commitment(&self, position: u64) -> Option<NoteCommitment> {
        if position >= self.size {
            return None;
        }
        let hash = self.get_node(0, position);
        if hash == EMPTY_LEAVES[0] {
            return None;
        }
        Some(NoteCommitment(hash))
    }

    /// Check if a root is a valid recent root.
    /// This allows transactions to use slightly stale roots.
    pub fn is_valid_root(&self, root: &TreeHash) -> bool {
        self.recent_roots.contains(root)
    }

    /// Get all recent valid roots.
    pub fn recent_roots(&self) -> &[TreeHash] {
        &self.recent_roots
    }

    /// Create a witness for a commitment at the given position.
    /// The witness contains all the data needed for a spend proof.
    pub fn witness(&self, position: u64) -> Option<CommitmentWitness> {
        let commitment = self.get_commitment(position)?;
        let path = self.get_path(position)?;
        let root = self.root();

        Some(CommitmentWitness {
            commitment,
            position,
            path,
            root,
        })
    }
}

/// A witness for a commitment, containing everything needed for a spend proof.
#[derive(Clone, Debug)]
pub struct CommitmentWitness {
    /// The commitment being witnessed.
    pub commitment: NoteCommitment,
    /// Position in the tree.
    pub position: u64,
    /// Merkle path from commitment to root.
    pub path: MerklePath,
    /// The root at the time of witness generation.
    pub root: TreeHash,
}

impl CommitmentWitness {
    /// Verify the witness is valid.
    pub fn verify(&self) -> bool {
        self.path.verify(&self.commitment, &self.root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::rngs::StdRng;

    fn random_commitment(rng: &mut StdRng) -> NoteCommitment {
        let mut bytes = [0u8; 32];
        for b in &mut bytes {
            *b = rng.gen();
        }
        NoteCommitment(bytes)
    }

    use ark_std::rand::Rng;

    #[test]
    fn test_empty_tree() {
        let tree = CommitmentTree::new();
        assert_eq!(tree.size(), 0);
        assert!(tree.is_empty());
        assert_eq!(tree.root(), CommitmentTree::empty_root());
    }

    #[test]
    fn test_single_append() {
        let mut tree = CommitmentTree::new();
        let mut rng = StdRng::seed_from_u64(12345);

        let cm = random_commitment(&mut rng);
        let position = tree.append(&cm);

        assert_eq!(position, 0);
        assert_eq!(tree.size(), 1);
        assert!(!tree.is_empty());
        assert_ne!(tree.root(), CommitmentTree::empty_root());
    }

    #[test]
    fn test_merkle_path_verification() {
        let mut tree = CommitmentTree::new();
        let mut rng = StdRng::seed_from_u64(12345);

        // Add several commitments
        let mut commitments = Vec::new();
        for _ in 0..10 {
            let cm = random_commitment(&mut rng);
            tree.append(&cm);
            commitments.push(cm);
        }

        // Verify paths for all commitments
        for (i, cm) in commitments.iter().enumerate() {
            let path = tree.get_path(i as u64).unwrap();
            let root = tree.root();
            assert!(path.verify(cm, &root), "Path verification failed for position {}", i);
        }
    }

    #[test]
    fn test_invalid_path() {
        let mut tree = CommitmentTree::new();
        let mut rng = StdRng::seed_from_u64(12345);

        let cm1 = random_commitment(&mut rng);
        let cm2 = random_commitment(&mut rng);
        tree.append(&cm1);
        tree.append(&cm2);

        let path = tree.get_path(0).unwrap();
        let root = tree.root();

        // Path for cm1 should not verify for cm2
        assert!(!path.verify(&cm2, &root));
    }

    #[test]
    fn test_recent_roots() {
        let mut tree = CommitmentTree::new();
        let mut rng = StdRng::seed_from_u64(12345);

        let root_before = tree.root();

        let cm = random_commitment(&mut rng);
        tree.append(&cm);

        let root_after = tree.root();

        // Both roots should be valid
        assert!(tree.is_valid_root(&root_before));
        assert!(tree.is_valid_root(&root_after));

        // Random root should not be valid
        let fake_root = random_commitment(&mut rng).0;
        assert!(!tree.is_valid_root(&fake_root));
    }

    #[test]
    fn test_witness() {
        let mut tree = CommitmentTree::new();
        let mut rng = StdRng::seed_from_u64(12345);

        let cm = random_commitment(&mut rng);
        let position = tree.append(&cm);

        let witness = tree.witness(position).unwrap();

        assert_eq!(witness.commitment, cm);
        assert_eq!(witness.position, position);
        assert!(witness.verify());
    }

    #[test]
    fn test_get_commitment() {
        let mut tree = CommitmentTree::new();
        let mut rng = StdRng::seed_from_u64(12345);

        let cm = random_commitment(&mut rng);
        let position = tree.append(&cm);

        let retrieved = tree.get_commitment(position).unwrap();
        assert_eq!(cm, retrieved);

        // Invalid position should return None
        assert!(tree.get_commitment(position + 1).is_none());
    }

    #[test]
    fn test_deterministic_root() {
        let mut rng = StdRng::seed_from_u64(12345);

        let mut tree1 = CommitmentTree::new();
        let mut tree2 = CommitmentTree::new();

        // Add same commitments to both trees
        for _ in 0..5 {
            let cm = random_commitment(&mut rng);
            tree1.append(&cm);
            tree2.append(&cm);
        }

        // Roots should be identical
        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_many_commitments() {
        let mut tree = CommitmentTree::new();
        let mut rng = StdRng::seed_from_u64(12345);

        // Add 1000 commitments
        for i in 0..1000 {
            let cm = random_commitment(&mut rng);
            let position = tree.append(&cm);
            assert_eq!(position, i);
        }

        assert_eq!(tree.size(), 1000);

        // Verify a random path
        let path = tree.get_path(500).unwrap();
        let cm = tree.get_commitment(500).unwrap();
        let root = tree.root();
        assert!(path.verify(&cm, &root));
    }
}
