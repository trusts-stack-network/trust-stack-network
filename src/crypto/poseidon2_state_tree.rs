use zeroize::Zeroize;
use poseidon2::{Poseidon, PoseidonConfig};
use merkle_tree::{MerkleTree, MerkleProof};

/// State tree implementation using Poseidon2 hash function.
///
/// This state tree is designed to be constant-time and secure against side-channel attacks.
/// The Poseidon2 hash function is used as the base for the Merkle Tree nodes.
pub struct Poseidon2StateTree {
    merkle_tree: MerkleTree<Poseidon>,
}

impl Poseidon2StateTree {
    /// Creates a new Poseidon2 State Tree with a given depth.
    ///
    /// # Arguments
    ///
    /// * `depth` - The depth of the Merkle Tree. Must be greater than 0.
    pub fn new(depth: usize) -> Self {
        let config = PoseidonConfig::new(depth);
        let poseidon_hash = Poseidon::new(config);
        let merkle_tree = MerkleTree::new(poseidon_hash, depth);

        Poseidon2StateTree { merkle_tree }
    }

    /// Inserts a new value into the state tree.
    ///
    /// # Arguments
    ///
    /// * `key` - The key associated with the value. Must be unique.
    /// * `value` - The value to insert.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) {
        self.merkle_tree.insert(key, value);
    }

    /// Retrieves a value from the state tree by its key.
    ///
    /// # Arguments
    ///
    /// * `key` - The key associated with the value to retrieve.
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.merkle_tree.get(key)
    }

    /// Generates a Merkle proof for a given key-value pair.
    ///
    /// # Arguments
    ///
    /// * `key` - The key associated with the value to prove.
    pub fn generate_proof(&self, key: &[u8]) -> Option<MerkleProof> {
        self.merkle_tree.generate_proof(key)
    }

    /// Verifies a Merkle proof for a given key-value pair and root hash.
    ///
    /// # Arguments
    ///
    /// * `key` - The key associated with the value to prove.
    /// * `value` - The value to prove.
    /// * `proof` - The Merkle proof to verify.
    /// * `root_hash` - The root hash of the Merkle Tree.
    pub fn verify_proof(
        &self,
        key: &[u8],
        value: &[u8],
        proof: &MerkleProof,
        root_hash: &[u8],
    ) -> bool {
        self.merkle_tree.verify_proof(key, value, proof, root_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_poseidon2_state_tree() {
        let mut rng = OsRng;
        let depth = 4;
        let mut state_tree = Poseidon2StateTree::new(depth);

        let key1 = b"key1";
        let value1 = b"value1";
        let key2 = b"key2";
        let value2 = b"value2";

        // Insert values
        state_tree.insert(key1, value1);
        state_tree.insert(key2, value2);

        // Retrieve values
        assert_eq!(state_tree.get(key1), Some(value1));
        assert_eq!(state_tree.get(key2), Some(value2));

        // Generate and verify proof
        let proof = state_tree.generate_proof(key1).unwrap();
        assert!(state_tree.verify_proof(key1, value1, &proof, state_tree.merkle_tree.root_hash()));

        // Insert a new value that should invalidate the previous proof
        let key3 = b"key3";
        let value3 = b"value3";
        state_tree.insert(key3, value3);

        assert!(!state_tree.verify_proof(key1, value1, &proof, state_tree.merkle_tree.root_hash()));
    }
}