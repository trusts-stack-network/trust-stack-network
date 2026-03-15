#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::merkle_tree::{MerkleTree, MerkleProof};
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct FuzzData {
    leaves: Vec<u8>,
    proof_indices: Vec<usize>,
    proof_data: Vec<u8>,
}

fuzz_target!(|data: FuzzData| {
    let mut tree = MerkleTree::new();
    
    // Ajoute des feuilles avec des indices potentiellement invalides
    for (i, leaf) in data.leaves.iter().enumerate() {
        tree.insert(i % 1000, *leaf); // Limite l'index pour éviter OOM
    }
    
    // Test avec des preuves potentiellement invalides
    if data.proof_data.len() >= 32 {
        let proof = MerkleProof::from_bytes(&data.proof_data);
        let _ = proof.verify(tree.root(), 0);
    }
});