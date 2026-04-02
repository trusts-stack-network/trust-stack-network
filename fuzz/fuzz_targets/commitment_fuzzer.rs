#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn::crypto::commitment::{commit, verify_commitment};
use tsn::crypto::merkle_tree::MerkleTree;

fuzz_target!(|data: &[u8]| {
    // Test commitment avec données aléatoires
    let commitment = commit(data);
    
    // Vérifie que le commitment est valide
    let (comm, opening) = commit(data);
    assert!(verify_commitment(&comm, data, &opening));
    
    // Test avec taille variable
    if data.len() > 0 {
        let mut corrupted = data.to_vec();
        corrupted[0] ^= 0xFF;
        
        // Commitment différent pour données corrompues
        let (corrupted_comm, _) = commit(&corrupted);
        assert_ne!(comm, corrupted_comm);
    }
    
    // Fuzz Merkle tree
    let mut tree = MerkleTree::new();
    tree.insert(data);
    
    // Ne doit pas paniquer
    let _ = tree.root();
});