use tsn_crypto::merkle_tree::{MerkleTree, MerkleProof};
use tsn_crypto::poseidon::PoseidonHash;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[test]
fn test_merkle_proof_verification_timing() {
    // Test de timing attack sur la vérification de preuve Merkle
    let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
    let mut tree = MerkleTree::new(32);
    
    // Ajoute des feuilles aléatoires
    for i in 0..100 {
        let leaf = rng.gen::<[u8; 32]>();
        tree.insert(i, leaf).unwrap();
    }
    
    let mut timings = Vec::new();
    
    for _ in 0..1000 {
        let index = rng.gen_range(0..100);
        let proof = tree.get_proof(index).unwrap();
        let leaf = tree.get_leaf(index).unwrap();
        
        let start = std::time::Instant::now();
        let _ = proof.verify(&tree.root(), index, &leaf);
        timings.push(start.elapsed());
    }
    
    // Analyse la distribution des temps
    let mut sorted_timings = timings.clone();
    sorted_timings.sort();
    
    let median = sorted_timings[500];
    let q1 = sorted_timings[250];
    let q3 = sorted_timings[750];
    let iqr = q3 - q1;
    
    // Si IQR est trop petit, potentielle fuite d'information
    assert!(iqr.as_nanos() > 100, "Potential information leakage in Merkle proof verification");
}

proptest! {
    #[test]
