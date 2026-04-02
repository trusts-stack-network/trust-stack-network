use tsn_crypto::commitment::{CommitmentScheme, verify_commitment};
use tsn_crypto::merkle_tree::MerkleTree;
use rand::{Rng, thread_rng};
use proptest::prelude::*;

#[test]
fn test_invalid_commitment_detection() {
    let mut rng = thread_rng();
    let scheme = CommitmentScheme::new();
    
    // Test valeurs aux limites
    let test_cases = vec![
        vec![0u8; 0],      // Vide
        vec![0u8; 1],      // 1 byte
        vec![0u8; 31],     // 31 bytes
        vec![0u8; 32],     // 32 bytes
        vec![0u8; 64],     // 64 bytes
        vec![255u8; 32],   // Tous bits à 1
    ];
    
    for data in test_cases {
        let (comm, opening) = scheme.commit(&data, &mut rng);
        
        // Vérification valide
        assert!(verify_commitment(&comm, &data, &opening));
        
        // Donnée modifiée
        let mut bad_data = data.clone();
        if !bad_data.is_empty() {
            bad_data[0] ^= 1;
            assert!(!verify_commitment(&comm, &bad_data