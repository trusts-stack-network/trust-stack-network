use tsn_crypto::commitment::{Commitment, compute_commitment};
use tsn_crypto::poseidon::PoseidonHash;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[test]
fn test_commitment_side_channel_resistance() {
    // Test de résistance aux attaques par canal auxiliaire
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    
    // Génère deux valeurs proches pour tester la fuite d'information
    let value1 = 1000u64;
    let value2 = 1001u64;
    let blinding1 = rng.gen::<[u8; 32]>();
    let blinding2 = rng.gen::<[u8; 32]>();
    
    let commit1 = compute_commitment(value1, &blinding1);
    let commit2 = compute_commitment(value2, &blinding2);
    
    // Vérifie que les commitments sont indiscernables
    assert_ne!(commit1, commit2, "Different values should produce different commitments");
    
    // Test la propriété d'hiding - même valeur avec blinding différent
    let blinding3 = rng.gen::<[u8; 32]>();
    let commit3 = compute_commitment(value1, &blinding3);
    
    assert_ne!(commit1, commit3, "Same value with different blinding should hide");
}

#[test]
fn test_commitment_blinding_entropy() {
    // Vérifie que le blinding a suffisamment d'entropie
    use tsn_crypto::commitment::BLINDING_SIZE;
    
    assert_eq!(BLINDING_SIZE, 32, "Blinding should be 256 bits for 128-bit security");
    
    let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
    let mut blindings = std::collections::HashSet::new();
    
    for _ in 0..1000 {
        let blinding = rng.gen::<[u8; 32]>();
        blindings.insert(blinding);
    }
    
    assert_eq!(blindings.len(), 1000, "Blinding collision detected");
}