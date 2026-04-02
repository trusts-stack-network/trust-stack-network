use crate::crypto::commitment::CommitmentScheme;
use crate::crypto::poseidon::PoseidonHash;
use proptest::prelude::*;
use ark_ff::UniformRand;
use rand::rngs::OsRng;

proptest! {
    #[test]
    fn commitment_binding(
        input1 in prop::collection::vec(any::<u8>(), 32..128),
        input2 in prop::collection::vec(any::<u8>(), 32..128),
        blinding1 in any::<[u8; 32]>(),
        blinding2 in any::<[u8; 32]>()
    ) {
        let scheme = CommitmentScheme::new();
        let comm1 = scheme.commit(&input1, &blinding1);
        let comm2 = scheme.commit(&input2, &blinding2);
        
        // Test de liaison - commitments différents pour inputs différents
        prop_assert!(comm1 != comm2 || (input1 == input2 && blinding1 == blinding2));
    }
    
    #[test]
    fn commitment_hiding(
        input in prop::collection::vec(any::<u8>(), 64),
        blinding1 in any::<[u8; 32]>(),
        blinding2 in any::<[u8; 32]>()
    ) {
        let scheme = CommitmentScheme::new();
        let comm1 = scheme.commit(&input, &blinding1);
        let comm2 = scheme.commit(&input, &blinding2);
        
        // Même input avec blinding différent = commitments différents
        prop_assert_ne!(comm1, comm2);
    }
}

#[test]
fn test_commitment_homomorphic() {
    let scheme = CommitmentScheme::new();
    let value1 = 100u64;
    let value2 = 200u64;
    let blinding = [0u8; 32];
    
    let comm1 = scheme.commit_value(value1, &blinding);
    let comm2 = scheme.commit_value(value2, &blinding);
    let comm_sum = scheme.commit_value(value1 + value2, &blinding);
    
    // Vérifier l'homomorphisme
    assert_eq!(comm_sum, scheme.add(&comm1, &comm2));
}

#[test]
fn test_poseidon_parameter_validation() {
    use crate::crypto::poseidon::PoseidonParams;
    
    // Test avec des paramètres invalides
    let invalid_params = [
        (0, 3),  // capacité nulle
        (2, 0),  // rate nul
        (1, 1),  // trop petit
    ];
    
    for (capacity, rate) in invalid_params {
        let result = PoseidonParams::new(capacity, rate);
        assert!(result.is_err(), "Params ({}, {}) should be invalid", capacity, rate);
    }
}