use tsn_crypto::commitment::{CommitmentScheme, PedersenCommitment};
use tsn_crypto::note::NoteCommitment;
use proptest::prelude::*;
use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;

/// Tests de sécurité pour le système de commitment
#[test]
fn test_commitment_binding() {
    let mut rng = thread_rng();
    let scheme = PedersenCommitment::new();
    
    let value1 = 100u64;
    let value2 = 200u64;
    let blinding1 = Scalar::random(&mut rng);
    let blinding2 = Scalar::random(&mut rng);
    
    let commitment1 = scheme.commit(value1, blinding1);
    let commitment2 = scheme.commit(value2, blinding2);
    
    // Deux valeurs différentes do