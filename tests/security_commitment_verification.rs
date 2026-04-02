// DISABLED: uses API/modules that no longer exist in current codebase
#![cfg(feature = "disabled_test")]
//! Tests de sécurité: Vérification des commitments Plonky2
//!
//! Ce module teste la vulnérabilité identifiée dans TODO #3:
//! "Vérifier la preuve Plonky2 avant d'accepter le commitment"
//!
//! # Menace
//! Sans vérification de la preuve ZK, un attaquant peut créer des commitments
//! invalides qui seraient acceptés par le système, compromettant l'intégrité
//! des transactions confidentielles.
//!
//! # Mitigation
//! - Vérification complète de la preuve Plonky2
//! - Validation des public inputs
//! - Vérification du commitment root

use tsn::crypto::commitment::{Commitment, CommitmentProof};
use tsn::crypto::poseidon2::Poseidon2Hash;
use tsn::plonky2::{verify_proof, Plonky2Config};

/// Test: Rejet d'un commitment avec preuve invalide
#[test]
fn test_commitment_rejects_invalid_proof() {
    let commitment = Commitment::new(
        Poseidon2Hash::from_bytes(&[0x12; 32]),
        1000u64,
    );

    // Créer une preuve invalide (données aléatoires)
    let invalid_proof = CommitmentProof::from_bytes(&[0xFFu8; 1024]
    ).expect("Preuve créée");

    // La vérification doit échouer
    let result = commitment.verify_plonky2_proof(&invalid_proof);
    assert!(result.is_err(), "Preuve invalide doit être rejetée");
    
    match result {
        Err(CommitmentError::InvalidProof) => {},
        Err(e) => panic!("Mauvaise erreur: {:?}", e),
        Ok(_) => panic!("Preuve invalide acceptée - VULNÉRABILITÉ!"),
    }
}

/// Test: Acceptation d'un commitment avec preuve valide
#[test]
fn test_commitment_accepts_valid_proof() {
    // Créer un commitment valide avec preuve Plonky2
    let (commitment, proof) = create_valid_commitment_with_proof();

    // La vérification doit réussir
    let result = commitment.verify_plonky2_proof(&proof);
    assert!(result.is_ok(), "Preuve valide doit être acceptée: {:?}", result);
}

/// Test: Vérification du commitment root
#[test]
fn test_commitment_root_verification() {
    let commitment = Commitment::new(
        Poseidon2Hash::from_bytes(&[0xab; 32]),
        5000u64,
    );

    // Root incorrect
    let wrong_root = Poseidon2Hash::from_bytes(&[0x00; 32]
    );

    let result = commitment.verify_against_root(&wrong_root);
    assert!(result.is_err(), "Mauvais root doit être rejeté");
}

/// Test: Attaque par malleabilité de la preuve
#[test]
fn test_proof_malleability_protection() {
    let (commitment, mut proof) = create_valid_commitment_with_proof();

    // Modifier légèrement la preuve
    if let Some(byte) = proof.bytes_mut().last_mut() {
        *byte = byte.wrapping_add(1);
    }

    // La preuve modifiée doit être rejetée
    let result = commitment.verify_plonky2_proof(&proof);
    assert!(result.is_err(), "Preuve malléable doit être rejetée");
}

/// Test: Vérification des public inputs
#[test]
fn test_public_inputs_validation() {
    let commitment = Commitment::new(
        Poseidon2Hash::from_bytes(&[0x12; 32]),
        1000u64,
    );

    // Créer une preuve avec mauvais public inputs
    let wrong_inputs_proof = create_proof_with_wrong_inputs(&commitment
    );

    let result = commitment.verify_plonky2_proof(&wrong_inputs_proof);
    assert!(result.is_err(), "Mauvais public inputs doivent être rejetés");
}

/// Test: Performance de vérification
#[test]
fn test_proof_verification_performance() {
    use std::time::Instant;

    let (commitment, proof) = create_valid_commitment_with_proof();

    let start = Instant::now();
    for _ in 0..100 {
        let _ = commitment.verify_plonky2_proof(&proof);
    }
    let elapsed = start.elapsed();

    // La vérification doit être raisonnablement rapide
    assert!(
        elapsed.as_millis() < 5000,
        "Vérification trop lente: {:?}",
        elapsed
    );
}

/// Test: Batch verification de commitments
#[test]
fn test_batch_commitment_verification() {
    let mut commitments = vec![];
    let mut proofs = vec![];

    for i in 0..10 {
        let (comm, proof) = create_valid_commitment_with_proof_with_value(i * 100);
        commitments.push(comm);
        proofs.push(proof);
    }

    // Vérification batch
    let results: Vec<bool> = commitments.iter()
        .zip(proofs.iter())
        .map(|(c, p)| c.verify_plonky2_proof(p).is_ok())
        .collect();

    // Toutes doivent passer
    assert!(results.iter().all(|r| *r), "Toutes les preuves doivent être valides");
}

/// Test: Rejet si preuve manquante
#[test]
fn test_commitment_rejects_missing_proof() {
    let commitment = Commitment::new(
        Poseidon2Hash::from_bytes(&[0x12; 32]),
        1000u64,
    );

    // Vérification sans preuve
    let result = commitment.verify_without_proof();
    assert!(result.is_err(), "Commitment sans preuve doit être rejeté");
}

/// Test: Sérialisation sécurisée
#[test]
fn test_commitment_serialization_integrity() {
    use tsn::storage::serialize;

    let (commitment, proof) = create_valid_commitment_with_proof();

    // Sérialiser
    let comm_bytes = serialize(&commitment).unwrap();
    let proof_bytes = serialize(&proof).unwrap();

    // Corrompre les bytes
    let mut corrupted = comm_bytes.clone();
    if let Some(last) = corrupted.last_mut() {
        *last ^= 0xFF;
    }

    // La désérialisation doit échouer ou détecter la corruption
    let result: Result<Commitment, _> = serialize::deserialize(&corrupted);
    
    // Soit échec de désérialisation, soit vérification échoue
    match result {
        Ok(comm) => {
            // Si désérialisé, la vérification doit échouer
            assert!(comm.verify_plonky2_proof(&proof).is_err());
        }
        Err(_) => {
            // Échec de désérialisation - acceptable
        }
    }
}

// Helper functions
fn create_valid_commitment_with_proof() -> (Commitment, CommitmentProof) {
    create_valid_commitment_with_proof_with_value(1000)
}

fn create_valid_commitment_with_proof_with_value(value: u64) -> (Commitment, CommitmentProof) {
    // Simuler la création d'un commitment valide avec preuve Plonky2
    let config = Plonky2Config::default();
    let commitment = Commitment::new(
        Poseidon2Hash::from_bytes(&[0x12; 32]),
        value,
    );
    
    let proof = commitment.generate_proof(&config
    ).expect("Preuve générée");
    
    (commitment, proof)
}

fn create_proof_with_wrong_inputs(commitment: &Commitment) -> CommitmentProof {
    // Créer une preuve avec des inputs qui ne correspondent pas au commitment
    CommitmentProof::from_bytes(&[0x00u8; 1024]
    ).expect("Preuve créée")
}

#[derive(Debug)]
enum CommitmentError {
    InvalidProof,
    InvalidRoot,
    MissingProof,
}
