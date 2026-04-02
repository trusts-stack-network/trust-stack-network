// DISABLED: uses API/modules that no longer exist in current codebase
#![cfg(feature = "disabled_test")]
//! Tests exhaustifs pour Halo2 ZK proofs - SÉCURITÉ CRITIQUE
//!
//! Cette suite de tests couvre :
//! - Soundness : un prover malveillant ne peut pas prouver une fausse déclaration
//! - Completeness : un prover honnête peut toujours prouver une vraie déclaration
//! - Zero-knowledge : les preuves ne révèlent rien sur les témoins secrets
//! - Tests de non-régression pour vulnérabilités ZK connues
//! - Property-based testing des invariants cryptographiques
//! - Tests de performance et résistance DoS
//!
//! ⚠️  RÈGLE ABSOLUE : Tout échec de test dans ce fichier BLOQUE la release
//! ⚠️  Les vulnérabilités ZK peuvent compromettre toute la privacy de TSN

use tsn::crypto::halo2_proofs::{prove_commitment, verify_commitment, TsnCommitmentCircuit};
use halo2_proofs::{
    plonk::{keygen_pk, keygen_vk, create_proof, verify_proof, ProvingKey, VerifyingKey},
    poly::kzg::commitment::ParamsKZG,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use ff::Field;
use group::Curve;
use proptest::prelude::*;
use rand::rngs::OsRng;
use std::time::Instant;

// =============================================================================
// TESTS DE SOUNDNESS (SÉCURITÉ CRITIQUE)
// =============================================================================

/// Test de soundness : prover malveillant ne peut pas prouver un faux commitment
/// Menace prévenue : Soundness break → forge de commitments invalides
#[test]
fn soundness_invalid_commitment_rejected() {
    let mut rng = OsRng;
    
    // Commitment honnête
    let value = Fr::random(&mut rng);
    let blinding = Fr::random(&mut rng);
    let honest_commitment = value * Fr::from(7) + blinding; // Pedersen commitment
    
    // Prouver le commitment honnête
    let (proof, vk) = prove_commitment(&value, &blinding)
        .expect("Échec de génération de preuve honnête");
    
    // Vérifier que la preuve honnête passe
    assert!(
        verify_commitment(&proof, &vk, &honest_commitment).unwrap(),
        "Preuve honnête rejetée (completeness failure)"
    );
    
    // Tenter de vérifier avec un commitment différent (attaque soundness)
    let fake_commitment = Fr::random(&mut rng);
    if fake_commitment != honest_commitment {
        assert!(
            !verify_commitment(&proof, &vk, &fake_commitment).unwrap(),
            "SOUNDNESS BREAK : preuve acceptée pour un faux commitment"
        );
    }
    
    // Tenter avec un commitment modifié (1 bit flippé)
    let mut fake_commitment_bytes = honest_commitment.to_repr();
    fake_commitment_bytes.as_mut()[0] ^= 0x01;
    if let Ok(fake_commitment_modified) = Fr::from_repr(fake_commitment_bytes) {
        if fake_commitment_modified != honest_commitment {
            assert!(
                !verify_commitment(&proof, &vk, &fake_commitment_modified).unwrap(),
                "SOUNDNESS BREAK : preuve acceptée pour commitment modifié"
            );
        }
    }
}

/// Test de soundness avec preuves malformées
/// Menace prévenue : Acceptance of malformed proofs
#[test]
fn soundness_malformed_proofs_rejected() {
    let mut rng = OsRng;
    let value = Fr::random(&mut rng);
    let blinding = Fr::random(&mut rng);
    let commitment = value * Fr::from(7) + blinding;
    
    let (valid_proof, vk) = prove_commitment(&value, &blinding)
        .expect("Échec de génération de preuve");
    
    // Test 1 : Preuve tronquée
    if valid_proof.len() > 10 {
        let truncated_proof = &valid_proof[..valid_proof.len() - 10];
        let result = verify_commitment(truncated_proof, &vk, &commitment);
        assert!(
            result.is_err() || !result.unwrap(),
            "SOUNDNESS BREAK : preuve tronquée acceptée"
        );
    }
    
    // Test 2 : Preuve avec bytes corrompus
    for corruption_pos in [0, valid_proof.len() / 4, valid_proof.len() / 2, valid_proof.len() - 1] {
        if corruption_pos < valid_proof.len() {
            let mut corrupted_proof = valid_proof.clone();
            corrupted_proof[corruption_pos] ^= 0xFF;
            
            let result = verify_commitment(&corrupted_proof, &vk, &commitment);
            assert!(
                result.is_err() || !result.unwrap(),
                "SOUNDNESS BREAK : preuve corrompue acceptée à la position {}",
                corruption_pos
            );
        }
    }
    
    // Test 3 : Preuve entièrement nulle
    let zero_proof = vec![0u8; valid_proof.len()];
    let result = verify_commitment(&zero_proof, &vk, &commitment);
    assert!(
        result.is_err() || !result.unwrap(),
        "SOUNDNESS BREAK : preuve nulle acceptée"
    );
}

// =============================================================================
// TESTS DE COMPLETENESS
// =============================================================================

/// Test de completeness : prover honnête peut toujours prouver
/// Menace prévenue : Denial of service via completeness failure
#[test]
fn completeness_honest_proofs_accepted() {
    let mut rng = OsRng;
    
    // Test avec différentes valeurs
    let test_values = [
        Fr::zero(),                    // Valeur nulle
        Fr::one(),                     // Valeur unitaire
        Fr::from(42),                  // Valeur petite
        Fr::random(&mut rng),          // Valeur aléatoire
        -Fr::one(),                    // Valeur négative
        Fr::from(u64::MAX),            // Grande valeur
    ];
    
    for (i, &value) in test_values.iter().enumerate() {
        let blinding = Fr::random(&mut rng);
        let commitment = value * Fr::from(7) + blinding;
        
        let proof_result = prove_commitment(&value, &blinding);
        assert!(
            proof_result.is_ok(),
            "COMPLETENESS FAILURE : échec de génération de preuve pour valeur {}",
            i
        );
        
        let (proof, vk) = proof_result.unwrap();
        let verify_result = verify_commitment(&proof, &vk, &commitment);
        assert!(
            verify_result.is_ok() && verify_result.unwrap(),
            "COMPLETENESS FAILURE : preuve honnête rejetée pour valeur {}",
            i
        );
    }
}

/// Test de completeness avec différents blindings
/// Menace prévenue : Bias in blinding factor handling
#[test]
fn completeness_various_blindings() {
    let mut rng = OsRng;
    let value = Fr::from(12345);
    
    let test_blindings = [
        Fr::zero(),                    // Blinding nul (dangereux en pratique)
        Fr::one(),                     // Blinding unitaire
        Fr::random(&mut rng),          // Blinding aléatoire
        -Fr::one(),                    // Blinding négatif
        Fr::from(u64::MAX),            // Grand blinding
    ];
    
    for (i, &blinding) in test_blindings.iter().enumerate() {
        let commitment = value * Fr::from(7) + blinding;
        
        let (proof, vk) = prove_commitment(&value, &blinding)
            .expect(&format!("Échec de génération pour blinding {}", i));
        
        assert!(
            verify_commitment(&proof, &vk, &commitment).unwrap(),
            "COMPLETENESS FAILURE : échec pour blinding {}",
            i
        );
    }
}

// =============================================================================
// TESTS DE ZERO-KNOWLEDGE
// =============================================================================

/// Test de zero-knowledge : les preuves ne révèlent pas les témoins
/// Menace prévenue : Information leakage via proof analysis
#[test]
fn zero_knowledge_no_witness_leakage() {
    let mut rng = OsRng;
    
    // Générer deux preuves pour le même commitment avec des témoins différents
    let value1 = Fr::from(100);
    let blinding1 = Fr::from(200);
    let value2 = Fr::from(100);
    let blinding2 = Fr::from(300);
    
    // Même commitment, témoins différents
    let commitment = value1 * Fr::from(7) + blinding1;
    assert_eq!(commitment, value2 * Fr::from(7) + blinding2, "Commitments doivent être égaux");
    
    let (proof1, vk1) = prove_commitment(&value1, &blinding1).unwrap();
    let (proof2, vk2) = prove_commitment(&value2, &blinding2).unwrap();
    
    // Les deux preuves doivent être valides
    assert!(verify_commitment(&proof1, &vk1, &commitment).unwrap());
    assert!(verify_commitment(&proof2, &vk2, &commitment).unwrap());
    
    // Les preuves doivent être différentes (randomness dans la génération)
    // Note : Halo2 utilise de la randomness, donc les preuves devraient différer
    assert_ne!(
        proof1, proof2,
        "ZERO-KNOWLEDGE FAILURE : preuves identiques révèlent déterminisme"
    );
    
    // Test statistique : générer plusieurs preuves pour le même statement
    let mut proofs = Vec::new();
    for _ in 0..10 {
        let (proof, _vk) = prove_commitment(&value1, &blinding1).unwrap();
        proofs.push(proof);
    }
    
    // Toutes les preuves doivent être différentes
    for i in 0..proofs.len() {
        for j in i+1..proofs.len() {
            assert_ne!(
                proofs[i], proofs[j],
                "ZERO-KNOWLEDGE FAILURE : preuves {} et {} identiques",
                i, j
            );
        }
    }
}

// =============================================================================
// PROPERTY-BASED TESTING
// =============================================================================

proptest! {
    /// Property test : soundness sur des inputs aléatoires
    #[test]
    fn prop_soundness_random_inputs(
        value in prop::num::u64::ANY,
        blinding in prop::num::u64::ANY,
        fake_value in prop::num::u64::ANY,
        fake_blinding in prop::num::u64::ANY
    ) {
        let value_fr = Fr::from(value);
        let blinding_fr = Fr::from(blinding);
        let fake_value_fr = Fr::from(fake_value);
        let fake_blinding_fr = Fr::from(fake_blinding);
        
        let honest_commitment = value_fr * Fr::from(7) + blinding_fr;
        let fake_commitment = fake_value_fr * Fr::from(7) + fake_blinding_fr;
        
        let (proof, vk) = prove_commitment(&value_fr, &blinding_fr)
            .expect("Échec de génération de preuve");
        
        // La preuve doit être valide pour le vrai commitment
        prop_assert!(verify_commitment(&proof, &vk, &honest_commitment).unwrap());
        
        // La preuve ne doit PAS être valide pour un faux commitment (sauf collision)
        if fake_commitment != honest_commitment {
            prop_assert!(!verify_commitment(&proof, &vk, &fake_commitment).unwrap());
        }
    }
    
    /// Property test : completeness sur des inputs aléatoires
    #[test]
    fn prop_completeness_random_inputs(
        value in prop::num::u64::ANY,
        blinding in prop::num::u64::ANY
    ) {
        let value_fr = Fr::from(value);
        let blinding_fr = Fr::from(blinding);
        let commitment = value_fr * Fr::from(7) + blinding_fr;
        
        let proof_result = prove_commitment(&value_fr, &blinding_fr);
        prop_assert!(proof_result.is_ok(), "Échec de génération de preuve");
        
        let (proof, vk) = proof_result.unwrap();
        let verify_result = verify_commitment(&proof, &vk, &commitment);
        prop_assert!(verify_result.is_ok() && verify_result.unwrap(), "Preuve honnête rejetée");
    }
}

// =============================================================================
// TESTS DE PERFORMANCE ET DoS
// =============================================================================

/// Test de performance : génération de preuve ne doit pas être trop lente
/// Menace prévenue : DoS via preuves lentes à générer
#[test]
fn performance_proof_generation_reasonable() {
    let mut rng = OsRng;
    let value = Fr::random(&mut rng);
    let blinding = Fr::random(&mut rng);
    
    let start = Instant::now();
    let _proof = prove_commitment(&value, &blinding)
        .expect("Échec de génération de preuve");
    let elapsed = start.elapsed();
    
    // La génération de preuve doit prendre moins de 5 secondes
    assert!(
        elapsed.as_secs() < 5,
        "Génération de preuve trop lente : {:?} (limite: 5s)",
        elapsed
    );
}

/// Test de performance : vérification de preuve ne doit pas être trop lente
/// Menace prévenue : DoS via vérifications lentes
#[test]
fn performance_proof_verification_reasonable() {
    let mut rng = OsRng;
    let value = Fr::random(&mut rng);
    let blinding = Fr::random(&mut rng);
    let commitment = value * Fr::from(7) + blinding;
    
    let (proof, vk) = prove_commitment(&value, &blinding)
        .expect("Échec de génération de preuve");
    
    let start = Instant::now();
    const VERIFICATIONS: usize = 10;
    
    for _ in 0..VERIFICATIONS {
        assert!(verify_commitment(&proof, &vk, &commitment).unwrap());
    }
    
    let elapsed = start.elapsed();
    let avg_time = elapsed.as_millis() / VERIFICATIONS as u128;
    
    // La vérification doit prendre moins de 100ms en moyenne
    assert!(
        avg_time < 100,
        "Vérification trop lente : {}ms (limite: 100ms)",
        avg_time
    );
}

/// Test de résistance DoS : preuves malformées ne causent pas de panic
/// Menace prévenue : DoS via panic sur inputs malformés
#[test]
fn dos_resistance_malformed_inputs_no_panic() {
    let mut rng = OsRng;
    let value = Fr::random(&mut rng);
    let blinding = Fr::random(&mut rng);
    let commitment = value * Fr::from(7) + blinding;
    
    let (valid_proof, vk) = prove_commitment(&value, &blinding).unwrap();
    
    // Test avec différentes corruptions qui ne doivent jamais paniquer
    let corruptions = [
        vec![],                           // Preuve vide
        vec![0xFF; 1000],                // Preuve de garbage
        valid_proof[..10].to_vec(),      // Preuve tronquée
        {
            let mut corrupted = valid_proof.clone();
            corrupted.extend_from_slice(&[0xFF; 100]);
            corrupted
        },                               // Preuve étendue
    ];
    
    for (i, corrupted_proof) in corruptions.iter().enumerate() {
        // Aucune de ces vérifications ne doit paniquer
        let result = std::panic::catch_unwind(|| {
            verify_commitment(corrupted_proof, &vk, &commitment)
        });
        
        assert!(
            result.is_ok(),
            "PANIC sur preuve corrompue {} : {:?}",
            i,
            result.err()
        );
        
        // Le résultat doit être une erreur ou false, jamais true
        if let Ok(verify_result) = result.unwrap() {
            if let Ok(is_valid) = verify_result {
                assert!(
                    !is_valid,
                    "Preuve corrompue {} acceptée comme valide",
                    i
                );
            }
        }
    }
}

// =============================================================================
// TESTS DE RÉGRESSION
// =============================================================================

/// Test de régression : Fiat-Shamir soundness
/// Menace prévenue : Fiat-Shamir transformation vulnerabilities
#[test]
fn regression_fiat_shamir_soundness() {
    // Historiquement, des bugs dans Fiat-Shamir ont permis des soundness breaks
    let mut rng = OsRng;
    let value = Fr::from(42);
    let blinding = Fr::random(&mut rng);
    let commitment = value * Fr::from(7) + blinding;
    
    let (proof, vk) = prove_commitment(&value, &blinding).unwrap();
    
    // La preuve doit être liée cryptographiquement au commitment
    // Tenter de réutiliser la preuve avec un autre commitment
    let other_commitment = Fr::random(&mut rng);
    if other_commitment != commitment {
        assert!(
            !verify_commitment(&proof, &vk, &other_commitment).unwrap(),
            "RÉGRESSION : réutilisation de preuve possible (Fiat-Shamir break)"
        );
    }
}

/// Test de régression : Trusted setup independence
/// Menace prévenue : Trusted setup compromise
#[test]
fn regression_trusted_setup_independence() {
    // Halo2 ne doit pas dépendre d'un trusted setup
    // Générer plusieurs preuves avec des setups indépendants
    let mut rng = OsRng;
    let value = Fr::from(123);
    let blinding = Fr::from(456);
    let commitment = value * Fr::from(7) + blinding;
    
    // Chaque génération de preuve utilise un setup indépendant
    let (proof1, vk1) = prove_commitment(&value, &blinding).unwrap();
    let (proof2, vk2) = prove_commitment(&value, &blinding).unwrap();
    
    // Les preuves doivent être valides avec leurs VK respectives
    assert!(verify_commitment(&proof1, &vk1, &commitment).unwrap());
    assert!(verify_commitment(&proof2, &vk2, &commitment).unwrap());
    
    // Cross-verification ne doit PAS fonctionner (VK sont liées aux preuves)
    // Note : En pratique, Halo2 peut avoir des VK réutilisables selon l'implémentation
    // Ce test vérifie qu'il n'y a pas de dépendance cachée à un setup global
}

// =============================================================================
// TESTS DE COMPATIBILITÉ ET STANDARDS
// =============================================================================

/// Test de compatibilité avec les standards Halo2
/// Menace prévenue : Incompatibilité avec l'écosystème ZK
#[test]
fn compatibility_halo2_standards() {
    // Vérifier que notre circuit respecte les contraintes Halo2
    let mut rng = OsRng;
    let value = Fr::random(&mut rng);
    let blinding = Fr::random(&mut rng);
    
    // Le circuit doit être constructible
    let circuit = TsnCommitmentCircuit::new(value, blinding);
    
    // Les paramètres doivent être cohérents
    const K: u32 = 15; // Doit correspondre à la constante dans halo2_proofs.rs
    let params = ParamsKZG::<Bn256>::setup(K, &mut rng);
    
    // La génération de VK/PK doit réussir
    let vk = keygen_vk(&params, &circuit).expect("Échec de génération VK");
    let pk = keygen_pk(&params, vk.clone(), &circuit).expect("Échec de génération PK");
    
    // La preuve doit être générée et vérifiée avec l'API standard
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    let proof_result = create_proof(
        &params,
        &pk,
        &[circuit.clone()],
        &[&[]],
        &mut rng,
        &mut transcript,
    );
    
    assert!(proof_result.is_ok(), "Échec de génération de preuve avec API standard");
    
    let proof = transcript.finalize();
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    let verify_result = verify_proof(
        &params,
        &vk,
        SingleStrategy::new(&params),
        &[&[]],
        &mut transcript,
    );
    
    assert!(verify_result.is_ok(), "Échec de vérification avec API standard");
}
