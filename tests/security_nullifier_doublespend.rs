// DISABLED: uses API/modules that no longer exist in current codebase
#![cfg(feature = "disabled_test")]
//! Tests de sécurité: Protection contre le double-spend via nullifier
//!
//! Ce module teste la vulnérabilité identifiée dans TODO #4:
//! "Vérifier que le nullifier n'est pas déjà utilisé dans l'historique complet"
//!
//! # Menace
//! Un attaquant pourrait réutiliser un nullifier déjà dépensé pour créer
//! une transaction frauduleuse, permettant un double-spend.
//!
//! # Mitigation
//! - Indexation de tous les nullifiers dépensés
//! - Vérification atomique avant acceptation de transaction
//! - Bloom filter pour recherche rapide

use std::collections::HashSet;
use tsn::crypto::nullifier::{Nullifier, NullifierSet};
use tsn::core::transaction::{Transaction, TransactionError};

/// Test de régression: Double-spend avec nullifier réutilisé
/// Vulnérabilité: CVE-2024-XXXX (simulé)
#[test]
fn test_nullifier_double_spend_prevention() {
    // Créer un nullifier
    let nullifier = Nullifier::from_bytes(
        &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
           0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
           0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
           0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]
    ).expect("Nullifier valide");

    // Créer un set de nullifiers
    let mut nullifier_set = NullifierSet::new();

    // Première utilisation - doit réussir
    assert!(
        nullifier_set.insert(nullifier.clone()),
        "Première insertion doit réussir"
    );

    // Tentative de double-spend - doit échouer
    assert!(
        !nullifier_set.insert(nullifier.clone()),
        "Double-spend doit être détecté et rejeté"
    );

    // Vérifier que le nullifier est bien dans le set
    assert!(nullifier_set.contains(&nullifier), "Nullifier doit être présent");
}

/// Test: Vérification atomique du nullifier pendant validation transaction
#[test]
fn test_transaction_nullifier_atomic_check() {
    use tsn::core::state::State;

    let mut state = State::new();
    let nullifier = Nullifier::from_bytes(
        &[0xab; 32]
    ).expect("Nullifier valide");

    // Simuler une transaction avec nullifier
    let tx = create_test_transaction_with_nullifier(nullifier.clone());

    // Première validation - doit passer
    assert!(state.validate_nullifier(&nullifier).is_ok(),
            "Première validation doit passer");

    // Marquer comme dépensé
    state.spend_nullifier(nullifier.clone()).expect("Spend doit réussir");

    // Deuxième validation - doit échouer
    let result = state.validate_nullifier(&nullifier);
    assert!(result.is_err(), "Double-spend doit être rejeté");
    
    match result {
        Err(TransactionError::NullifierAlreadySpent) => {},
        _ => panic!("Erreur attendue: NullifierAlreadySpent"),
    }
}

/// Test: Attaque par race condition sur nullifier
/// Scénario: Deux threads tentent de valider le même nullifier simultanément
#[test]
fn test_nullifier_race_condition_protection() {
    use std::sync::{Arc, Mutex};
    use std::thread;

    let nullifier_set = Arc::new(Mutex::new(NullifierSet::new()));
    let nullifier = Nullifier::from_bytes(
        &[0xde; 32]
    ).expect("Nullifier valide");

    let mut handles = vec![];

    // Lancer 10 threads qui tentent tous d'insérer le même nullifier
    for _ in 0..10 {
        let set = Arc::clone(&nullifier_set);
        let nf = nullifier.clone();
        
        let handle = thread::spawn(move || {
            let mut set = set.lock().unwrap();
            set.insert(nf)
        });
        handles.push(handle);
    }

    // Collecter les résultats
    let results: Vec<bool> = handles.into_iter()
        .map(|h| h.join().unwrap())
        .collect();

    // Exactement UN thread doit avoir réussi
    let success_count = results.iter().filter(|&&r| r).count();
    assert_eq!(success_count, 1, 
        "Exactement une insertion doit réussir (race condition protection). \
         Réussi: {}", success_count);
}

/// Test: Performance de recherche dans grand set de nullifiers
/// Vérifie que la vérification reste rapide même avec millions de nullifiers
#[test]
fn test_nullifier_performance_large_set() {
    use std::time::Instant;

    let mut nullifier_set = NullifierSet::new();
    
    // Insérer 100k nullifiers
    for i in 0..100_000u64 {
        let bytes = i.to_le_bytes();
        let mut full_bytes = [0u8; 32];
        full_bytes[0..8].copy_from_slice(&bytes);
        
        let nf = Nullifier::from_bytes(&full_bytes).expect("Nullifier valide");
        nullifier_set.insert(nf);
    }

    // Mesurer le temps de recherche
    let target = Nullifier::from_bytes(
        &[0x99; 32]
    ).expect("Nullifier valide");
    
    let start = Instant::now();
    for _ in 0..1000 {
        nullifier_set.contains(&target);
    }
    let elapsed = start.elapsed();

    // Doit être très rapide (< 1ms pour 1000 recherches)
    assert!(
        elapsed.as_millis() < 10,
        "Recherche trop lente: {:?} pour 1000 recherches",
        elapsed
    );
}

/// Test: Nullifier avec valeurs aux limites
#[test]
fn test_nullifier_edge_cases() {
    // Nullifier avec tous les bytes à 0
    let zero_nf = Nullifier::from_bytes(&[0u8; 32]
    ).expect("Nullifier valide");

    // Nullifier avec tous les bytes à 0xFF
    let max_nf = Nullifier::from_bytes(
        &[0xFFu8; 32]
    ).expect("Nullifier valide");

    // Nullifier avec pattern alterné
    let alt_nf = Nullifier::from_bytes(
        &[0xAA, 0x55].repeat(16).as_slice()
    ).expect("Nullifier valide");

    let mut set = NullifierSet::new();
    
    // Tous doivent être insérables
    assert!(set.insert(zero_nf.clone()));
    assert!(set.insert(max_nf.clone()));
    assert!(set.insert(alt_nf.clone()));

    // Et non réinsérables
    assert!(!set.insert(zero_nf));
    assert!(!set.insert(max_nf));
    assert!(!set.insert(alt_nf));
}

/// Test: Sérialisation/désérialisation du nullifier set
#[test]
fn test_nullifier_set_serialization() {
    use tsn::storage::serialize;

    let mut set = NullifierSet::new();
    
    // Ajouter quelques nullifiers
    for i in 0..100u64 {
        let bytes = i.to_le_bytes();
        let mut full_bytes = [0u8; 32];
        full_bytes[0..8].copy_from_slice(&bytes);
        let nf = Nullifier::from_bytes(&full_bytes).unwrap();
        set.insert(nf);
    }

    // Sérialiser
    let serialized = serialize(&set).expect("Sérialisation réussie");

    // Désérialiser
    let deserialized: NullifierSet = serialize::deserialize(&serialized)
        .expect("Désérialisation réussie");

    // Vérifier que tous les nullifiers sont préservés
    for i in 0..100u64 {
        let bytes = i.to_le_bytes();
        let mut full_bytes = [0u8; 32];
        full_bytes[0..8].copy_from_slice(&bytes);
        let nf = Nullifier::from_bytes(&full_bytes).unwrap();
        assert!(deserialized.contains(&nf), "Nullifier {} manquant", i);
    }
}

// Helper function
fn create_test_transaction_with_nullifier(nullifier: Nullifier) -> Transaction {
    // Créer une transaction de test avec le nullifier
    Transaction::new_test_with_nullifier(nullifier)
}
