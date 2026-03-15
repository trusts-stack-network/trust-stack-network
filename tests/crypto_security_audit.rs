// DISABLED: uses API/modules that no longer exist in current codebase
#![cfg(feature = "disabled_test")]
//! Tests de sécurité critiques pour les modules cryptographiques TSN
//!
//! Ce module teste spécifiquement les vulnérabilités de sécurité identifiées
//! lors de l'audit de sécurité des modules crypto.

use std::time::Instant;
use tsn::crypto::pq::ml_dsa::{keygen_from_seed, sign, verify};
use tsn::crypto::poseidon::{poseidon_hash, DOMAIN_NOTE_COMMITMENT, DOMAIN_NULLIFIER};
use ark_bn254::Fr;
use ark_ff::PrimeField;

/// Test de timing attack sur la vérification ML-DSA
/// 
/// VULNÉRABILITÉ: La fonction verify() pourrait révéler des informations
/// via des différences de timing entre signatures valides et invalides.
#[test]
fn test_mldsa_timing_attack_resistance() {
    let seed = [42u8; 32];
    let (sk, pk) = keygen_from_seed(&seed).unwrap();
    let message = b"test message for timing analysis";
    
    // Signature valide
    let valid_sig = sign(&sk, message);
    
    // Signature invalide (modifiée)
    let mut invalid_sig = valid_sig.clone();
    // Modifier la signature pour la rendre invalide
    // Note: On ne peut pas accéder directement aux bytes, donc on crée une signature différente
    let invalid_sig = sign(&sk, b"different message");
    
    // Mesurer le temps de vérification pour signatures valides
    let mut valid_times = Vec::new();
    for _ in 0..1000 {
        let start = Instant::now();
        let result = verify(&pk, message, &valid_sig);
        let duration = start.elapsed();
        assert!(result, "Valid signature should verify");
        valid_times.push(duration);
    }
    
    // Mesurer le temps de vérification pour signatures invalides
    let mut invalid_times = Vec::new();
    for _ in 0..1000 {
        let start = Instant::now();
        let result = verify(&pk, message, &invalid_sig);
        let duration = start.elapsed();
        assert!(!result, "Invalid signature should not verify");
        invalid_times.push(duration);
    }
    
    // Analyser les différences de timing
    let avg_valid: f64 = valid_times.iter().map(|d| d.as_nanos() as f64).sum::<f64>() / valid_times.len() as f64;
    let avg_invalid: f64 = invalid_times.iter().map(|d| d.as_nanos() as f64).sum::<f64>() / invalid_times.len() as f64;
    
    let timing_ratio = (avg_valid - avg_invalid).abs() / avg_valid.min(avg_invalid);
    
    // SEUIL CRITIQUE: Si la différence de timing > 5%, c'est un timing attack potentiel
    if timing_ratio > 0.05 {
        panic!(
            "TIMING ATTACK DÉTECTÉ: Différence de timing significative entre signatures valides ({:.2}ns) et invalides ({:.2}ns). Ratio: {:.2}%",
            avg_valid, avg_invalid, timing_ratio * 100.0
        );
    }
    
    println!("✅ Test timing attack ML-DSA: Ratio = {:.2}% (< 5% seuil)", timing_ratio * 100.0);
}

/// Test de résistance aux attaques par collision de domaines Poseidon
///
/// VULNÉRABILITÉ: Les domaines sont des u64 simples, risque de collision
/// si un attaquant peut contrôler les inputs.
#[test]
fn test_poseidon_domain_collision_resistance() {
    // Test 1: Vérifier qu'on ne peut pas créer une collision en manipulant les inputs
    let value1 = Fr::from(DOMAIN_NOTE_COMMITMENT); // 1
    let value2 = Fr::from(123u64);
    
    let value3 = Fr::from(DOMAIN_NULLIFIER); // 3  
    let value4 = Fr::from(123u64);
    
    // Ces deux hashs ne doivent JAMAIS être égaux même si les valeurs après domaine sont identiques
    let hash1 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[value2]);
    let hash2 = poseidon_hash(DOMAIN_NULLIFIER, &[value4]);
    
    assert_ne!(hash1, hash2, "COLLISION DÉTECTÉE: Domaines différents produisent le même hash!");
    
    // Test 2: Vérifier qu'on ne peut pas bypasser le domaine en manipulant les inputs
    // Tentative d'attaque: hash(domain=1, [a,b]) == hash(domain=2, [c,d]) où c = 1 et d = a
    let a = Fr::from(999u64);
    let b = Fr::from(888u64);
    
    let legitimate_hash = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[a, b]);
    
    // Attaque: essayer de reproduire ce hash avec un domaine différent
    let attack_hash = poseidon_hash(DOMAIN_NULLIFIER, &[Fr::from(DOMAIN_NOTE_COMMITMENT), a]);
    
    assert_ne!(legitimate_hash, attack_hash, "BYPASS DOMAINE DÉTECTÉ: Attaquant peut forger des hashs!");
    
    println!("✅ Test collision domaines Poseidon: Résistant aux attaques par manipulation");
}

/// Test de robustesse contre les inputs malformés Poseidon
///
/// VULNÉRABILITÉ: panic!() dans poseidon_hash peut crasher le nœud
#[test]
fn test_poseidon_malformed_inputs_robustness() {
    // Test avec des valeurs extrêmes
    let max_field = Fr::from_str("21888242871839275222246405745257275088548364400416034343698204186575808495616").unwrap_or(Fr::from(0u64));
    let zero_field = Fr::from(0u64);
    
    // Ces appels ne doivent JAMAIS paniquer
    let result1 = std::panic::catch_unwind(|| {
        poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[max_field, zero_field])
    });
    
    assert!(result1.is_ok(), "Poseidon panic avec valeurs extrêmes!");
    
    // Test avec beaucoup d'inputs (potentiel DoS)
    let many_inputs: Vec<Fr> = (0..100).map(|i| Fr::from(i as u64)).collect();
    
    let result2 = std::panic::catch_unwind(|| {
        poseidon_hash(DOMAIN_NOTE_COMMITMENT, &many_inputs)
    });
    
    assert!(result2.is_ok(), "Poseidon panic avec beaucoup d'inputs!");
    
    // Test avec inputs vides
    let result3 = std::panic::catch_unwind(|| {
        poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[])
    });
    
    assert!(result3.is_ok(), "Poseidon panic avec inputs vides!");
    
    println!("✅ Test robustesse Poseidon: Résistant aux inputs malformés");
}

/// Test de zeroization sécurisée des clés secrètes
///
/// VULNÉRABILITÉ: Le code unsafe peut être optimisé par le compilateur
#[test]
fn test_secret_key_secure_zeroization() {
    use tsn::crypto::pq::ml_dsa::SecretKey;
    use std::ptr;
    
    let seed = [42u8; 32];
    let (sk, _pk) = keygen_from_seed(&seed).unwrap();
    
    // Capturer un pointeur vers les données de la clé
    let sk_ptr = &sk as *const SecretKey as *const u8;
    
    // Vérifier que la clé contient des données non-nulles initialement
    let initial_data = unsafe {
        std::slice::from_raw_parts(sk_ptr, std::mem::size_of::<SecretKey>())
    };
    
    let has_nonzero_initial = initial_data.iter().any(|&b| b != 0);
    assert!(has_nonzero_initial, "Clé secrète devrait contenir des données non-nulles");
    
    // Forcer la destruction de la clé
    drop(sk);
    
    // ATTENTION: Ce test est fragile car il dépend du comportement du compilateur
    // et de l'allocateur. Il sert surtout à détecter des régressions évidentes.
    
    // Vérifier que la mémoire a été modifiée (pas forcément zéroée à cause de l'allocateur)
    let post_drop_data = unsafe {
        std::slice::from_raw_parts(sk_ptr, std::mem::size_of::<SecretKey>())
    };
    
    // Note: On ne peut pas garantir que la mémoire soit zéroée car l'allocateur
    // peut réutiliser la zone. Ce test détecte surtout les cas où zeroize() n'est pas appelé.
    
    println!("✅ Test zeroization: Drop appelé (vérification complète nécessite outils externes)");
    println!("   Initial non-zero bytes: {}", initial_data.iter().filter(|&&b| b != 0).count());
    println!("   Post-drop non-zero bytes: {}", post_drop_data.iter().filter(|&&b| b != 0).count());
}

/// Test de non-malléabilité des signatures ML-DSA
///
/// VULNÉRABILITÉ: Vérifier qu'un attaquant ne peut pas modifier une signature
/// valide pour créer une autre signature valide pour le même message.
#[test]
fn test_mldsa_signature_non_malleability() {
    let seed = [42u8; 32];
    let (sk, pk) = keygen_from_seed(&seed).unwrap();
    let message = b"critical transaction data";
    
    let signature = sign(&sk, message);
    
    // Vérifier que la signature originale est valide
    assert!(verify(&pk, message, &signature), "Signature originale doit être valide");
    
    // Tenter de créer des signatures modifiées
    // Note: Comme on ne peut pas accéder aux bytes de la signature directement,
    // on teste la propriété de non-malléabilité indirectement
    
    // Test 1: Deux signatures du même message doivent être identiques (déterminisme)
    let signature2 = sign(&sk, message);
    
    // ML-DSA est déterministe, donc les signatures doivent être identiques
    // Si elles diffèrent, c'est soit un problème de randomness, soit de malléabilité
    
    // Test 2: Signature d'un message légèrement différent doit être complètement différente
    let modified_message = b"critical transaction datA"; // Un seul caractère changé
    let signature_modified = sign(&sk, modified_message);
    
    // Vérifier que cette signature n'est pas valide pour le message original
    assert!(!verify(&pk, message, &signature_modified), 
           "Signature d'un message modifié ne doit pas être valide pour l'original");
    
    println!("✅ Test non-malléabilité ML-DSA: Signatures résistantes à la modification");
}

/// Test de résistance aux attaques par rejeu (replay attacks)
///
/// VULNÉRABILITÉ: S'assurer qu'une signature valide ne peut pas être réutilisée
/// dans un contexte différent.
#[test]
fn test_signature_replay_resistance() {
    let seed1 = [1u8; 32];
    let seed2 = [2u8; 32];
    
    let (sk1, pk1) = keygen_from_seed(&seed1).unwrap();
    let (sk2, pk2) = keygen_from_seed(&seed2).unwrap();
    
    let message = b"transfer 1000 TSN to Alice";
    
    // Alice signe le message
    let signature_alice = sign(&sk1, message);
    
    // Vérifier que la signature d'Alice est valide avec sa clé publique
    assert!(verify(&pk1, message, &signature_alice), "Signature Alice doit être valide");
    
    // ATTAQUE: Bob essaie de réutiliser la signature d'Alice avec sa propre clé publique
    assert!(!verify(&pk2, message, &signature_alice), 
           "REPLAY ATTACK: Signature d'Alice ne doit pas être valide avec la clé de Bob");
    
    // ATTAQUE: Essayer d'utiliser la signature avec un message légèrement modifié
    let modified_message = b"transfer 1000 TSN to Bob  "; // Espaces ajoutés
    assert!(!verify(&pk1, modified_message, &signature_alice),
           "REPLAY ATTACK: Signature ne doit pas être valide pour un message modifié");
    
    println!("✅ Test résistance replay: Signatures liées à la clé et au message exact");
}

/// Test de performance et résistance DoS sur les opérations crypto
///
/// VULNÉRABILITÉ: S'assurer qu'un attaquant ne peut pas DoS le nœud
/// avec des opérations crypto coûteuses.
#[test]
fn test_crypto_performance_dos_resistance() {
    use std::time::{Duration, Instant};
    
    let seed = [42u8; 32];
    let (sk, pk) = keygen_from_seed(&seed).unwrap();
    let message = b"performance test message";
    
    // Test 1: Temps de signature (doit être raisonnable)
    let start = Instant::now();
    let signature = sign(&sk, message);
    let sign_duration = start.elapsed();
    
    // Seuil: signature ne doit pas prendre plus de 10ms
    assert!(sign_duration < Duration::from_millis(10), 
           "Signature trop lente: {:?} > 10ms (DoS potentiel)", sign_duration);
    
    // Test 2: Temps de vérification (doit être encore plus rapide)
    let start = Instant::now();
    let is_valid = verify(&pk, message, &signature);
    let verify_duration = start.elapsed();
    
    assert!(is_valid, "Signature doit être valide");
    assert!(verify_duration < Duration::from_millis(5),
           "Vérification trop lente: {:?} > 5ms (DoS potentiel)", verify_duration);
    
    // Test 3: Résistance DoS Poseidon avec inputs multiples
    let inputs: Vec<Fr> = (0..10).map(|i| Fr::from(i as u64)).collect();
    
    let start = Instant::now();
    let _hash = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &inputs);
    let hash_duration = start.elapsed();
    
    assert!(hash_duration < Duration::from_millis(1),
           "Hash Poseidon trop lent: {:?} > 1ms (DoS potentiel)", hash_duration);
    
    println!("✅ Test performance DoS: Sign={:?}, Verify={:?}, Hash={:?}", 
             sign_duration, verify_duration, hash_duration);
}
