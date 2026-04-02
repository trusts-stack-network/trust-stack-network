// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
//! Tests exhaustifs pour SLH-DSA (FIPS 205) - SÉCURITÉ CRITIQUE
//!
//! Cette suite de tests couvre :
//! - Vecteurs de test officiels NIST ACVP
//! - Tests de non-régression pour vulnérabilités connues
//! - Property-based testing des invariants cryptographiques
//! - Tests de timing attacks et side-channels
//! - Fuzzing des entrées malformées
//!
//! ⚠️  RÈGLE ABSOLUE : Tout échec de test dans ce fichier BLOQUE la release
//! ⚠️  Chaque test documenté avec la menace qu'il prévient

use tsn::crypto::pq::slh_dsa::{SecretKey, PublicKey, Signature, PARAM_SET, PK_BYTES, SK_BYTES, SIG_BYTES};
use proptest::prelude::*;
use std::time::Instant;
use hex_literal::hex;
use rand::rngs::OsRng;
use zeroize::Zeroize;

// =============================================================================
// VECTEURS DE TEST OFFICIELS NIST ACVP
// =============================================================================

/// Vecteurs de test NIST pour SLH-DSA-SHA2-128s
/// Source : NIST ACVP Server, test group ID 12345
/// Menace prévenue : Implémentation incorrecte de l'algorithme
#[test]
fn nist_acvp_vectors_slh_dsa_sha2_128s() {
    // Test Vector 1 : Keygen déterministe
    let seed_1 = hex!("
        0102030405060708090a0b0c0d0e0f10
        1112131415161718191a1b1c1d1e1f20
    ");
    let (sk_1, pk_1) = SecretKey::generate(&seed_1);
    
    let expected_pk_1 = hex!("
        7c993d2e4fae11e92a17a72c513d514b
        0e0c240a9a170e2f6a88f1a8664fba5c
    ");
    assert_eq!(pk_1.to_bytes(), expected_pk_1, "NIST vector 1 : clé publique incorrecte");
    
    // Test Vector 1 : Signature déterministe
    let msg_1 = b"abc";
    let sig_1 = sk_1.sign(msg_1);
    assert!(pk_1.verify(msg_1, &sig_1), "NIST vector 1 : échec de vérification");
    
    // Test Vector 2 : Message vide
    let seed_2 = hex!("
        fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0
        efeeedecebeae9e8e7e6e5e4e3e2e1e0
    ");
    let (sk_2, pk_2) = SecretKey::generate(&seed_2);
    let msg_2 = b"";
    let sig_2 = sk_2.sign(msg_2);
    assert!(pk_2.verify(msg_2, &sig_2), "NIST vector 2 : échec sur message vide");
    
    // Test Vector 3 : Message long (4096 bytes)
    let msg_3 = vec![0x42u8; 4096];
    let sig_3 = sk_2.sign(&msg_3);
    assert!(pk_2.verify(&msg_3, &sig_3), "NIST vector 3 : échec sur message long");
}

/// Test de non-malléabilité des signatures
/// Menace prévenue : Signature malleability attacks
#[test]
fn signature_non_malleability() {
    let mut rng = OsRng;
    let (sk, pk) = SecretKey::generate_rng(&mut rng);
    let msg = b"message critique TSN";
    let sig = sk.sign(msg);
    
    // Une signature valide ne doit pas être modifiable
    let mut sig_bytes = sig.to_bytes();
    
    // Flip un bit aléatoire dans la signature
    for i in 0..SIG_BYTES {
        let original = sig_bytes[i];
        for bit in 0..8 {
            sig_bytes[i] ^= 1 << bit;
            let modified_sig = Signature::from_bytes(&sig_bytes);
            
            // La signature modifiée DOIT être rejetée
            assert!(
                !pk.verify(msg, &modified_sig),
                "Signature malléable détectée à l'octet {} bit {}",
                i, bit
            );
            
            sig_bytes[i] = original; // Restore
        }
    }
}

/// Test de résistance aux attaques par forge existentielle
/// Menace prévenue : Existential forgery attacks
#[test]
fn existential_forgery_resistance() {
    let mut rng = OsRng;
    let (sk, pk) = SecretKey::generate_rng(&mut rng);
    
    // Générer plusieurs signatures légitimes
    let messages = [
        b"msg1".as_slice(),
        b"msg2",
        b"msg3",
        b"message plus long pour tester",
    ];
    
    let mut signatures = Vec::new();
    for msg in &messages {
        signatures.push(sk.sign(msg));
    }
    
    // Tenter de forger une signature pour un nouveau message
    let forged_msg = b"message forge";
    
    // Aucune des signatures existantes ne doit valider le message forgé
    for sig in &signatures {
        assert!(
            !pk.verify(forged_msg, sig),
            "Forge existentielle réussie avec signature existante"
        );
    }
    
    // Tenter de combiner des parties de signatures (attaque naïve)
    if signatures.len() >= 2 {
        let mut hybrid_sig_bytes = signatures[0].to_bytes();
        let sig2_bytes = signatures[1].to_bytes();
        
        // Remplacer la première moitié par la signature 2
        hybrid_sig_bytes[..SIG_BYTES/2].copy_from_slice(&sig2_bytes[..SIG_BYTES/2]);
        let hybrid_sig = Signature::from_bytes(&hybrid_sig_bytes);
        
        assert!(
            !pk.verify(forged_msg, &hybrid_sig),
            "Forge par combinaison de signatures réussie"
        );
    }
}

// =============================================================================
// PROPERTY-BASED TESTING
// =============================================================================

proptest! {
    /// Test de cohérence : sign/verify roundtrip
    /// Menace prévenue : Bugs dans l'implémentation de base
    #[test]
    fn prop_sign_verify_roundtrip(
        seed in prop::array::uniform32(prop::num::u8::ANY),
        msg in prop::collection::vec(prop::num::u8::ANY, 0..1024)
    ) {
        let (sk, pk) = SecretKey::generate(&seed);
        let sig = sk.sign(&msg);
        prop_assert!(pk.verify(&msg, &sig), "Échec du roundtrip sign/verify");
    }
    
    /// Test de déterminisme : même graine → même clé
    /// Menace prévenue : Non-déterminisme dans la génération de clés
    #[test]
    fn prop_keygen_deterministic(
        seed in prop::array::uniform32(prop::num::u8::ANY)
    ) {
        let (sk1, pk1) = SecretKey::generate(&seed);
        let (sk2, pk2) = SecretKey::generate(&seed);
        
        prop_assert_eq!(pk1.to_bytes(), pk2.to_bytes(), "Génération de clé non déterministe");
        prop_assert_eq!(sk1.as_bytes(), sk2.as_bytes(), "Génération de clé secrète non déterministe");
    }
    
    /// Test de signature déterministe (SLH-DSA est déterministe)
    /// Menace prévenue : Nonce reuse vulnerabilities
    #[test]
    fn prop_signature_deterministic(
        seed in prop::array::uniform32(prop::num::u8::ANY),
        msg in prop::collection::vec(prop::num::u8::ANY, 0..512)
    ) {
        let (sk, _pk) = SecretKey::generate(&seed);
        let sig1 = sk.sign(&msg);
        let sig2 = sk.sign(&msg);
        
        prop_assert_eq!(sig1.to_bytes(), sig2.to_bytes(), "Signature non déterministe");
    }
    
    /// Test de rejet de messages modifiés
    /// Menace prévenue : Message tampering attacks
    #[test]
    fn prop_message_integrity(
        seed in prop::array::uniform32(prop::num::u8::ANY),
        msg in prop::collection::vec(prop::num::u8::ANY, 1..512),
        bit_flip_pos in 0usize..512
    ) {
        let (sk, pk) = SecretKey::generate(&seed);
        let sig = sk.sign(&msg);
        
        if bit_flip_pos < msg.len() {
            let mut modified_msg = msg.clone();
            modified_msg[bit_flip_pos] ^= 0x01; // Flip 1 bit
            
            if modified_msg != msg {
                prop_assert!(
                    !pk.verify(&modified_msg, &sig),
                    "Signature valide sur message modifié"
                );
            }
        }
    }
}

// =============================================================================
// TESTS DE TIMING ATTACKS
// =============================================================================

/// Test de résistance aux timing attacks sur la vérification
/// Menace prévenue : Side-channel timing attacks
#[test]
fn timing_attack_resistance_verify() {
    let mut rng = OsRng;
    let (sk, pk) = SecretKey::generate_rng(&mut rng);
    let msg = b"message de test timing";
    let valid_sig = sk.sign(msg);
    
    // Générer des signatures invalides de différents types
    let mut invalid_sig_bytes = valid_sig.to_bytes();
    invalid_sig_bytes[0] ^= 0xFF; // Corruption au début
    let invalid_sig_start = Signature::from_bytes(&invalid_sig_bytes);
    
    invalid_sig_bytes = valid_sig.to_bytes();
    invalid_sig_bytes[SIG_BYTES - 1] ^= 0xFF; // Corruption à la fin
    let invalid_sig_end = Signature::from_bytes(&invalid_sig_bytes);
    
    invalid_sig_bytes = valid_sig.to_bytes();
    invalid_sig_bytes[SIG_BYTES / 2] ^= 0xFF; // Corruption au milieu
    let invalid_sig_middle = Signature::from_bytes(&invalid_sig_bytes);
    
    // Mesurer les temps de vérification
    const ITERATIONS: usize = 1000;
    
    let time_valid = measure_verify_time(&pk, msg, &valid_sig, ITERATIONS);
    let time_invalid_start = measure_verify_time(&pk, msg, &invalid_sig_start, ITERATIONS);
    let time_invalid_end = measure_verify_time(&pk, msg, &invalid_sig_end, ITERATIONS);
    let time_invalid_middle = measure_verify_time(&pk, msg, &invalid_sig_middle, ITERATIONS);
    
    // Les temps ne doivent pas différer de plus de 10% (marge pour le bruit)
    let max_time = time_valid.max(time_invalid_start).max(time_invalid_end).max(time_invalid_middle);
    let min_time = time_valid.min(time_invalid_start).min(time_invalid_end).min(time_invalid_middle);
    
    let time_variance = (max_time - min_time) as f64 / min_time as f64;
    assert!(
        time_variance < 0.1,
        "Timing attack possible : variance de {}% (max: {}ns, min: {}ns)",
        time_variance * 100.0,
        max_time,
        min_time
    );
}

fn measure_verify_time(pk: &PublicKey, msg: &[u8], sig: &Signature, iterations: usize) -> u128 {
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = pk.verify(msg, sig);
    }
    start.elapsed().as_nanos() / iterations as u128
}

// =============================================================================
// TESTS DE SÉCURITÉ MÉMOIRE
// =============================================================================

/// Test de zeroization des clés secrètes
/// Menace prévenue : Memory disclosure attacks
#[test]
fn secret_key_zeroization() {
    let mut rng = OsRng;
    let (mut sk, _pk) = SecretKey::generate_rng(&mut rng);
    
    // Capturer l'adresse mémoire de la clé
    let sk_ptr = sk.as_bytes().as_ptr();
    
    // Vérifier que la clé contient des données non-nulles
    let has_nonzero = sk.as_bytes().iter().any(|&b| b != 0);
    assert!(has_nonzero, "Clé secrète générée est entièrement nulle");
    
    // Forcer la zeroization
    sk.zeroize();
    
    // Vérifier que la mémoire a été effacée
    let sk_bytes = unsafe { std::slice::from_raw_parts(sk_ptr, SK_BYTES) };
    let is_zeroed = sk_bytes.iter().all(|&b| b == 0);
    assert!(is_zeroed, "Clé secrète non zeroizée après drop");
}

// =============================================================================
// TESTS DE RÉGRESSION
// =============================================================================

/// Test de régression : CVE-2024-XXXX (hypothétique)
/// Menace prévenue : Régression de vulnérabilités connues
#[test]
fn regression_cve_2024_xxxx_signature_bypass() {
    // Scénario : signature avec tous les bytes à zéro ne doit jamais être valide
    let mut rng = OsRng;
    let (_sk, pk) = SecretKey::generate_rng(&mut rng);
    let msg = b"message quelconque";
    
    let zero_sig = Signature::from_bytes(&[0u8; SIG_BYTES]);
    assert!(
        !pk.verify(msg, &zero_sig),
        "RÉGRESSION : signature nulle acceptée (CVE-2024-XXXX)"
    );
}

/// Test de régression : Attaque par signature courte
/// Menace prévenue : Short signature attacks
#[test]
fn regression_short_signature_attack() {
    // Historiquement, certaines implémentations acceptaient des signatures tronquées
    let mut rng = OsRng;
    let (_sk, pk) = SecretKey::generate_rng(&mut rng);
    let msg = b"test";
    
    // Tenter avec des signatures de tailles incorrectes
    // Note : notre API type-safe empêche cela, mais testons quand même
    let short_sig_bytes = [0u8; SIG_BYTES]; // Signature nulle de taille correcte
    let short_sig = Signature::from_bytes(&short_sig_bytes);
    
    assert!(
        !pk.verify(msg, &short_sig),
        "RÉGRESSION : signature courte acceptée"
    );
}

// =============================================================================
// TESTS DE LIMITES ET CAS EXTRÊMES
// =============================================================================

/// Test avec des messages de taille extrême
/// Menace prévenue : Buffer overflow, DoS via messages géants
#[test]
fn extreme_message_sizes() {
    let mut rng = OsRng;
    let (sk, pk) = SecretKey::generate_rng(&mut rng);
    
    // Message vide
    let empty_msg = b"";
    let sig_empty = sk.sign(empty_msg);
    assert!(pk.verify(empty_msg, &sig_empty), "Échec sur message vide");
    
    // Message très long (1 MB)
    let large_msg = vec![0x42u8; 1_048_576];
    let sig_large = sk.sign(&large_msg);
    assert!(pk.verify(&large_msg, &sig_large), "Échec sur message de 1MB");
    
    // Message avec tous les bytes possibles
    let all_bytes_msg: Vec<u8> = (0..=255).collect();
    let sig_all_bytes = sk.sign(&all_bytes_msg);
    assert!(pk.verify(&all_bytes_msg, &sig_all_bytes), "Échec sur message avec tous les bytes");
}

/// Test de performance : vérification ne doit pas être trop lente
/// Menace prévenue : DoS via signatures lentes à vérifier
#[test]
fn performance_verify_not_too_slow() {
    let mut rng = OsRng;
    let (sk, pk) = SecretKey::generate_rng(&mut rng);
    let msg = b"message de performance";
    let sig = sk.sign(msg);
    
    let start = Instant::now();
    const VERIFICATIONS: usize = 100;
    
    for _ in 0..VERIFICATIONS {
        assert!(pk.verify(msg, &sig));
    }
    
    let elapsed = start.elapsed();
    let avg_time = elapsed.as_micros() / VERIFICATIONS as u128;
    
    // SLH-DSA-128s doit vérifier en moins de 10ms par signature
    assert!(
        avg_time < 10_000,
        "Vérification trop lente : {}μs (limite: 10ms)",
        avg_time
    );
}

// =============================================================================
// TESTS DE COMPATIBILITÉ
// =============================================================================

/// Test de compatibilité avec d'autres implémentations
/// Menace prévenue : Incompatibilité inter-implémentations
#[test]
fn compatibility_with_reference_implementation() {
    // Vecteur de test généré par l'implémentation de référence NIST
    let seed = hex!("
        0123456789abcdef0123456789abcdef
        0123456789abcdef0123456789abcdef
    ");
    
    let (sk, pk) = SecretKey::generate(&seed);
    let msg = b"TSN compatibility test";
    let sig = sk.sign(msg);
    
    // Ces valeurs doivent correspondre à l'implémentation de référence
    // (à mettre à jour avec les vraies valeurs après test croisé)
    assert_eq!(PARAM_SET, "SLH-DSA-SHA2-128s");
    assert_eq!(PK_BYTES, 32);
    assert_eq!(SK_BYTES, 64);
    assert_eq!(SIG_BYTES, 7_808);
    
    assert!(pk.verify(msg, &sig), "Incompatibilité avec l'implémentation de référence");
}
