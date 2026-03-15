use tsn_crypto::signature::{Signature, verify_signature};
use tsn_crypto::keys::{PublicKey, SecretKey};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::thread_rng;

/// Test de résistance aux timing attacks sur la vérification de signature
/// VULNÉRABILITÉ: La comparaison actuelle n'est pas en constant-time
#[test]
fn test_signature_timing_attack_resistance() {
    let mut rng = thread_rng();
    let sk = SecretKey::generate(&mut rng);
    let pk = PublicKey::from(&sk);
    
    let message = b"message to sign";
    let signature = sk.sign(message, &mut rng);
    
    // Mesure le temps de vérification avec signature valide
    let start = std::time::Instant::now();
    for _ in 0..1000 {
        assert!(verify_signature(&pk, message, &signature));
    }
    let valid_time = start.elapsed();
    
    // Mesure le temps avec signature invalide (premier octet modifié)
    let mut bad_signature = signature.clone();
    bad_signature.0[0] ^= 0x01;
    
    let start = std::time::Instant::now();
    for _ in 0..1000 {
        assert!(!verify_signature(&pk, message, &bad_signature));
    }
    let invalid_time = start.elapsed();
    
    // Si les temps sont significativement différents, il y a une fuite temporelle
    let time_diff = if valid_time > invalid_time {
        valid_time - invalid_time
    } else {
        invalid_time - valid_time
    };
    
    // ÉCHEC: Cette assertion devrait passer mais échoue actuellement
    // Temps moyen par opération devrait être similaire (< 10% de différence)
    let avg_valid = valid_time / 1000;
    let avg_invalid = invalid_time / 1000;
    let diff_ratio = (time_diff.as_nanos() as f64) / (avg_valid.as_nanos() as f64);
    
    assert!(diff_ratio < 0.1, 
        "Timing attack détecté: différence de {}% entre valid/invalid", 
        diff_ratio * 100.0);
}

/// Test de constant-time comparison (implémentation corrigée)
#[test]
fn test_constant_time_comparison() {
    use tsn_crypto::utils::constant_time_eq;
    
    let a = [1u8; 32];
    let b = [1u8; 32];
    let c = [2u8; 32];
    
    // Devrait prendre le même temps peu importe le résultat
    let start = std::time::Instant::now();
    for _ in 0..10000 {
        assert!(constant_time_eq(&a, &b));
    }
    let eq_time = start.elapsed();
    
    let start = std::time::Instant::now();
    for _ in 0..10000 {
        assert!(!constant_time_eq(&a, &c));
    }
    let neq_time = start.elapsed();
    
    let time_diff = if eq_time > neq_time {
        eq_time - neq_time
    } else {
        neq_time - eq_time
    };
    
    // Différence devrait être négligeable (< 5%)
    let avg_eq = eq_time / 10000;
    let diff_ratio = (time_diff.as_nanos() as f64) / (avg_eq.as_nanos() as f64);
    
    assert!(diff_ratio < 0.05, 
        "Constant-time comparison échoue: différence de {}%", 
        diff_ratio * 100.0);
}