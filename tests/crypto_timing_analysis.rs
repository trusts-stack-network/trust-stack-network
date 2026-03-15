// DISABLED: uses API/modules that no longer exist in current codebase
#![cfg(feature = "disabled_test")]
//! Tests d'analyse de timing pour détecter les fuites cryptographiques
//!
//! Ces tests utilisent des mesures statistiques pour détecter des différences
//! de timing qui pourraient révéler des informations cryptographiques.

use std::time::{Duration, Instant};
use tsn::crypto::pq::ml_dsa::{keygen_from_seed, sign, verify};
use tsn::crypto::poseidon::{poseidon_hash, bytes32_to_field};

/// Nombre d'échantillons pour l'analyse statistique
const TIMING_SAMPLES: usize = 1000;

/// Seuil de différence de timing considéré comme suspect (en nanosecondes)
const TIMING_THRESHOLD_NS: u64 = 1000;

#[test]
fn test_mldsa_verify_timing_consistency() {
    println!("🔍 Test de consistance timing ML-DSA verify()");
    
    // Générer une paire de clés de test
    let seed = [42u8; 32];
    let (sk, pk) = keygen_from_seed(&seed).expect("Keygen failed");
    
    let message = b"test message for timing analysis";
    let valid_signature = sign(&sk, message);
    
    // Créer une signature invalide (modifier un byte)
    let mut invalid_sig_bytes = valid_signature.as_bytes().to_vec();
    invalid_sig_bytes[0] = invalid_sig_bytes[0].wrapping_add(1);
    
    // Mesurer les timings pour signatures valides
    let mut valid_timings = Vec::with_capacity(TIMING_SAMPLES);
    for _ in 0..TIMING_SAMPLES {
        let start = Instant::now();
        let result = verify(&pk, message, &valid_signature);
        let duration = start.elapsed();
        
        assert!(result, "Signature valide rejetée");
        valid_timings.push(duration);
    }
    
    // Mesurer les timings pour signatures invalides
    // Note: On ne peut pas facilement créer une Signature invalide avec l'API actuelle
    // donc on teste avec un message modifié
    let modified_message = b"modified message for timing analysis";
    let mut invalid_timings = Vec::with_capacity(TIMING_SAMPLES);
    for _ in 0..TIMING_SAMPLES {
        let start = Instant::now();
        let result = verify(&pk, modified_message, &valid_signature);
        let duration = start.elapsed();
        
        assert!(!result, "Signature invalide acceptée");
        invalid_timings.push(duration);
    }
    
    // Analyser les statistiques de timing
    let valid_avg = average_duration(&valid_timings);
    let invalid_avg = average_duration(&invalid_timings);
    let valid_stddev = stddev_duration(&valid_timings, valid_avg);
    let invalid_stddev = stddev_duration(&invalid_timings, invalid_avg);
    
    println!("📊 Statistiques de timing:");
    println!("  Signatures valides   - Moyenne: {:?}, Écart-type: {:?}", valid_avg, valid_stddev);
    println!("  Signatures invalides - Moyenne: {:?}, Écart-type: {:?}", invalid_avg, invalid_stddev);
    
    // Calculer la différence de timing
    let timing_diff = if valid_avg > invalid_avg {
        valid_avg - invalid_avg
    } else {
        invalid_avg - valid_avg
    };
    
    println!("  Différence absolue: {:?}", timing_diff);
    
    // Vérifier que la différence n'est pas statistiquement significative
    let threshold = Duration::from_nanos(TIMING_THRESHOLD_NS);
    if timing_diff > threshold {
        panic!(
            "🚨 TIMING LEAK DÉTECTÉ! Différence: {:?} > seuil: {:?}. \
             Cela indique une possible fuite d'informations cryptographiques.",
            timing_diff, threshold
        );
    }
    
    // Test de Welch (approximation) pour vérifier la significativité statistique
    let welch_t = welch_t_test(&valid_timings, &invalid_timings);
    println!("  Statistique t de Welch: {:.3}", welch_t);
    
    // Seuil critique pour p < 0.05 (approximatif)
    if welch_t.abs() > 2.0 {
        println!("⚠️  ATTENTION: Différence statistiquement significative détectée (t = {:.3})", welch_t);
        println!("   Cela pourrait indiquer une fuite de timing subtile.");
    }
    
    println!("✅ Test de timing ML-DSA terminé");
}

#[test]
fn test_poseidon_hash_timing_consistency() {
    println!("🔍 Test de consistance timing Poseidon hash");
    
    // Préparer différents types d'inputs
    let field_zero = bytes32_to_field(&[0u8; 32]);
    let field_max = bytes32_to_field(&[0xFFu8; 32]);
    let field_random = bytes32_to_field(&[0x42u8; 32]);
    
    let test_cases = vec![
        ("zero", vec![field_zero]),
        ("max", vec![field_max]),
        ("random", vec![field_random]),
        ("multiple", vec![field_zero, field_max, field_random]),
    ];
    
    for (name, inputs) in test_cases {
        let mut timings = Vec::with_capacity(TIMING_SAMPLES);
        
        for _ in 0..TIMING_SAMPLES {
            let start = Instant::now();
            let _result = poseidon_hash(1, &inputs);
            let duration = start.elapsed();
            timings.push(duration);
        }
        
        let avg = average_duration(&timings);
        let stddev = stddev_duration(&timings, avg);
        
        println!("📊 Timing Poseidon '{}': Moyenne: {:?}, Écart-type: {:?}", name, avg, stddev);
        
        // Vérifier que les timings sont dans une plage raisonnable
        let max_expected = Duration::from_millis(10); // 10ms max pour un hash
        if avg > max_expected {
            panic!("🚨 PERFORMANCE DÉGRADÉE: Hash Poseidon trop lent: {:?} > {:?}", avg, max_expected);
        }
    }
    
    println!("✅ Test de timing Poseidon terminé");
}

#[test]
fn test_constant_time_operations() {
    println!("🔍 Test d'opérations en temps constant");
    
    // Test de comparaison en temps constant pour les clés
    let seed1 = [1u8; 32];
    let seed2 = [2u8; 32];
    
    let (sk1, pk1) = keygen_from_seed(&seed1).expect("Keygen 1 failed");
    let (sk2, pk2) = keygen_from_seed(&seed2).expect("Keygen 2 failed");
    
    let message = b"constant time test message";
    let sig1 = sign(&sk1, message);
    let sig2 = sign(&sk2, message);
    
    // Mesurer le timing de vérification avec la bonne clé vs mauvaise clé
    let mut correct_timings = Vec::with_capacity(TIMING_SAMPLES / 2);
    let mut incorrect_timings = Vec::with_capacity(TIMING_SAMPLES / 2);
    
    for _ in 0..TIMING_SAMPLES / 2 {
        // Vérification correcte
        let start = Instant::now();
        let result = verify(&pk1, message, &sig1);
        let duration = start.elapsed();
        assert!(result);
        correct_timings.push(duration);
        
        // Vérification incorrecte (mauvaise clé)
        let start = Instant::now();
        let result = verify(&pk2, message, &sig1);
        let duration = start.elapsed();
        assert!(!result);
        incorrect_timings.push(duration);
    }
    
    let correct_avg = average_duration(&correct_timings);
    let incorrect_avg = average_duration(&incorrect_timings);
    let timing_diff = if correct_avg > incorrect_avg {
        correct_avg - incorrect_avg
    } else {
        incorrect_avg - correct_avg
    };
    
    println!("📊 Timing vérification:");
    println!("  Clé correcte: {:?}", correct_avg);
    println!("  Clé incorrecte: {:?}", incorrect_avg);
    println!("  Différence: {:?}", timing_diff);
    
    let threshold = Duration::from_nanos(TIMING_THRESHOLD_NS);
    if timing_diff > threshold {
        panic!(
            "🚨 TIMING LEAK DÉTECTÉ dans la vérification! \
             Différence: {:?} > seuil: {:?}",
            timing_diff, threshold
        );
    }
    
    println!("✅ Test d'opérations en temps constant terminé");
}

// Fonctions utilitaires pour l'analyse statistique

fn average_duration(durations: &[Duration]) -> Duration {
    let total_nanos: u64 = durations.iter().map(|d| d.as_nanos() as u64).sum();
    Duration::from_nanos(total_nanos / durations.len() as u64)
}

fn stddev_duration(durations: &[Duration], mean: Duration) -> Duration {
    let mean_nanos = mean.as_nanos() as f64;
    let variance: f64 = durations
        .iter()
        .map(|d| {
            let diff = d.as_nanos() as f64 - mean_nanos;
            diff * diff
        })
        .sum::<f64>() / durations.len() as f64;
    
    Duration::from_nanos(variance.sqrt() as u64)
}

fn welch_t_test(sample1: &[Duration], sample2: &[Duration]) -> f64 {
    let mean1 = average_duration(sample1).as_nanos() as f64;
    let mean2 = average_duration(sample2).as_nanos() as f64;
    
    let var1 = variance_duration(sample1, Duration::from_nanos(mean1 as u64));
    let var2 = variance_duration(sample2, Duration::from_nanos(mean2 as u64));
    
    let n1 = sample1.len() as f64;
    let n2 = sample2.len() as f64;
    
    let pooled_se = ((var1 / n1) + (var2 / n2)).sqrt();
    
    if pooled_se == 0.0 {
        0.0
    } else {
        (mean1 - mean2) / pooled_se
    }
}

fn variance_duration(durations: &[Duration], mean: Duration) -> f64 {
    let mean_nanos = mean.as_nanos() as f64;
    durations
        .iter()
        .map(|d| {
            let diff = d.as_nanos() as f64 - mean_nanos;
            diff * diff
        })
        .sum::<f64>() / durations.len() as f64
}
