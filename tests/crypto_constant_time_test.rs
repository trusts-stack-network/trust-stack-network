// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
use tsn_crypto::commitment::Commitment;
use tsn_crypto::nullifier::Nullifier;
use tsn_crypto::keys::{PublicKey, SecretKey};
use subtle::{Choice, ConstantTimeEq};
use proptest::prelude::*;
use std::time::{Duration, Instant};
use std::thread;

/// Test property-based pour vérifier la constant-time property
/// Temps d'exécution doit être indépendant des valeurs
proptest! {
    #[test]
    fn commitment_verify_timing_independent(
        a: [u8; 32],
        b: [u8; 32],
        c: [u8; 32],
        d: [u8; 32]
    ) {
        let comm1 = Commitment::new(a);
        let comm2 = Commitment::new(b);
        let comm3 = Commitment::new(c);
        let comm4 = Commitment::new(d);
        
        // Mesure temps vérification paires égales
        let start = Instant::now();
        let _ = comm1.verify(&comm2);
        let duration_equal = start.elapsed();
        
        // Mesure temps vérification paires différentes
        let start = Instant::now();
        let _ = comm3.verify(&comm4);
        let duration_different = start.elapsed();
        
        // Différence de temps doit être négligeable (< 10%)
        let diff = if duration_equal > duration_different {
            duration_equal - duration_different
        } else {
            duration_different - duration_equal
        };
        
        prop_assert!(diff.as_nanos() < (duration_equal.as_nanos() / 10));
    }
    
    #[test]
    fn nullifier_equality_timing_independent(
        n1: [u8; 32],
        n2: [u8; 32]
    ) {
        let null1 = Nullifier::from_bytes(n1);
        let null2 = Nullifier::from_bytes(n2);
        
        // Test timing equality
        let start = Instant::now();
        let _ = null1.ct_eq(&null2);
        let duration = start.elapsed();
        
        // Timing doit être stable sur 100 itérations
        let mut timings = Vec::new();
        for _ in 0..100 {
            let start = Instant::now();
            let _ = null1.ct_eq(&null2);
            timings.push(start.elapsed());
        }
        
        // Vérification variance minimale
        let avg = timings.iter().sum::<Duration>() / timings.len() as u32;
        let variance = timings.iter()
            .map(|t| t.as_nanos() as i128 - avg.as_nanos() as i128)
            .map(|v| v * v)
            .sum::<i128>() / timings.len() as i128;
            
        prop_assert!(variance < 1000); // Variance très faible
    }
}

/// Test de regression pour timing attack sur commitments
#[test]
fn test_commitment_timing_regression() {
    let secret1 = [0x42u8; 32];
    let secret2 = [0x43u8; 32];
    
    let comm1 = Commitment::new(secret1);
    let comm2 = Commitment::new(secret2);
    
    // Mesure de base
    let baseline = measure_verify_timing(&comm1, &comm2, 1000);
    
    // Test avec valeurs proches (risque de leak)
    let mut similar = [0x42u8; 32];
    similar[31] = 0x44;
    let comm_similar = Commitment::new(similar);
    
    let timing = measure_verify_timing(&comm1, &comm_similar, 1000);
    
    // Écart doit être < 5% (const-time)
    let diff = (timing.as_nanos() as f64 - baseline.as_nanos() as f64).abs();
    let pct = diff / baseline.as_nanos() as f64;
    
    assert!(pct < 0.05, "Timing variance too high: {}%", pct * 100.0);
}

fn measure_verify_timing(comm1: &Commitment, comm2: &Commitment, iterations: u32) -> Duration {
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = comm1.verify(comm2);
    }
    start.elapsed()
}
