// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
use tsn_crypto::{Signature, PublicKey, Commitment, Nullifier};
use std::time::{Instant, Duration};
use rand::thread_rng;

#[test]
fn test_signature_comparison_timing_attack() {
    // Test de timing attack sur la vérification de signature
    let mut rng = thread_rng();
    let msg = b"test message";
    
    // Génération d'une paire de clés valide
    let (pk, sk) = tsn_crypto::generate_keypair(&mut rng).unwrap();
    let valid_sig = tsn_crypto::sign(&sk, msg, &mut rng).unwrap();
    
    // Test avec une signature modifiée
    let mut invalid_sig = valid_sig.clone();
    invalid_sig.0[0] ^= 0x01; // Flip un bit
    
    // Mesure du temps de vérification
    let iterations = 1000;
    let mut valid_times = Vec::with_capacity(iterations);
    let mut invalid_times = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        // Test signature valide
        let start = Instant::now();
        let _ = tsn_crypto::verify(&pk, msg, &valid_sig);
        valid_times.push(start.elapsed());
        
        // Test signature invalide
        let start = Instant::now();
        let _ = tsn_crypto::verify(&pk, msg, &invalid_sig);
        invalid_times.push(start.elapsed());
    }
    
    let valid_avg: Duration = valid_times.iter().sum::<Duration>() / iterations as u32;
    let invalid_avg: Duration = invalid_times.iter().sum::<Duration>() / iterations as u32;
    
    // Si la différence est significative (>10%), c'est une vulnérabilité
    let diff_pct = ((valid_avg.as_nanos() as f64 - invalid_avg.as_nanos() as f64).abs() 
                    / valid_avg.as_nanos() as f64) * 100.0;
    
    assert!(diff_pct < 5.0, "Possible timing attack: {}% difference", diff_pct);
}

#[test]
fn test_commitment_equality_timing() {
    let mut rng = thread_rng();
    let value1 = [1u8; 32];
    let value2 = [2u8; 32];
    let blinding = [3u8; 32];
    
    let comm1 = Commitment::new(&value1, &blinding);
    let comm2 = Commitment::new(&value2, &blinding);
    
    // Test comparaison constant-time
    let iterations = 1000;
    let mut equal_times = Vec::new();
    let mut diff_times = Vec::new();
    
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = comm1 == comm1;
        equal_times.push(start.elapsed());
        
        let start = Instant::now();
        let _ = comm1 == comm2;
        diff_times.push(start.elapsed());
    }
    
    let equal_avg = equal_times.iter().sum::<Duration>() / iterations as u32;
    let diff_avg = diff_times.iter().sum::<Duration>() / iterations as u32;
    
    let diff_pct = ((equal_avg.as_nanos() as f64 - diff_avg.as_nanos() as f64).abs() 
                    / equal_avg.as_nanos() as f64) * 100.0;
    
    assert!(diff_pct < 5.0, "Commitment comparison not constant-time: {}%", diff_pct);
}
