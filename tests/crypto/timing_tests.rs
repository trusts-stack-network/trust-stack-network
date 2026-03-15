use std::time::{Duration, Instant};
use rand::{Rng, thread_rng};
use subtle::ConstantTimeEq;

/// Test que la comparaison de signatures est constant-time
#[test]
fn test_signature_comparison_constant_time() {
    use tsn_crypto::signature::Signature;
    
    let sig1 = Signature::from_bytes(&[0u8; 64]);
    let sig2 = Signature::from_bytes(&[0u8; 64]);
    let sig3 = Signature::from_bytes(&[1u8; 64]);
    
    // Mesurer le temps pour différentes comparaisons
    let iterations = 1000;
    let mut times_equal = Vec::with_capacity(iterations);
    let mut times_different = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = sig1.ct_eq(&sig2);
        times_equal.push(start.elapsed());
        
        let start = Instant::now();
        let _ = sig1.ct_eq(&sig3);
        times_different.push(start.elapsed());
    }
    
    // Calculer les statistiques
    let avg_equal = times_equal.iter().sum::<Duration>() / iterations as u32;
    let avg_different = times_different.iter().sum::<Duration>() / iterations as u32;
    
    // Le temps devrait être statistiquement similaire (±10%)
    let diff = if avg_equal > avg_different {
        (avg_equal - avg_different).as_nanos() as f64 / avg_equal.as_nanos() as f64
    } else {
        (avg_different - avg_equal).as_nanos() as f64 / avg_different.as_nanos() as f64
    };
    
    assert!(diff < 0.1, "Comparaison non constant-time détectée: {}% de différence", diff * 100.0);
}

/// Test de resistance aux timing attacks sur la vérification de preuve
#[test]
fn test_proof_verification_timing() {
    use tsn_crypto::proof::Proof;
    use tsn_crypto::keys::PublicKey;
    
    let valid_proof = Proof::generate_valid();
    let invalid_proof = Proof::generate_invalid();
    let pubkey = PublicKey::generate();
    
    let iterations = 100;
    let mut valid_times = Vec::with_capacity(iterations);
    let mut invalid_times = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = valid_proof.verify(&pubkey);
        valid_times.push(start.elapsed());
        
        let start = Instant::now();
        let _ = invalid_proof.verify(&pubkey);
        invalid_times.push(start.elapsed());
    }
    
    // Analyse statistique pour détecter des fuites temporelles
    let valid_avg = valid_times.iter().sum::<Duration>() / iterations as u32;
    let invalid_avg = invalid_times.iter().sum::<Duration>() / iterations as u32;
    
    println!("Valid proof verification avg: {:?}", valid_avg);
    println!("Invalid proof verification avg: {:?}", invalid_avg);
    
    // Log si différence significative détectée
    let time_diff = if valid_avg > invalid_avg {
        valid_avg - invalid_avg
    } else {
        invalid_avg - valid_avg
    };
    
    if time_diff > Duration::from_micros(10) {
        eprintln!("ATTENTION: Différence de timing significative détectée: {:?}", time_diff);
    }
}