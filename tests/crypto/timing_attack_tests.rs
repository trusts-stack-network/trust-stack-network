use std::time::{Instant, Duration};
use rand::{Rng, thread_rng};
use tsn_crypto::signature::{SignatureScheme, verify_signature_constant_time};
use tsn_crypto::keys::{PublicKey, SecretKey};

#[test]
fn test_signature_timing_independence() {
    let mut rng = thread_rng();
    let message = b"test message for timing analysis";
    
    // Générer plusieurs paires de clés
    let keypairs: Vec<_> = (0..100)
        .map(|_| {
            let sk = SecretKey::generate(&mut rng);
            let pk = sk.public_key();
            (sk, pk)
        })
        .collect();
    
    // Mesurer le temps de vérification pour différentes signatures
    let mut timings = Vec::new();
    
    for (sk, pk) in &keypairs {
        let sig = sk.sign(message);
        
        // Test avec signature valide
        let start = Instant::now();
        let result1 = verify_signature_constant_time(&pk, message, &sig);
        let duration1 = start.elapsed();
        
        // Test avec signature modifiée (doit échouer en temps constant)
        let mut invalid_sig = sig.clone();
        invalid_sig.0[0] ^= 0x01;
        
        let start = Instant::now();
        let result2 = verify_signature_constant_time(&pk, message, &invalid_sig);
        let duration2 = start.elapsed();
        
        assert!(result1.is_ok());
        assert!(result2.is_err());
        
        // Vérifier que les temps sont similaires (±10%)
        let ratio = duration1.as_nanos() as f64 / duration2.as_nanos() as f64;
        assert!(ratio > 0.9 && ratio < 1.1, 
                "Timing leak detected: ratio = {}", ratio);
        
        timings.push((duration1, duration2));
    }
    
    // Analyse statistique des timings
    let valid_times: Vec<_> = timings.iter().map(|(v, _)| v.as_nanos()).collect();
    let invalid_times: Vec<_> = timings.iter().map(|(_, i)| i.as_nanos()).collect();
    
    // Test de variance - doit être similaire
    let valid_var = statistical_variance(&valid_times);
    let invalid_var = statistical_variance(&invalid_times);
    
    let variance_ratio = valid_var / invalid_var;
    assert!(variance_ratio > 0.5 && variance_ratio < 2.0,
            "Variance ratio indicates timing attack vulnerability: {}", variance_ratio);
}

fn statistical_variance(samples: &[u128]) -> f64 {
    let mean = samples.iter().sum::<u128>() as f64 / samples.len() as f64;
    let variance = samples.iter()
        .map(|x| (*x as f64 - mean).powi(2))
        .sum::<f64>() / samples.len() as f64;
    variance
}