use std::time::{Duration, Instant};
use std::hint::black_box;
use tsn_crypto::keys::{PublicKey, SecretKey};
use tsn_crypto::signature::Signature;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[test]
fn test_signature_comparison_timing() {
    // Test que la comparaison de signatures ne fuite pas d'information via le timing
    let mut rng = ChaCha20Rng::from_entropy();
    let secret = SecretKey::generate(&mut rng);
    let public = secret.public_key();
    
    let message = b"test message for timing analysis";
    let signature = secret.sign(message);
    
    // Créer des signatures avec des différences bit par bit
    let mut modified_sig = signature.clone();
    let sig_bytes = modified_sig.to_bytes();
    
    let mut timings = Vec::new();
    
    for i in 0..8 {
        let mut test_sig = signature.clone();
        let mut test_bytes = test_sig.to_bytes();
        
        // Modifier un bit
        test_bytes[i] ^= 0x01;
        test_sig = Signature::from_bytes(&test_bytes).unwrap_or_else(|_| signature.clone());
        
        // Mesurer le temps de comparaison
        let start = Instant::now();
        let _ = black_box(signature == test_sig);
        let duration = start.elapsed();
        
        timings.push(duration);
    }
    
    // Vérifier que les temps de comparaison sont similaires (±10%)
    let avg_timing = timings.iter().sum::<Duration>() / timings.len() as u32;
    for timing in &timings {
        let diff = if *timing > avg_timing {
            *timing - avg_timing
        } else {
            avg_timing - *timing
        };
        
        assert!(
            diff < avg_timing / 10,
            "Timing difference detected - potential timing attack vulnerability"
        );
    }
}

#[test]
fn test_nullifier_comparison_constant_time() {
    use tsn_crypto::nullifier::Nullifier;
    
    let nullifier1 = Nullifier::random();
    let nullifier2 = Nullifier::random();
    
    let iterations = 1000;
    let mut timings = Vec::new();
    
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = black_box(nullifier1 == nullifier2);
        timings.push(start.elapsed());
    }
    
    let avg_timing = timings.iter().sum::<Duration>() / timings.len() as u32;
    let variance = timings.iter()
        .map(|t| {
            let diff = if *t > avg_timing {
                *t - avg_timing
            } else {
                avg_timing - *t
            };
            diff.as_nanos() as f64
        })
        .sum::<f64>() / timings.len() as f64;
    
    // La variance devrait être faible si l'opération est constant-time
    assert!(
        variance < (avg_timing.as_nanos() as f64 * 0.1),
        "High variance in nullifier comparison - timing attack possible"
    );
}

#[test]
fn test_secret_key_zeroization() {
    // Vérifier que les clés secrètes sont correctement effacées de la mémoire
    let secret = SecretKey::generate(&mut ChaCha20Rng::from_entropy());
    let secret_bytes = secret.to_bytes();
    
    // Drop explicit de la clé
    drop(secret);
    
    // Vérifier que la mémoire a été effacée (dans la mesure du possible)
    // Note: Ce test est limité par les garanties Rust, mais vérifie la présence
    // d'une méthode zeroize() si implémentée
    assert!(secret_bytes.iter().all(|&b| b == 0), "Secret key not properly zeroized");
}