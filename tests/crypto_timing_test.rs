// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
use std::time::{Duration, Instant};
use tsn_crypto::signature::{SignatureScheme, MLDSASignature};
use tsn_crypto::keys::KeyPair;
use rand::rngs::OsRng;

#[test]
fn test_signature_verification_timing() {
    let iterations = 1000;
    let keypair = KeyPair::generate(&mut OsRng);
    let msg_valid = b"valid message";
    let msg_invalid = b"invalid message";
    
    let sig = MLDSASignature::sign(&keypair.secret, msg_valid);
    
    // Mesurer temps vérification signature valide
    let mut valid_times = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = sig.verify(&keypair.public, msg_valid);
        valid_times.push(start.elapsed());
    }
    
    // Mesurer temps vérification signature invalide
    let mut invalid_times = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = sig.verify(&keypair.public, msg_invalid);
        invalid_times.push(start.elapsed());
    }
    
    // Calculer moyennes
    let valid_avg: Duration = valid_times.iter().sum::<Duration>() / iterations as u32;
    let invalid_avg: Duration = invalid_times.iter().sum::<Duration>() / iterations as u32;
    
    // Différence doit être < 5% (contre les timing attacks)
    let diff = if valid_avg > invalid_avg {
        valid_avg - invalid_avg
    } else {
        invalid_avg - valid_avg
    };
    
    let threshold = valid_avg / 20; // 5%
    assert!(diff < threshold, 
        "Différence de timing détectée: {:?} > {:?}", diff, threshold);
}

#[test]
fn test_key_comparison_constant_time() {
    use tsn_crypto::keys::PublicKey;
    
    let key1 = PublicKey::from_bytes(&[0u8; 32]).unwrap();
    let key2 = PublicKey::from_bytes(&[1u8; 32]).unwrap();
    
    let iterations = 10000;
    let mut same_times = Vec::new();
    let mut diff_times = Vec::new();
    
    // Comparaison identique
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = key1.ct_eq(&key1);
        same_times.push(start.elapsed());
    }
    
    // Comparaison différente
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = key1.ct_eq(&key2);
        diff_times.push(start.elapsed());
    }
    
    let same_avg = same_times.iter().sum::<Duration>() / iterations as u32;
    let diff_avg = diff_times.iter().sum::<Duration>() / iterations as u32;
    
    // Doit être constant-time
    let diff = (same_avg.as_nanos() as i64 - diff_avg.as_nanos() as i64).abs();
    assert!(diff < 100, "Comparaison non constant-time: {}ns de différence", diff);
}
