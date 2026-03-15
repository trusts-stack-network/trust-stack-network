use tsn::crypto::keys::{SecretKey, PublicKey};
use tsn::crypto::address::Address;
use proptest::prelude::*;
use std::time::Instant;

/// Test constant-time key derivation
#[test]
fn test_key_generation_timing() {
    let iterations = 1000;
    let mut timings = Vec::with_capacity(iterations);
    
    for i in 0..iterations {
        let start = Instant::now();
        let sk = SecretKey::generate();
        let _pk = sk.public_key();
        let _addr = Address::from_public_key(&_pk);
        timings.push(start.elapsed());
    }
    
    // Check timing variance (should be low for constant-time)
    let mean = timings.iter().sum::<Duration>() / timings.len() as u32;
    let variance = timings.iter()
        .map(|t| {
            let diff = t.as_nanos() as i128 - mean.as_nanos() as i128;
            (diff * diff) as f64
        })
        .sum::<f64>() / timings.len() as f64;
    
    let std_dev = variance.sqrt();
    let cv = std_dev / mean.as_nanos() as f64;
    
    assert!(cv < 0.1, "Key generation not constant-time: CV = {}", cv);
}

proptest! {
    #[test]
    fn test_key_derivation_consistency(
        seed in prop::collection::vec(any::<u8>(), 32..64)
    ) {
        // Derive key from seed should be deterministic
        let sk1 = SecretKey::from_seed(&seed);
        let sk2 = SecretKey::from_seed(&seed);
        
        prop_assert_eq!(sk1.to_bytes(), sk2.to_bytes());
        
        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();
        
        prop_assert_eq!(pk1.to_bytes(), pk2.to_bytes());
    }
}

/// Test for side-channel leakage in key serialization
#[test]
fn test_key_serialization_constant_time() {
    let sk = SecretKey::generate();
    let iterations = 1000;
    
    // Time serialization with different key values
    let mut timings = Vec::new();
    for _ in 0..iterations {
        let sk = SecretKey::generate();
        let start = Instant::now();
        let _bytes = sk.to_bytes();
        timings.push(start.elapsed());
    }
    
    // All timings should be similar (constant-time)
    let first = timings[0];
    for (i, &t) in timings.iter().enumerate().skip(1) {
        let diff = if t > first { t - first } else { first - t };
        assert!(diff.as_nanos() < 1000, "Serialization timing leak at iteration {}", i);
    }
}