use tsn::crypto::signature::{Signature, verify_signature};
use tsn::crypto::keys::{PublicKey, SecretKey};
use proptest::prelude::*;
use std::time::{Instant, Duration};
use subtle::ConstantTimeEq;

/// Test constant-time properties of signature verification
#[test]
fn test_signature_verification_timing() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let message = b"test message";
    
    let valid_sig = sk.sign(message);
    let invalid_sig = Signature::from_bytes(&[0u8; 64]).unwrap();
    
    // Measure timing for valid signature
    let start = Instant::now();
    for _ in 0..1000 {
        let _ = verify_signature(&pk, message, &valid_sig);
    }
    let valid_time = start.elapsed();
    
    // Measure timing for invalid signature
    let start = Instant::now();
    for _ in 0..1000 {
        let _ = verify_signature(&pk, message, &invalid_sig);
    }
    let invalid_time = start.elapsed();
    
    // Timing difference should be < 5% (constant-time)
    let diff = if valid_time > invalid_time {
        (valid_time - invalid_time).as_nanos() as f64 / valid_time.as_nanos() as f64
    } else {
        (invalid_time - valid_time).as_nanos() as f64 / invalid_time.as_nanos() as f64
    };
    
    assert!(diff < 0.05, "Signature verification not constant-time: {}% difference", diff * 100.0);
}

proptest! {
    #[test]
    fn test_signature_malleability(
        message in prop::collection::vec(any::<u8>(), 0..1024),
        tweak in any::<u8>()
    ) {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let mut sig = sk.sign(&message);
        
        // Try to malleate signature
        let mut sig_bytes = sig.to_bytes();
        sig_bytes[63] ^= tweak;
        let malleated_sig = Signature::from_bytes(&sig_bytes).unwrap_or(sig);
        
        // Malleated signature should not verify
        prop_assert!(!verify_signature(&pk, &message, &malleated_sig));
    }
}

/// Test for signature replay attacks
#[test]
fn test_signature_replay_protection() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let message1 = b"message1";
    let message2 = b"message2";
    
    let sig1 = sk.sign(message1);
    let sig2 = sk.sign(message2);
    
    // Cross-validation should fail
    assert!(!verify_signature(&pk, message2, &sig1));
    assert!(!verify_signature(&pk, message1, &sig2));
}