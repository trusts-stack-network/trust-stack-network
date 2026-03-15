use tsn_crypto::pq::{MLDSA65Signature, MLDSA65PublicKey};
use rand::thread_rng;
use wycheproof::{TestFlag, TestGroup, TestSet};

#[test]
fn test_mldsa65_wycheproof_vectors() {
    // Test contre les vecteurs de test Wycheproof connus
    let test_set = TestSet::load(MLDSA65_TEST_VECTORS)
        .expect("Failed to load test vectors");
    
    for group in test_set.groups {
        for test in group.tests {
            let pk = MLDSA65PublicKey::from_bytes(&test.pk)
                .expect("Invalid public key");
            let sig = MLDSA65Signature::from_bytes(&test.sig)
                .expect("Invalid signature");
            
            let result = verify_mldsa65(&pk, &test.msg, &sig);
            
            match test.result {
                TestFlag::Valid => assert!(result, "Signature valide rejetée"),
                TestFlag::Invalid => assert!(!result, "Signature invalide acceptée"),
                TestFlag::Acceptable => {
                    // Acceptable signifie qu'on peut accepter ou rejeter
                    // On doit être constant-time peu importe
                    let _ = black_box(result);
                }
            }
        }
    }
}

#[test]
fn test_mldsa65_fault_injection() {
    // Test la résistance aux fault injections
    let mut rng = thread_rng();
    let msg = b"test message";
    
    let (pk, sk) = generate_mldsa65_keypair(&mut rng);
    
    // Signe normalement
    let sig = sk.sign(msg);
    assert!(verify_mldsa65(&pk, msg, &sig));
    
    // Corrompt un bit de la signature
    let mut corrupted_sig = sig.to_bytes();
    corrupted_sig[10] ^= 0x01;
    let corrupted_sig = MLDSA65Signature::from_bytes(&corrupted_sig)
        .expect("Signature corrompue invalide");
    
    assert!(!verify_mldsa65(&pk, msg, &corrupted_sig));
}