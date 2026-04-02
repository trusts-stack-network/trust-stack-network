//! Fuzzer pour les opérations de signature ML-DSA
//!
//! Ce fuzzer teste la robustesse des fonctions de signature et vérification
//! ML-DSA contre des inputs malformés et des attaques potentielles.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use tsn::crypto::pq::ml_dsa::{keygen_from_seed, sign, verify, PublicKey, SecretKey, Signature};

#[derive(Arbitrary, Debug)]
struct MLDSAFuzzInput {
    seed: [u8; 32],
    message: Vec<u8>,
    operation: FuzzOperation,
}

#[derive(Arbitrary, Debug)]
enum FuzzOperation {
    SignVerify,
    VerifyInvalidSignature { sig_bytes: Vec<u8> },
    VerifyInvalidPublicKey { pk_bytes: Vec<u8> },
    SignLargeMessage,
    VerifyWithWrongKey { wrong_seed: [u8; 32] },
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    
    if let Ok(input) = MLDSAFuzzInput::arbitrary(&mut u) {
        match input.operation {
            FuzzOperation::SignVerify => {
                fuzz_sign_verify(&input.seed, &input.message);
            }
            
            FuzzOperation::VerifyInvalidSignature { sig_bytes } => {
                fuzz_verify_invalid_signature(&input.seed, &input.message, &sig_bytes);
            }
            
            FuzzOperation::VerifyInvalidPublicKey { pk_bytes } => {
                fuzz_verify_invalid_public_key(&input.message, &pk_bytes);
            }
            
            FuzzOperation::SignLargeMessage => {
                // Créer un message très large pour tester les limites
                let large_message: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
                fuzz_sign_verify(&input.seed, &large_message);
            }
            
            FuzzOperation::VerifyWithWrongKey { wrong_seed } => {
                fuzz_verify_wrong_key(&input.seed, &wrong_seed, &input.message);
            }
        }
    }
});

fn fuzz_sign_verify(seed: &[u8; 32], message: &[u8]) {
    // Génération de clés ne doit jamais paniquer
    let keygen_result = std::panic::catch_unwind(|| {
        keygen_from_seed(seed)
    });
    
    let (sk, pk) = match keygen_result {
        Ok(Ok(keys)) => keys,
        Ok(Err(_)) => return, // Erreur de keygen, pas un panic
        Err(_) => panic!("keygen_from_seed a paniqué avec seed: {:?}", seed),
    };
    
    // Signature ne doit jamais paniquer
    let sign_result = std::panic::catch_unwind(|| {
        sign(&sk, message)
    });
    
    let signature = match sign_result {
        Ok(sig) => sig,
        Err(_) => panic!("sign a paniqué avec message de {} bytes", message.len()),
    };
    
    // Vérification ne doit jamais paniquer
    let verify_result = std::panic::catch_unwind(|| {
        verify(&pk, message, &signature)
    });
    
    let is_valid = match verify_result {
        Ok(valid) => valid,
        Err(_) => panic!("verify a paniqué"),
    };
    
    // Une signature valide doit toujours être vérifiée comme valide
    if !is_valid {
        panic!("Signature valide rejetée par verify()");
    }
}

fn fuzz_verify_invalid_signature(seed: &[u8; 32], message: &[u8], sig_bytes: &[u8]) {
    // Générer une clé valide
    let keygen_result = keygen_from_seed(seed);
    let (_sk, pk) = match keygen_result {
        Ok(keys) => keys,
        Err(_) => return, // Erreur de keygen
    };
    
    // Essayer de créer une signature à partir des bytes arbitraires
    // Note: On ne peut pas créer directement une Signature depuis des bytes
    // dans l'API actuelle, donc on teste indirectement
    
    // Créer une signature valide puis la modifier
    if !message.is_empty() {
        let valid_sig = sign(&_sk, message);
        
        // Tester la vérification avec un message différent (doit être false)
        let modified_message = if message.len() > 1 {
            let mut mod_msg = message.to_vec();
            mod_msg[0] = mod_msg[0].wrapping_add(1);
            mod_msg
        } else {
            vec![0u8]
        };
        
        let verify_result = std::panic::catch_unwind(|| {
            verify(&pk, &modified_message, &valid_sig)
        });
        
        match verify_result {
            Ok(false) => {}, // Attendu: signature invalide
            Ok(true) => panic!("Signature acceptée pour un message modifié!"),
            Err(_) => panic!("verify a paniqué avec message modifié"),
        }
    }
}

fn fuzz_verify_invalid_public_key(message: &[u8], pk_bytes: &[u8]) {
    // Tenter de créer une clé publique à partir de bytes arbitraires
    // Note: L'API actuelle ne permet pas de créer directement une PublicKey
    // depuis des bytes arbitraires, donc on teste la robustesse indirectement
    
    // Générer une clé valide pour avoir une signature valide
    let seed = [42u8; 32];
    if let Ok((sk, _pk)) = keygen_from_seed(&seed) {
        if !message.is_empty() {
            let signature = sign(&sk, message);
            
            // Générer une autre clé (différente) et tester la vérification
            let wrong_seed = [99u8; 32];
            if let Ok((_wrong_sk, wrong_pk)) = keygen_from_seed(&wrong_seed) {
                let verify_result = std::panic::catch_unwind(|| {
                    verify(&wrong_pk, message, &signature)
                });
                
                match verify_result {
                    Ok(false) => {}, // Attendu: signature invalide avec mauvaise clé
                    Ok(true) => panic!("Signature acceptée avec une mauvaise clé publique!"),
                    Err(_) => panic!("verify a paniqué avec une clé publique différente"),
                }
            }
        }
    }
}

fn fuzz_verify_wrong_key(correct_seed: &[u8; 32], wrong_seed: &[u8; 32], message: &[u8]) {
    // Générer deux paires de clés différentes
    let correct_keys = keygen_from_seed(correct_seed);
    let wrong_keys = keygen_from_seed(wrong_seed);
    
    if let (Ok((sk, _pk)), Ok((_wrong_sk, wrong_pk))) = (correct_keys, wrong_keys) {
        if !message.is_empty() {
            // Signer avec la bonne clé
            let signature = sign(&sk, message);
            
            // Vérifier avec la mauvaise clé (doit être false)
            let verify_result = std::panic::catch_unwind(|| {
                verify(&wrong_pk, message, &signature)
            });
            
            match verify_result {
                Ok(false) => {}, // Attendu
                Ok(true) => {
                    // Vérifier que les clés sont vraiment différentes
                    if correct_seed != wrong_seed {
                        panic!("Signature acceptée avec une clé différente!");
                    }
                }
                Err(_) => panic!("verify a paniqué lors du test de clé incorrecte"),
            }
        }
    }
}