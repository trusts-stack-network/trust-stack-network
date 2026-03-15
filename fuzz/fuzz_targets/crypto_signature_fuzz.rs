#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::signature::{Signature, SignatureScheme};
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct SignatureInput {
    message: Vec<u8>,
    corrupted_sig: Vec<u8>,
    corrupted_pk: Vec<u8>,
}

fuzz_target!(|input: SignatureInput| {
    let scheme = SignatureScheme::new();
    
    // Génère une paire de clés valide
    let (pk, sk) = scheme.generate_keypair();
    
    // Test avec message fuzzé
    let _sig = scheme.sign(&sk, &input.message);
    
    // Test de vérification avec signature corrompue
    let corrupted_sig = Signature(input.corrupted_sig);
    let _ = scheme.verify(&pk, &input.message, &corrupted_sig);
    
    // Test avec clé publique corrompue
    let corrupted_pk = PublicKey(input.corrupted_pk);
    let _ = scheme.verify(&corrupted_pk, &input.message, &_sig);
    
    // Test de stress avec messages de tailles extrêmes
    let huge_message = vec![0u8; 10_000_000]; // 10MB
    let _ = std::panic::catch_unwind(|| {
        let _ = scheme.sign(&sk, &huge_message);
    });
});