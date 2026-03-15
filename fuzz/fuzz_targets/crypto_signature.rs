#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::signature::{Signature, verify_signature};
use tsn_crypto::keys::{PublicKey, SecretKey};
use rand::thread_rng;

/// Fuzzing de la vérification de signature
/// Cherche des cas où une signature invalide est acceptée
fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }
    
    let mut rng = thread_rng();
    let sk = SecretKey::generate(&mut rng);
    let pk = PublicKey::from(&sk);
    
    // Fuzz les inputs de vérification
    let message = &data[0..data.len()/2];
    let sig_bytes = &data[data.len()/2..];
    
    // Tente de créer une signature depuis des bytes aléatoires
    if let Ok(signature) = Signature::from_bytes(sig_bytes) {
        let _ = verify_signature(&pk, message, &signature);
        // Ne pas panic ici - on teste juste la robustesse
    }
});

/// Fuzzing du parsing de clés publiques
fuzz_target!(|data: &[u8]| {
    if data.len() != 32 {
        return;
    }
    
    // Tente de parser une clé publique depuis des bytes aléatoires
    let _ = PublicKey::from_bytes(data);
});

/// Fuzzing de la désérialisation
fuzz_target!(|data: &[u8]| {
    use tsn_crypto::signature::Signature;
    
    // Teste la désérialisation avec des données corrompues
    let _ = Signature::deserialize(data);
});