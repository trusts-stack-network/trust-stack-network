#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn::crypto::Signature;

/// Fuzzer pour la désérialisation de signature
/// Cherche des panics lors de la désérialisation de données malformées
fuzz_target!(|data: &[u8]| {
    // Ne doit jamais panic, même avec des données aléatoires
    let _ = Signature::from_bytes(data);
    
    // Test aussi avec des tailles spécifiques qui causent souvent des problèmes
    if data.len() == 64 || data.len() == 32 {
        let _ = Signature::from_bytes(data);
    }
});