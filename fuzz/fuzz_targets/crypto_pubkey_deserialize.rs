#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn::crypto::PublicKey;

/// Fuzzer pour la désérialisation de clé publique
/// Vérifie qu'on ne peut pas faire panic le parser avec des données invalides
fuzz_target!(|data: &[u8]| {
    // Test de désérialisation - ne doit pas panic
    let _ = PublicKey::from_bytes(data);
    
    // Test avec des préfixes connus pour bypasser des validations
    let mut prefixed_data = vec![0xFF, 0xFE, 0xFD];
    prefixed_data.extend_from_slice(data);
    let _ = PublicKey::from_bytes(&prefixed_data);
});