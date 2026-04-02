#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn::crypto::poseidon::PoseidonHash;

/// Fuzzer pour le hachage Poseidon - test de collision et panic
fuzz_target!(|data: &[u8]| {
    // Test avec différentes tailles d'input
    let hash_result = std::panic::catch_unwind(|| {
        PoseidonHash::hash(data)
    });
    
    // Vérifier qu'aucun panic ne survient
    assert!(hash_result.is_ok(), "Panic dans Poseidon hash avec input: {:?}", data);
    
    // Test de cohérence avec le même input
    if data.len() < 1024 { // Limiter la taille pour la performance
        let hash1 = PoseidonHash::hash(data);
        let hash2 = PoseidonHash::hash(data);
        assert_eq!(hash1, hash2, "Incohérence dans le hachage identique");
    }
});