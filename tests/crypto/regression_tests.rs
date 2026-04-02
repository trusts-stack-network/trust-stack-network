/// Tests de régression pour les vulnérabilités corrigées
/// Chaque test vérifie qu'une vulnérabilité spécifique ne peut plus être exploitée

use tsn_crypto::signature::{Signature, verify_signature, constant_time_verify};
use tsn_crypto::keys::{PublicKey, SecretKey};
use tsn_crypto::address::Address;

/// RÉGRESSION-001: Vérifie que la timing attack sur signature est corrigée
#[test]
fn regression_signature_timing_attack() {
    let sk = SecretKey::generate(&mut OsRng);
    let pk = PublicKey::from(&sk);
    let message = b"regression test message";
    
    // Génère une signature valide
    let signature = sk.sign(message, &mut OsRng);
    
    // Test avec la version corrigée (constant-time)
    let iterations = 10000;
    let mut valid_times = Vec::with_capacity(iterations);
    let mut invalid_times = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        // Temps pour signature valide
        let start = std::time::Instant::now();
        assert!(constant_time_verify(&pk, message, &signature));
        valid_times.push(start.elapsed());
        
        // Temps pour signature invalide (premier octet modifi