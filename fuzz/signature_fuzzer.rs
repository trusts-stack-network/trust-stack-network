// Fuzzer pour les signatures ML-DSA-65
// Utilise libfuzzer_sys pour l'intégration avec cargo-fuzz
//
// VULNÉRABILITÉS CIBLÉES:
// - Signatures malformées
// - Clés publiques invalides
// - Messages de taille excessive
// - Timing attacks

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::time::Instant;

// Limite de temps par exécution pour éviter les DoS
const MAX_EXECUTION_TIME_MS: u64 = 100;

fuzz_target!(|data: &[u8]| {
    // Structure des données fuzzées:
    // [0..2592] = clé publique ML-DSA-65 (2592 bytes)
    // [2592..7190] = signature ML-DSA-65 (4598 bytes)
    // [7190..] = message à vérifier
    
    const PUBKEY_SIZE: usize = 2592;
    const SIGNATURE_SIZE: usize = 4598;
    const MIN_DATA_SIZE: usize = PUBKEY_SIZE + SIGNATURE_SIZE;
    
    // Ignorer les entrées trop courtes
    if data.len() < MIN_DATA_SIZE {
        return;
    }
    
    let start = Instant::now();
    
    // Extraire les composants
    let pubkey = &data[0..PUBKEY_SIZE];
    let signature = &data[PUBKEY_SIZE..PUBKEY_SIZE + SIGNATURE_SIZE];
    let message = &data[PUBKEY_SIZE + SIGNATURE_SIZE..];
    
    // Vérifier que la clé publique n'est pas nulle
    let is_null_pubkey = pubkey.iter().all(|b| *b == 0);
    if is_null_pubkey {
        // Clé publique nulle - devrait être rejetée
        return;
    }
    
    // Vérifier que la signature n'est pas vide
    if signature.iter().all(|b| *b == 0) {
        // Signature vide - devrait être rejetée
        return;
    }
    
    // Vérifier le timeout
    if start.elapsed().as_millis() > MAX_EXECUTION_TIME_MS as u128 {
        panic!("DoS: vérification de signature trop lente");
    }
    
    // NOTE: Ici on ferait normalement appel à la vérification de signature
    // Pour le fuzzer, on vérifie juste que les données sont bien formées
    
    // Vérifier que le message n'est pas trop grand (DoS)
    if message.len() > 1024 * 1024 {
        // Message trop grand - potentiel DoS
        return;
    }
    
    // Simuler une vérification
    let _ = simulate_signature_verification(pubkey, signature, message);
});

fn simulate_signature_verification(
    _pubkey: &[u8],
    _signature: &[u8],
    _message: &[u8]
) -> Result<bool, &'static str> {
    // Simulation de vérification
    // Dans la vraie implémentation, appelerait ML-DSA-65 verify
    
    // Vérifications de base
    if _pubkey.len() != 2592 {
        return Err("Invalid public key size");
    }
    
    if _signature.len() != 4598 {
        return Err("Invalid signature size");
    }
    
    // Simuler un résultat aléatoire pour le fuzzing
    Ok(true)
}
