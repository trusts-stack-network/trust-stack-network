// Fuzzer pour les preuves ZK (Groth16/Plonky2)
// Utilise libfuzzer_sys pour l'intégration avec cargo-fuzz
//
// VULNÉRABILITÉS CIBLÉES:
// - Preuves malformées
// - unwrap_or_default() masquant les erreurs
// - Preuves de taille excessive (DoS)
// - Public inputs invalides

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::time::Instant;

// Limite de temps par exécution pour éviter les DoS
const MAX_EXECUTION_TIME_MS: u64 = 100;
// Taille maximale de preuve (1MB)
const MAX_PROOF_SIZE: usize = 1024 * 1024;
// Taille minimale de preuve (100 bytes)
const MIN_PROOF_SIZE: usize = 100;

fuzz_target!(|data: &[u8]| {
    // Structure des données fuzzées:
    // [0..4] = type de preuve (0 = Groth16, 1 = Plonky2)
    // [4..8] = taille de la preuve (u32 LE)
    // [8..8+proof_size] = données de la preuve
    // [8+proof_size..] = public inputs
    
    if data.len() < 8 {
        return;
    }
    
    let start = Instant::now();
    
    // Extraire le type de preuve
    let proof_type = data[0];
    
    // Extraire la taille de la preuve
    let proof_size = u32::from_le_bytes([
        data[4], data[5], data[6], data[7]
    ]) as usize;
    
    // Vérifier que la taille est raisonnable
    if proof_size < MIN_PROOF_SIZE || proof_size > MAX_PROOF_SIZE {
        // Taille invalide - devrait être rejetée
        return;
    }
    
    // Vérifier que les données sont suffisantes
    let total_size = 8 + proof_size;
    if data.len() < total_size {
        return;
    }
    
    // Extraire la preuve
    let proof = &data[8..8 + proof_size];
    
    // Extraire les public inputs
    let public_inputs = &data[total_size..];
    
    // Vérifier que la preuve n'est pas vide
    if proof.is_empty() {
        return;
    }
    
    // Vérifier que la preuve n'est pas composée uniquement de zéros
    // (preuve triviale qui pourrait passer)
    let is_all_zeros = proof.iter().all(|b| *b == 0);
    if is_all_zeros {
        // Preuve triviale - devrait être rejetée
        return;
    }
    
    // Vérifier le timeout
    if start.elapsed().as_millis() > MAX_EXECUTION_TIME_MS as u128 {
        panic!("DoS: vérification de preuve trop lente");
    }
    
    // Simuler la vérification selon le type
    let result = match proof_type {
        0 => simulate_groth16_verification(proof, public_inputs),
        1 => simulate_plonky2_verification(proof, public_inputs),
        _ => Err("Unknown proof type"),
    };
    
    // IMPORTANT: Ne pas utiliser unwrap_or_default()!
    // C'est exactement la vulnérabilité qu'on cherche à éviter
    match result {
        Ok(valid) => {
            if valid {
                // Preuve valide
            }
        }
        Err(e) => {
            // Log l'erreur pour analyse
            // En production: log::debug!("Proof verification failed: {}", e);
            let _ = e;
        }
    }
});

fn simulate_groth16_verification(
    proof: &[u8],
    _public_inputs: &[u8]
) -> Result<bool, &'static str> {
    // Vérifications de base
    if proof.len() < MIN_PROOF_SIZE {
        return Err("Proof too small");
    }
    
    if proof.len() > MAX_PROOF_SIZE {
        return Err("Proof too large");
    }
    
    // Simuler une vérification
    // Dans la vraie implémentation, utiliser groth16::verify
    Ok(false) // Par défaut, rejeter
}

fn simulate_plonky2_verification(
    proof: &[u8],
    _public_inputs: &[u8]
) -> Result<bool, &'static str> {
    // Vérifications de base
    if proof.len() < MIN_PROOF_SIZE {
        return Err("Proof too small");
    }
    
    if proof.len() > MAX_PROOF_SIZE {
        return Err("Proof too large");
    }
    
    // Simuler une vérification
    // Dans la vraie implémentation, utiliser plonky2::verify
    Ok(false) // Par défaut, rejeter
}
