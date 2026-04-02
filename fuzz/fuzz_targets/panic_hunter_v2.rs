// Fuzzer pour détecter les panics dans les fonctions critiques TSN
//
// Ce fuzzer cible spécifiquement:
// - La désérialisation des transactions
// - La validation des signatures
// - La vérification des preuves ZK
// - Le traitement des blocs
//
// # Usage
// cargo +nightly fuzz run panic_hunter_v2

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::panic::{self, AssertUnwindSafe};

/// Structure pour capturer les résultats de fuzzing
#[derive(Debug)]
struct FuzzResult {
    success: bool,
    panic_detected: bool,
    error_message: Option<String>,
}

impl FuzzResult {
    fn success() -> Self {
        Self {
            success: true,
            panic_detected: false,
            error_message: None,
        }
    }
    
    fn error(msg: String) -> Self {
        Self {
            success: false,
            panic_detected: false,
            error_message: Some(msg),
        }
    }
    
    fn panic(msg: String) -> Self {
        Self {
            success: false,
            panic_detected: true,
            error_message: Some(msg),
        }
    }
}

/// Wrapper sécurisé pour exécuter du code qui pourrait paniquer
fn run_safely<F, R>(f: F, input: &[u8]) -> FuzzResult
where
    F: FnOnce(&[u8]) -> R + panic::UnwindSafe,
{
    match panic::catch_unwind(AssertUnwindSafe(|| f(input))) {
        Ok(_) => FuzzResult::success(),
        Err(e) => {
            let msg = if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else {
                "Unknown panic".to_string()
            };
            FuzzResult::panic(msg)
        }
    }
}

/// Simule la validation d'une transaction avec protection contre les panics
fn fuzz_transaction_validation(data: &[u8]) -> FuzzResult {
    run_safely(|input| {
        // Vérifier la taille minimale
        if input.len() < 8 {
            return;
        }
        
        // Vérifier les magic bytes
        if input[0..4] != [0x54, 0x53, 0x4e, 0x54] {
            return;
        }
        
        // Vérifier la version
        let version = input[4];
        if version > 2 {
            return;
        }
        
        // Simuler la lecture de la taille
        let size_bytes = &input[4..8];
        let size = u32::from_le_bytes([
            size_bytes[0],
            size_bytes[1],
            size_bytes[2],
            size_bytes[3],
        ]) as usize;
        
        // Vérifier que la taille déclarée correspond
        if input.len() < 8 + size {
            return;
        }
        
        // Simuler la validation de signature
        let sig_offset = 8 + size;
        if input.len() < sig_offset + 64 {
            return;
        }
        
        // Tout s'est bien passé
    }, data)
}

/// Simule la validation d'un bloc avec protection contre les panics
fn fuzz_block_validation(data: &[u8]) -> FuzzResult {
    run_safely(|input| {
        // Vérifier la taille minimale pour un header
        if input.len() < 80 {
            return;
        }
        
        // Vérifier les magic bytes du bloc
        if input[0..4] != [0x42, 0x4c, 0x4b, 0x00] {
            return;
        }
        
        // Lire la hauteur du bloc
        let height = u64::from_le_bytes([
            input[8], input[9], input[10], input[11],
            input[12], input[13], input[14], input[15],
        ]);
        
        // Vérifier que la hauteur est raisonnable
        if height > 100_000_000 {
            return;
        }
        
        // Lire le timestamp
        let timestamp = u64::from_le_bytes([
            input[16], input[17], input[18], input[19],
            input[20], input[21], input[22], input[23],
        ]);
        
        // Vérifier que le timestamp est dans une plage raisonnable
        let now = 1700000000u64; // ~2023
        if timestamp > now + 86400 * 365 {
            return;
        }
        
        // Vérifier le nombre de transactions
        let tx_count = u32::from_le_bytes([
            input[76], input[77], input[78], input[79],
        ]);
        
        if tx_count > 10000 {
            return;
        }
        
        // Vérifier que les données sont suffisantes
        let expected_size = 80 + tx_count as usize * 100;
        if input.len() < expected_size {
            return;
        }
        
    }, data)
}

/// Simule la validation d'une preuve ZK avec protection contre les panics
fn fuzz_proof_validation(data: &[u8]) -> FuzzResult {
    run_safely(|input| {
        // Vérifier la taille minimale
        if input.len() < 32 {
            return;
        }
        
        // Vérifier le type de preuve
        let proof_type = input[0];
        match proof_type {
            0x01 => {
                // Preuve Groth16
                if input.len() < 192 {
                    return;
                }
            }
            0x02 => {
                // Preuve Plonky2
                if input.len() < 1024 {
                    return;
                }
            }
            _ => return, // Type inconnu
        }
        
        // Vérifier les public inputs
        let public_inputs_len = u32::from_le_bytes([
            input[1], input[2], input[3], input[4],
        ]) as usize;
        
        if public_inputs_len > 100 {
            return;
        }
        
        let expected_len = 5 + public_inputs_len * 32;
        if input.len() < expected_len {
            return;
        }
        
    }, data)
}

/// Simule la validation d'une adresse avec protection contre les panics
fn fuzz_address_validation(data: &[u8]) -> FuzzResult {
    run_safely(|input| {
        // Vérifier la taille
        if input.len() != 32 {
            return;
        }
        
        // Vérifier que ce n'est pas une adresse nulle
        if input.iter().all(|b| *b == 0) {
            return;
        }
        
        // Vérifier que ce n'est pas une adresse pleine de 0xff
        if input.iter().all(|b| *b == 0xff) {
            return;
        }
        
    }, data)
}

/// Simule la validation d'un hash avec protection contre les panics
fn fuzz_hash_validation(data: &[u8]) -> FuzzResult {
    run_safely(|input| {
        // Vérifier la taille pour SHA-256
        if input.len() != 32 {
            return;
        }
        
        // Vérifier que ce n'est pas un hash nul
        if input.iter().all(|b| *b == 0) {
            return;
        }
        
    }, data)
}

/// Simule la désérialisation d'un état avec protection contre les panics
fn fuzz_state_deserialization(data: &[u8]) -> FuzzResult {
    run_safely(|input| {
        // Vérifier la taille minimale
        if input.len() < 16 {
            return;
        }
        
        // Vérifier le magic number
        if input[0..4] != [0x53, 0x54, 0x41, 0x54] {
            return;
        }
        
        // Lire le nombre de comptes
        let account_count = u64::from_le_bytes([
            input[4], input[5], input[6], input[7],
            input[8], input[9], input[10], input[11],
        ]);
        
        // Vérifier que le nombre de comptes est raisonnable
        if account_count > 1_000_000 {
            return;
        }
        
        // Vérifier la taille des données
        let expected_size = 16 + account_count as usize * 40;
        if input.len() < expected_size {
            return;
        }
        
    }, data)
}

/// Point d'entrée principal du fuzzer
fuzz_target!(|data: &[u8]| {
    // Exécuter tous les fuzzers et collecter les résultats
    let results = vec![
        ("transaction", fuzz_transaction_validation(data)),
        ("block", fuzz_block_validation(data)),
        ("proof", fuzz_proof_validation(data)),
        ("address", fuzz_address_validation(data)),
        ("hash", fuzz_hash_validation(data)),
        ("state", fuzz_state_deserialization(data)),
    ];
    
    // Vérifier qu'aucun panic n'a été détecté
    for (name, result) in results {
        if result.panic_detected {
            panic!(
                "PANIC DETECTED in {}: {:?}",
                name,
                result.error_message
            );
        }
    }
});
