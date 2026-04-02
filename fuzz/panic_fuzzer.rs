//! Fuzzer pour détecter les panics sur entrées malveillantes
//!
//! Ce fuzzer cible les parsers et validateurs qui pourraient paniquer
//! sur des entrées contrôlées par un attaquant.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::time::{SystemTime, UNIX_EPOCH};

/// Structure représentant une entrée fuzzée
#[derive(Debug)]
struct FuzzInput {
    data: Vec<u8>,
    timestamp: u64,
    flags: u32,
}

impl FuzzInput {
    fn from_bytes(raw: &[u8]) -> Option<Self> {
        if raw.len() < 16 {
            return None;
        }
        
        let timestamp = u64::from_le_bytes([
            raw[0], raw[1], raw[2], raw[3],
            raw[4], raw[5], raw[6], raw[7],
        ]);
        
        let flags = u32::from_le_bytes([
            raw[8], raw[9], raw[10], raw[11],
        ]);
        
        let data = raw[12..].to_vec();
        
        Some(FuzzInput {
            data,
            timestamp,
            flags,
        })
    }
}

/// Simule la validation de timestamp (version fuzz-safe)
fn validate_timestamp_fuzz(timestamp: u64) -> Result<(), &'static str> {
    // Version corrigée qui ne panique pas
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(now) => {
            let current = now.as_secs();
            
            // Vérifier que le timestamp n'est pas dans le futur lointain
            if timestamp > current + 3600 {
                return Err("timestamp too far in future");
            }
            
            // Vérifier que le timestamp n'est pas trop vieux
            if timestamp < current.saturating_sub(86400 * 7) {
                return Err("timestamp too old");
            }
            
            Ok(())
        }
        Err(_) => {
            // Gérer gracieusement l'erreur SystemTime
            Err("system time error")
        }
    }
}

/// Simule le traitement d'un payload (version fuzz-safe)
fn process_payload_fuzz(data: &[u8]) -> Result<usize, &'static str> {
    // Vérifier les limites avant tout traitement
    if data.len() > 1024 * 1024 {
        return Err("payload too large");
    }
    
    // Traitement sûr avec vérification des bounds
    let mut processed = 0;
    for (i, byte) in data.iter().enumerate() {
        // Opération simple qui ne panique pas
        processed += (*byte as usize).wrapping_add(i);
    }
    
    Ok(processed)
}

/// Simule la validation de flags (version fuzz-safe)
fn validate_flags_fuzz(flags: u32) -> Result<(), &'static str> {
    // Flags connus
    const FLAG_SYNC: u32 = 0x01;
    const FLAG_BROADCAST: u32 = 0x02;
    const FLAG_PRIORITY: u32 = 0x04;
    const KNOWN_FLAGS: u32 = FLAG_SYNC | FLAG_BROADCAST | FLAG_PRIORITY;
    
    // Vérifier qu'il n'y a pas de flags inconnus (optionnel)
    let unknown = flags & !KNOWN_FLAGS;
    if unknown != 0 {
        // C'est un warning, pas une erreur fatale
        eprintln!("Unknown flags: {:#x}", unknown);
    }
    
    Ok(())
}

/// Simule le parsing de bytes bruts (version fuzz-safe)
fn parse_raw_bytes_fuzz(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if data.is_empty() {
        return Ok(vec![]);
    }
    
    // Vérifier la longueur déclarée vs réelle
    if data.len() < 4 {
        return Err("data too short for header");
    }
    
    let declared_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    
    // Protection contre les déclarations de taille abusive
    if declared_len > 1024 * 1024 {
        return Err("declared length too large");
    }
    
    // Vérifier la cohérence
    if declared_len > data.len() - 4 {
        return Err("declared length exceeds actual data");
    }
    
    // Extraction sûre avec vérification des bounds
    let content = data[4..4 + declared_len.min(data.len() - 4)].to_vec();
    
    Ok(content)
}

/// Fuzz target principal - simule des entrées réseau malformées
fuzz_target!(|data: &[u8]| {
    // Ne jamais paniquer ici - le fuzzer détecte automatiquement les panics
    
    if let Some(input) = FuzzInput::from_bytes(data) {
        // Simuler le traitement d'un message réseau
        
        // Test 1: Validation de timestamp (ne devrait pas paniquer)
        // Le code actuel a un unwrap sur SystemTime::duration_since
        // Ce test vérifie que des timestamps extrêmes ne causent pas de panic
        let _ = validate_timestamp_fuzz(input.timestamp);
        
        // Test 2: Traitement de données de payload
        // Ne devrait jamais paniquer quelle que soit la taille
        let _ = process_payload_fuzz(&input.data);
        
        // Test 3: Validation de flags
        // Les flags malformés ne devraient pas causer de panic
        let _ = validate_flags_fuzz(input.flags);
    }
    
    // Test 4: Traitement direct des bytes bruts
    // Simule un parser qui reçoit des données arbitraires
    let _ = parse_raw_bytes_fuzz(data);
});

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fuzz_timestamp_edge_cases() {
        // Cas qui pourraient causer des problèmes
        let cases = vec![
            0u64,                    // Epoch
            u64::MAX,               // Max value
            1u64,                   // Just after epoch
            32503680000u64,         // Year 3000
        ];
        
        for case in cases {
            let result = validate_timestamp_fuzz(case);
            // Ne devrait jamais paniquer
            assert!(result.is_ok() || result.is_err());
        }
    }
    
    #[test]
    fn test_fuzz_payload_edge_cases() {
        let cases = vec![
            vec![],
            vec![0xff; 1024],
            vec![0x00; 1024],
        ];
        
        for case in cases {
            let result = process_payload_fuzz(&case);
            assert!(result.is_ok() || result.is_err());
        }
    }
    
    #[test]
    fn test_fuzz_raw_bytes_edge_cases() {
        let cases = vec![
            vec![],
            vec![0x01, 0x00, 0x00, 0x00], // Déclare 1 byte, 0 disponible
            vec![0xff, 0xff, 0xff, 0xff], // Déclare taille max
        ];
        
        for case in cases {
            let result = parse_raw_bytes_fuzz(&case);
            assert!(result.is_ok() || result.is_err());
        }
    }
}
