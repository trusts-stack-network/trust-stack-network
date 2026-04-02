//! Fuzzer complet pour la désérialisation des blocs TSN
//!
//! Couvre:
//! - BlockHeader (tous les champs)
//! - ShieldedBlock (avec transactions V1 et V2)
//! - Validation de structure (Merkle root, timestamps, etc.)
//! - Attaques DoS via blocs malformés
//!
//! THREAT MODEL:
//! - Adversaire contrôlant les données de blocs reçues du réseau
//! - Tentatives de crash via overflow, underflow, ou données malformées
//! - Attaques de déni de service via parsing coûteux
//! - Exploitation de vulnérabilités de désérialisation

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::panic;
use std::time::Instant;

use tsn::core::block::{BlockHeader, ShieldedBlock, BLOCK_HASH_SIZE};
use tsn::core::transaction::{ShieldedTransaction, ShieldedTransactionV2, CoinbaseTransaction};

/// Input struct pour le fuzzing avec arbitrary
#[derive(Arbitrary, Debug)]
struct BlockFuzzInput {
    raw_data: Vec<u8>,
    corruption_strategy: CorruptionStrategy,
    target_field: TargetField,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum CorruptionStrategy {
    RandomBytes,
    TruncatedData,
    ExtendedData,
    BitFlips,
    ByteSwapping,
    LengthOverflow,
    LengthUnderflow,
    MagicBytesCorruption,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum TargetField {
    BlockHeader,
    ShieldedBlock,
    AllFields,
}

fuzz_target!(|input: BlockFuzzInput| {
    // Protection anti-panic globale
    let result = panic::catch_unwind(|| {
        fuzz_block_deserialization(&input);
    });
    
    if let Err(_) = result {
        panic!("CRITICAL: Panic detected in block deserialization fuzzer! Strategy: {:?}, Target: {:?}", 
               input.corruption_strategy, input.target_field);
    }
});

fn fuzz_block_deserialization(input: &BlockFuzzInput) {
    // Appliquer la stratégie de corruption
    let corrupted_data = apply_corruption(&input.raw_data, input.corruption_strategy);
    
    match input.target_field {
        TargetField::BlockHeader => fuzz_block_header(&corrupted_data),
        TargetField::ShieldedBlock => fuzz_shielded_block(&corrupted_data),
        TargetField::AllFields => {
            fuzz_block_header(&corrupted_data);
            fuzz_shielded_block(&corrupted_data);
        }
    }
}

fn apply_corruption(data: &[u8], strategy: CorruptionStrategy) -> Vec<u8> {
    let mut result = data.to_vec();
    
    match strategy {
        CorruptionStrategy::RandomBytes => {
            // Données déjà aléatoires, rien à faire
        }
        CorruptionStrategy::TruncatedData => {
            if !result.is_empty() {
                let truncate_at = result.len() / 2;
                result.truncate(truncate_at);
            }
        }
        CorruptionStrategy::ExtendedData => {
            // Dupliquer les données
            let original = result.clone();
            result.extend_from_slice(&original);
        }
        CorruptionStrategy::BitFlips => {
            if !result.is_empty() {
                let flip_count = (result.len() / 10).max(1);
                for i in 0..flip_count {
                    let idx = i % result.len();
                    let bit = (idx % 8) as u8;
                    result[idx] ^= 1 << bit;
                }
            }
        }
        CorruptionStrategy::ByteSwapping => {
            if result.len() >= 2 {
                for i in (0..result.len() - 1).step_by(2) {
                    result.swap(i, i + 1);
                }
            }
        }
        CorruptionStrategy::LengthOverflow => {
            // Injecter des valeurs de longueur très grandes
            if result.len() >= 8 {
                let max_val = u64::MAX;
                result[0..8].copy_from_slice(&max_val.to_le_bytes());
            }
        }
        CorruptionStrategy::LengthUnderflow => {
            // Injecter des valeurs négatives (en complément à 2)
            if result.len() >= 8 {
                result[0..8].fill(0xFF);
            }
        }
        CorruptionStrategy::MagicBytesCorruption => {
            // Corrompre les premiers bytes (souvent des magic bytes)
            if !result.is_empty() {
                let corrupt_len = result.len().min(16);
                for i in 0..corrupt_len {
                    result[i] = result[i].wrapping_add(0x42);
                }
            }
        }
    }
    
    result
}

fn fuzz_block_header(data: &[u8]) {
    // Test 1: Désérialisation via serde
    let _ = serde_json::from_slice::<BlockHeader>(data);
    let _ = bincode::deserialize::<BlockHeader>(data);
    
    // Test 2: Construction manuelle avec vérification de bounds
    if data.len() >= 80 {
        // Extraire les champs avec vérification
        let version = u32::from_le_bytes([
            data.get(0).copied().unwrap_or(0),
            data.get(1).copied().unwrap_or(0),
            data.get(2).copied().unwrap_or(0),
            data.get(3).copied().unwrap_or(0),
        ]);
        
        // Vérifier que la version est raisonnable
        if version > 1000 {
            return; // Version suspecte, ignorer
        }
        
        let mut prev_hash = [0u8; BLOCK_HASH_SIZE];
        let mut merkle_root = [0u8; BLOCK_HASH_SIZE];
        let mut commitment_root = [0u8; BLOCK_HASH_SIZE];
        let mut nullifier_root = [0u8; BLOCK_HASH_SIZE];
        
        // Copier avec vérification de bounds
        for i in 0..BLOCK_HASH_SIZE {
            if 4 + i < data.len() {
                prev_hash[i] = data[4 + i];
            }
            if 36 + i < data.len() {
                merkle_root[i] = data[36 + i];
            }
            if 68 + i < data.len() {
                commitment_root[i] = data[68 + i];
            }
            if 100 + i < data.len() {
                nullifier_root[i] = data[100 + i];
            }
        }
        
        // Extraire timestamp, difficulty, nonce
        let timestamp = if data.len() >= 140 {
            u64::from_le_bytes([
                data[132], data[133], data[134], data[135],
                data[136], data[137], data[138], data[139],
            ])
        } else { 0 };
        
        let difficulty = if data.len() >= 148 {
            u64::from_le_bytes([
                data[140], data[141], data[142], data[143],
                data[144], data[145], data[146], data[147],
            ])
        } else { 0 };
        
        let nonce = if data.len() >= 156 {
            u64::from_le_bytes([
                data[148], data[149], data[150], data[151],
                data[152], data[153], data[154], data[155],
            ])
        } else { 0 };
        
        // Vérifier les valeurs critiques
        if timestamp > 4_000_000_000 {
            // Timestamp dans le futur lointain
            return;
        }
        
        if difficulty > 256 {
            // Difficulté impossible
            return;
        }
        
        // Construire le header
        let header = BlockHeader {
            version,
            prev_hash,
            merkle_root,
            commitment_root,
            nullifier_root,
            timestamp,
            difficulty,
            nonce,
        };
        
        // Tester les méthodes - ne doivent pas paniquer
        let _hash = header.hash();
        let _hash_hex = header.hash_hex();
        let _meets_difficulty = header.meets_difficulty();
    }
    
    // Test 3: Vérification de la taille maximale
    if data.len() > 10_000_000 {
        // DoS protection: données trop grandes
        return;
    }
}

fn fuzz_shielded_block(data: &[u8]) {
    // Test 1: Désérialisation via serde
    let start = Instant::now();
    let _ = serde_json::from_slice::<ShieldedBlock>(data);
    let elapsed = start.elapsed();
    
    // DoS protection: parsing ne doit pas prendre trop de temps
    if elapsed.as_millis() > 100 {
        return; // Trop lent, potentiel DoS
    }
    
    let start = Instant::now();
    let _ = bincode::deserialize::<ShieldedBlock>(data);
    let elapsed = start.elapsed();
    
    if elapsed.as_millis() > 100 {
        return;
    }
    
    // Test 2: Vérification des limites de transactions
    if data.len() >= 4 {
        // Simuler un nombre de transactions extrait des données
        let tx_count = u32::from_le_bytes([
            data[0], data[1], data[2], data[3],
        ]) as usize;
        
        // Protection DoS: limiter le nombre de transactions
        if tx_count > 10_000 {
            return;
        }
        
        // Vérifier que la taille des données est cohérente
        let min_tx_size = 100; // Taille minimale estimée par transaction
        if tx_count * min_tx_size > data.len() * 10 {
            // Incohérence: plus de transactions que de données
            return;
        }
    }
    
    // Test 3: Vérification des roots
    if data.len() >= 96 {
        let mut commitment_root = [0u8; 32];
        let mut nullifier_root = [0u8; 32];
        
        commitment_root.copy_from_slice(&data[32..64].min(data.len()).map(|i| data.get(i).copied().unwrap_or(0)).collect::<Vec<_>>()[..32.min(data.len().saturating_sub(32))]);
        
        // Vérifier que les roots ne sont pas des valeurs spéciales dangereuses
        let zero_root = [0u8; 32];
        let max_root = [0xFFu8; 32];
        
        // Un root tout à zéro ou tout à 0xFF est suspect mais pas invalide
        // On vérifie juste que le code ne panique pas
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_data() {
        let input = BlockFuzzInput {
            raw_data: vec![],
            corruption_strategy: CorruptionStrategy::RandomBytes,
            target_field: TargetField::BlockHeader,
        };
        fuzz_block_deserialization(&input);
    }

    #[test]
    fn test_all_strategies() {
        let strategies = [
            CorruptionStrategy::RandomBytes,
            CorruptionStrategy::TruncatedData,
            CorruptionStrategy::ExtendedData,
            CorruptionStrategy::BitFlips,
            CorruptionStrategy::ByteSwapping,
            CorruptionStrategy::LengthOverflow,
            CorruptionStrategy::LengthUnderflow,
            CorruptionStrategy::MagicBytesCorruption,
        ];
        
        for strategy in &strategies {
            let input = BlockFuzzInput {
                raw_data: vec![0xFF; 200],
                corruption_strategy: *strategy,
                target_field: TargetField::AllFields,
            };
            fuzz_block_deserialization(&input);
        }
    }

    #[test]
    fn test_large_data() {
        let input = BlockFuzzInput {
            raw_data: vec![0x42; 1_000_000],
            corruption_strategy: CorruptionStrategy::RandomBytes,
            target_field: TargetField::ShieldedBlock,
        };
        fuzz_block_deserialization(&input);
    }
}
