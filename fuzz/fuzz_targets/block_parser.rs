//! Fuzzer pour le parsing de blocs TSN
//!
//! Teste la robustesse du parser de blocs face à des entrées malformées,
//! corrompues ou malveillantes. Objectif : aucun panic, crash ou comportement
//! indéfini, même avec des données adversaires.
//!
//! THREAT MODEL:
//! - Adversaire contrôlant les données de blocs reçues du réseau
//! - Tentatives de crash via overflow, underflow, ou données malformées
//! - Attaques de déni de service via parsing coûteux
//! - Exploitation de vulnérabilités de désérialisation

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::panic;
use tsn::core::Block;

/// Point d'entrée du fuzzer pour le parsing de blocs
fuzz_target!(|data: &[u8]| {
    // Configurer un hook de panic pour capturer les panics
    let original_hook = panic::take_hook();
    let mut panic_occurred = false;
    
    panic::set_hook(Box::new(|_| {
        // Ne rien faire - on veut juste détecter le panic
    }));
    
    let result = panic::catch_unwind(|| {
        fuzz_block_parsing(data)
    });
    
    // Restaurer le hook original
    panic::set_hook(original_hook);
    
    match result {
        Ok(_) => {
            // Parsing réussi ou échec gracieux - OK
        },
        Err(_) => {
            // Panic détecté - c'est un bug !
            eprintln!("PANIC détecté lors du parsing de bloc avec {} bytes", data.len());
            eprintln!("Données: {:?}", data);
            panic!("Le parser de blocs ne doit jamais paniquer !");
        }
    }
});

/// Fonction principale de fuzzing du parsing de blocs
fn fuzz_block_parsing(data: &[u8]) {
    // Test 1: Tentative de désérialisation directe
    if data.len() >= 8 {
        let _ = try_deserialize_block(data);
    }
    
    // Test 2: Construction de bloc avec des données fuzzées
    if data.len() >= 32 {
        let _ = try_construct_block_from_fuzz_data(data);
    }
    
    // Test 3: Validation de blocs construits avec des données fuzzées
    if data.len() >= 64 {
        let _ = try_validate_fuzzed_block(data);
    }
    
    // Test 4: Calculs de hash avec des données corrompues
    if data.len() >= 16 {
        let _ = try_hash_calculations(data);
    }
    
    // Test 5: Merkle tree avec transactions fuzzées
    if data.len() >= 100 {
        let _ = try_merkle_tree_fuzzing(data);
    }
}

/// Tentative de désérialisation de bloc à partir de données brutes
fn try_deserialize_block(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // En vrai, on utiliserait serde ou bincode pour désérialiser
    // Ici on simule en extrayant des champs depuis les bytes bruts
    
    if data.len() < 80 { // Taille minimale d'un bloc
        return Err("Données trop courtes".into());
    }
    
    // Extraire les champs avec vérification de bounds
    let height = u64::from_le_bytes(data[0..8].try_into().unwrap_or([0; 8]));
    let parent_hash: [u8; 32] = data[8..40].try_into().unwrap_or([0; 32]);
    let merkle_root: [u8; 32] = data[40..72].try_into().unwrap_or([0; 32]);
    let timestamp = u64::from_le_bytes(data[72..80].try_into().unwrap_or([0; 8]));
    
    // Vérifications de sanité
    if height > 1_000_000_000 {
        return Err("Hauteur de bloc excessive".into());
    }
    
    if timestamp > 2_000_000_000 {
        return Err("Timestamp invalide".into());
    }
    
    // Construire un bloc avec ces données
    let block = Block::new(
        height,
        parent_hash,
        Vec::new(), // Pas de transactions pour ce test
        merkle_root,
        timestamp,
        0, // nonce
    );
    
    // Vérifier que le bloc peut calculer son hash sans paniquer
    let _hash = block.calculate_hash();
    
    Ok(())
}

/// Construction de bloc avec des paramètres fuzzés
fn try_construct_block_from_fuzz_data(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut offset = 0;
    
    // Extraire height avec protection contre les valeurs extrêmes
    let height = if data.len() >= offset + 8 {
        let raw_height = u64::from_le_bytes(data[offset..offset+8].try_into().unwrap());
        offset += 8;
        // Limiter à une valeur raisonnable pour éviter les DoS
        raw_height.min(1_000_000)
    } else {
        1
    };
    
    // Extraire parent_hash
    let parent_hash = if data.len() >= offset + 32 {
        let hash: [u8; 32] = data[offset..offset+32].try_into().unwrap();
        offset += 32;
        hash
    } else {
        [0u8; 32]
    };
    
    // Extraire timestamp
    let timestamp = if data.len() >= offset + 8 {
        let raw_timestamp = u64::from_le_bytes(data[offset..offset+8].try_into().unwrap());
        offset += 8;
        // Valider le timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        raw_timestamp.min(now + 3600) // Max 1h dans le futur
    } else {
        1234567890
    };
    
    // Extraire nonce
    let nonce = if data.len() >= offset + 8 {
        u64::from_le_bytes(data[offset..offset+8].try_into().unwrap())
    } else {
        0
    };
    
    // Construire le bloc
    let block = Block::new(
        height,
        parent_hash,
        Vec::new(),
        [0u8; 32], // merkle_root sera calculé
        timestamp,
        nonce,
    );
    
    // Tester les opérations sur le bloc
    let _hash = block.calculate_hash();
    let _merkle_root = block.calculate_merkle_root();
    
    // Vérifier la sérialisation (simulation)
    let _serialized = format!("{:?}", block);
    
    Ok(())
}

/// Validation de blocs avec des données fuzzées
fn try_validate_fuzzed_block(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    use tsn::consensus::validation::Validator;
    use tsn::core::Blockchain;
    
    // Construire un bloc à partir des données fuzzées
    let block = match try_construct_block_from_fuzz_data(data) {
        Ok(_) => {
            // Reconstruire le bloc pour les tests
            let height = u64::from_le_bytes(data[0..8].try_into().unwrap_or([0; 8])).min(1000);
            let parent_hash: [u8; 32] = data[8..40].try_into().unwrap_or([0; 32]);
            let timestamp = u64::from_le_bytes(data[40..48].try_into().unwrap_or([0; 8]));
            
            Block::new(height, parent_hash, Vec::new(), [0u8; 32], timestamp, 0)
        },
        Err(_) => return Ok(()), // Échec de construction - pas grave
    };
    
    // Tester la validation
    let validator = Validator::new();
    let blockchain = Blockchain::new();
    
    // Ces validations ne doivent jamais paniquer, même avec des données invalides
    let _struct_result = validator.validate_block_structure(&block);
    let _consensus_result = validator.validate_consensus_rules(&block, &blockchain);
    
    Ok(())
}

/// Test des calculs de hash avec des données corrompues
fn try_hash_calculations(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Tester le calcul de hash avec différentes tailles de données
    for chunk_size in [1, 2, 4, 8, 16, 32, 64].iter() {
        if data.len() >= *chunk_size {
            let chunk = &data[..*chunk_size];
            
            // Simuler le calcul de hash (en vrai on utiliserait SHA256 ou Blake3)
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            std::hash::Hasher::write(&mut hasher, chunk);
            let _hash_result = std::hash::Hasher::finish(&hasher);
        }
    }
    
    // Tester avec des données de taille variable
    for i in 0..data.len().min(1000) {
        let chunk = &data[..i];
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hasher::write(&mut hasher, chunk);
        let _hash_result = std::hash::Hasher::finish(&hasher);
    }
    
    Ok(())
}

/// Test du merkle tree avec des transactions fuzzées
fn try_merkle_tree_fuzzing(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    use tsn::core::Transaction;
    use tsn::crypto::keys::KeyPair;
    
    // Générer des transactions à partir des données fuzzées
    let mut transactions = Vec::new();
    let mut offset = 0;
    
    // Limiter le nombre de transactions pour éviter les DoS
    let max_transactions = 100;
    let mut tx_count = 0;
    
    while offset + 64 <= data.len() && tx_count < max_transactions {
        // Extraire les données pour une transaction
        let sender_kp = KeyPair::generate(); // En vrai, on extrairait des données
        let receiver_kp = KeyPair::generate();
        
        let amount = u64::from_le_bytes(data[offset..offset+8].try_into().unwrap()).min(1_000_000);
        offset += 8;
        
        let fee = u64::from_le_bytes(data[offset..offset+8].try_into().unwrap()).min(10_000);
        offset += 8;
        
        let nonce = u64::from_le_bytes(data[offset..offset+8].try_into().unwrap());
        offset += 8;
        
        // Construire la transaction
        let transaction = Transaction::new(
            sender_kp.public_key(),
            receiver_kp.public_key(),
            amount,
            fee,
            nonce,
        );
        
        transactions.push(transaction);
        tx_count += 1;
        
        // Avancer l'offset pour éviter les boucles infinies
        offset += 40; // Sauter quelques bytes
    }
    
    // Construire un bloc avec ces transactions
    let block = Block::new(
        1,
        [0u8; 32],
        transactions,
        [0u8; 32],
        1234567890,
        0,
    );
    
    // Calculer le merkle root - ne doit pas paniquer
    let _merkle_root = block.calculate_merkle_root();
    
    Ok(())
}

/// Tests de cas limites spécifiques
#[cfg(test)]
mod edge_case_tests {
    use super::*;
    
    #[test]
    fn test_empty_data() {
        fuzz_block_parsing(&[]);
    }
    
    #[test]
    fn test_single_byte() {
        fuzz_block_parsing(&[0xFF]);
    }
    
    #[test]
    fn test_all_zeros() {
        let data = vec![0u8; 1000];
        fuzz_block_parsing(&data);
    }
    
    #[test]
    fn test_all_ones() {
        let data = vec![0xFFu8; 1000];
        fuzz_block_parsing(&data);
    }
    
    #[test]
    fn test_alternating_pattern() {
        let data: Vec<u8> = (0..1000).map(|i| if i % 2 == 0 { 0xAA } else { 0x55 }).collect();
        fuzz_block_parsing(&data);
    }
    
    #[test]
    fn test_random_sizes() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        for size in [1, 7, 15, 31, 63, 127, 255, 511, 1023].iter() {
            let mut hasher = DefaultHasher::new();
            size.hash(&mut hasher);
            let seed = hasher.finish();
            
            let data: Vec<u8> = (0..*size).map(|i| ((seed + i as u64) % 256) as u8).collect();
            fuzz_block_parsing(&data);
        }
    }
}