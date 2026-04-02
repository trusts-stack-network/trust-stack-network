#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use tsn::core::block::{BlockHeader, BLOCK_HASH_SIZE};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Arbitrary, Debug)]
struct FuzzHeaderInput {
    data: Vec<u8>,
    test_difficulty_attacks: bool,
    test_timestamp_attacks: bool,
    test_hash_validation: bool,
    test_version_attacks: bool,
    test_pow_bypass: bool,
}

fn count_leading_zeros(hash: &[u8]) -> usize {
    let mut count = 0;
    for &byte in hash {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros() as usize;
            break;
        }
    }
    count
}

fuzz_target!(|input: FuzzHeaderInput| {
    // Test 1: Désérialisation basique - ne doit jamais crasher
    if let Ok(header) = bincode::deserialize::<BlockHeader>(&input.data) {
        
        // Test 2: Attaques difficulty
        if input.test_difficulty_attacks {
            // SECURITE CRITIQUE: Difficulty zéro = instant mining
            if header.difficulty == 0 {
                panic!("Zero difficulty detected - infinite mining speed!");
            }
            
            // SECURITE: Difficulty absurdement élevée = DoS
            if header.difficulty > 256 {
                panic!("Difficulty too high: {} (max reasonable: 256)", header.difficulty);
            }
            
            // SECURITE: Vérifier que le hash respecte réellement la difficulty
            let hash = header.hash();
            let actual_zeros = count_leading_zeros(&hash);
            
            // Si le header claim une difficulty, le hash doit la respecter
            if header.meets_difficulty() {
                if actual_zeros < header.difficulty as usize {
                    panic!(
                        "Header claims to meet difficulty {} but hash only has {} leading zeros", 
                        header.difficulty, actual_zeros
                    );
                }
            }
        }
        
        // Test 3: Attaques timestamp
        if input.test_timestamp_attacks {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            // SECURITE: Timestamp dans le futur lointain (> 2h)
            if header.timestamp > now + 7200 {
                panic!(
                    "Block timestamp too far in future: {} vs {} (diff: {}s)", 
                    header.timestamp, now, header.timestamp.saturating_sub(now)
                );
            }
            
            // SECURITE: Timestamp ancien (avant Bitcoin genesis)
            if header.timestamp < 1230768000 { // 2009-01-01
                panic!("Block timestamp before 2009: {}", header.timestamp);
            }
            
            // SECURITE: Timestamp overflow check
            if header.timestamp > u64::MAX / 1000 {
                panic!("Timestamp near overflow: {}", header.timestamp);
            }
        }
        
        // Test 4: Validation des hashes
        if input.test_hash_validation {
            // SECURITE CRITIQUE: Hashes ne doivent jamais être nuls
            if header.prev_hash == [0u8; BLOCK_HASH_SIZE] {
                // Exception: bloc genesis peut avoir prev_hash nul
                if header.timestamp > 1230768000 + 86400 { // Plus de 24h après genesis
                    panic!("Zero previous hash detected in non-genesis block");
                }
            }
            
            if header.merkle_root == [0u8; BLOCK_HASH_SIZE] {
                panic!("Zero merkle root detected");
            }
            
            if header.commitment_root == [0u8; BLOCK_HASH_SIZE] {
                panic!("Zero commitment root detected");
            }
            
            if header.nullifier_root == [0u8; BLOCK_HASH_SIZE] {
                panic!("Zero nullifier root detected");
            }
            
            // SECURITE: Vérifier que les roots sont différents (sauf cas spéciaux)
            if header.merkle_root == header.commitment_root {
                panic!("Merkle root equals commitment root - suspicious");
            }
            
            if header.commitment_root == header.nullifier_root {
                panic!("Commitment root equals nullifier root - suspicious");
            }
            
            // SECURITE: Hash du header doit être déterministe
            let hash1 = header.hash();
            let hash2 = header.hash();
            if hash1 != hash2 {
                panic!("Header hash not deterministic!");
            }
        }
        
        // Test 5: Attaques version
        if input.test_version_attacks {
            // SECURITE: Version supportée
            if header.version == 0 {
                panic!("Zero version detected");
            }
            
            if header.version > 10 {
                panic!("Unsupported version: {}", header.version);
            }
        }
        
        // Test 6: Attaques PoW bypass
        if input.test_pow_bypass {
            // SECURITE CRITIQUE: Le nonce doit être cohérent avec la difficulty
            if header.difficulty > 10 {
                // Pour des difficulties élevées, vérifier que ce n'est pas un faux PoW
                let hash = header.hash();
                let leading_zeros = count_leading_zeros(&hash);
                
                if leading_zeros >= header.difficulty as usize && header.nonce == 0 {
                    panic!("Suspicious: high difficulty met with zero nonce");
                }
                
                // Pattern suspect: nonce = 0x123456789abcdef0 (pattern)
                if header.nonce == 0x123456789abcdef0 {
                    panic!("Suspicious nonce pattern detected");
                }
            }
            
            // SECURITE: Test de collision de hash intentionnelle
            let mut modified_header = header.clone();
            modified_header.nonce = modified_header.nonce.wrapping_add(1);
            
            let original_hash = header.hash();
            let modified_hash = modified_header.hash();
            
            if original_hash == modified_hash {
                panic!("Hash collision detected with different nonces!");
            }
        }
        
        // Test 7: Contraintes de cohérence globale
        // SECURITE: Vérifier la cohérence entre tous les champs
        let computed_hash = header.hash();
        
        // Le hash ne doit pas être entièrement nul (probabilité astronomiquement faible)
        if computed_hash == [0u8; BLOCK_HASH_SIZE] {
            panic!("Computed hash is all zeros - astronomical probability or attack");
        }
        
        // Le hash ne doit pas être entièrement 0xFF (pattern suspect)
        if computed_hash == [0xFFu8; BLOCK_HASH_SIZE] {
            panic!("Computed hash is all 0xFF - suspicious pattern");
        }
    }
    
    // Test 8: Attaque par header malformé/tronqué
    if input.data.len() > 4 && input.data.len() < 200 {
        // Headers tronqués ne doivent jamais causer de panic
        let _ = bincode::deserialize::<BlockHeader>(&input.data);
    }
    
    // Test 9: Attaque par header surdimensionné (DoS)
    if input.data.len() > 100_000 {
        // DoS protection: parsing doit échouer rapidement
        let start = std::time::Instant::now();
        let _ = bincode::deserialize::<BlockHeader>(&input.data);
        let elapsed = start.elapsed();
        
        if elapsed.as_millis() > 10 {
            panic!("Oversized header parsing too slow: {}ms", elapsed.as_millis());
        }
    }
});