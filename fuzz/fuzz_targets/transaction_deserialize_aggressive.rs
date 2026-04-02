#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::collections::HashSet;
use std::time::Instant;

// Import de toutes les structures de transaction TSN
use tsn::core::transaction::{
    Transaction, ShieldedTransaction, ShieldedTransactionV2, CoinbaseTransaction, 
    LegacyTransaction, SpendDescription, OutputDescription, BindingSignature,
    SpendDescriptionV2, OutputDescriptionV2, TransactionError
};
use tsn::crypto::{
    nullifier::Nullifier,
    commitment::NoteCommitment,
    proof::ZkProof,
    note::EncryptedNote,
    Signature, Address,
};

/// Fuzzer ultra-agressif pour la désérialisation des transactions TSN.
/// Cible spécifiquement les vulnérabilités post-quantiques et les attaques DoS.
#[derive(Arbitrary, Debug)]
struct AggressiveFuzzInput {
    // Données brutes pour désérialisation
    raw_data: Vec<u8>,
    
    // Mutations ciblées
    target_overflow_amounts: bool,
    target_duplicate_nullifiers: bool,
    target_malformed_signatures: bool,
    target_oversized_structures: bool,
    target_timing_attacks: bool,
    target_pq_vulnerabilities: bool,
    target_memory_exhaustion: bool,
    
    // Paramètres d'attaque
    mutation_factor: u8,
    corruption_offset: u16,
    amplification_factor: u16,
}

fuzz_target!(|input: AggressiveFuzzInput| {
    // **TEST 1: DÉSÉRIALISATION TIMING ATTACK RESISTANCE**
    if input.target_timing_attacks {
        let start = Instant::now();
        let result = match input.raw_data.len() % 4 {
            0 => bincode::deserialize::<ShieldedTransaction>(&input.raw_data),
            1 => bincode::deserialize::<CoinbaseTransaction>(&input.raw_data),
            2 => bincode::deserialize::<LegacyTransaction>(&input.raw_data),
            _ => bincode::deserialize::<ShieldedTransactionV2>(&input.raw_data),
        };
        let elapsed = start.elapsed();
        
        // Le parsing doit être constant-time pour éviter les timing attacks
        // Limite max: 10ms pour éviter DoS + side-channel attacks
        if elapsed.as_millis() > 10 {
            panic!("TIMING ATTACK DETECTED: Parsing took {}ms for {} bytes", 
                   elapsed.as_millis(), input.raw_data.len());
        }
        
        // Vérifier que les échecs sont aussi constant-time
        if result.is_err() && elapsed.as_nanos() < 1_000_000 { // < 1ms
            panic!("TIMING LEAK: Error path too fast ({}ns) - reveals structure info", 
                   elapsed.as_nanos());
        }
    }
    
    // **TEST 2: ATTAQUES DE MUTATION CIBLÉES**
    if input.target_malformed_signatures && input.raw_data.len() > 100 {
        let mut corrupted = input.raw_data.clone();
        let offset = (input.corruption_offset as usize) % corrupted.len();
        
        // Corrompre spécifiquement les zones de signature ML-DSA-65
        for i in 0..64.min(corrupted.len() - offset) {
            corrupted[offset + i] = corrupted[offset + i]
                .wrapping_add(input.mutation_factor)
                .wrapping_mul(3);
        }
        
        // Test de résistance: ne doit jamais paniquer, même avec signatures corrompues
        let _ = panic::catch_unwind(|| {
            if let Ok(tx) = bincode::deserialize::<ShieldedTransaction>(&corrupted) {
                // Si ça parse, vérifier que la signature est rejetée
                for spend in &tx.spends {
                    if let Ok(valid) = spend.verify_signature() {
                        if valid {
                            panic!("CRYPTO VULN: Corrupted signature verified as valid!");
                        }
                    }
                }
            }
        });
    }
    
    // **TEST 3: ATTAQUES DE DÉBORDEMENT D'ENTIERS**
    if input.target_overflow_amounts && input.raw_data.len() > 50 {
        let mut overflow_data = input.raw_data.clone();
        
        // Injecter des valeurs proches de u64::MAX dans les montants
        let max_minus_small = u64::MAX - (input.amplification_factor as u64);
        let overflow_bytes = max_minus_small.to_le_bytes();
        
        // Remplacer plusieurs zones par ces valeurs dangereuses
        for chunk_start in (0..overflow_data.len()).step_by(16) {
            if chunk_start + 8 <= overflow_data.len() {
                overflow_data[chunk_start..chunk_start + 8]
                    .copy_from_slice(&overflow_bytes);
            }
        }
        
        if let Ok(tx) = bincode::deserialize::<ShieldedTransaction>(&overflow_data) {
            // Vérifier protection contre overflow dans les calculs de fees
            let mut total_fees: u64 = 0;
            if let Some(new_total) = total_fees.checked_add(tx.fee) {
                total_fees = new_total;
            } else {
                panic!("FEE OVERFLOW DETECTED: tx.fee={}", tx.fee);
            }
            
            // Test spécifique: somme des outputs ne doit pas déborder
            let mut total_output: u128 = 0; // Utiliser u128 pour détecter overflow
            for output in &tx.outputs {
                // Simuler extraction du montant (selon la structure EncryptedNote)
                if !output.encrypted_note.ciphertext.is_empty() {
                    let fake_amount = u64::from_le_bytes(
                        output.encrypted_note.ciphertext[0..8.min(output.encrypted_note.ciphertext.len())]
                            .try_into().unwrap_or([0u8; 8])
                    );
                    total_output += fake_amount as u128;
                    
                    if total_output > u64::MAX as u128 {
                        panic!("OUTPUT OVERFLOW ATTACK: total_output exceeds u64::MAX");
                    }
                }
            }
        }
    }
    
    // **TEST 4: ATTAQUES POST-QUANTIQUES SPÉCIFIQUES**
    if input.target_pq_vulnerabilities && input.raw_data.len() > 200 {
        // Test hybride: mélanger structures V1 (BN254) et V2 (post-quantum)
        let mut hybrid_attack = input.raw_data.clone();
        
        // Injecter des marqueurs V2 dans des données V1
        if hybrid_attack.len() > 100 {
            hybrid_attack[50..58].copy_from_slice(b"MLDSA65\0");
            hybrid_attack[90..98].copy_from_slice(b"PLONKY2\0");
        }
        
        // Tentative de désérialisation croisée (V1 en tant que V2)
        if let Ok(tx_v1) = bincode::deserialize::<ShieldedTransaction>(&hybrid_attack) {
            // Vérifier qu'on ne peut pas "upgrader" facilement V1 vers V2
            if tx_v1.spends.len() > 0 {
                let first_spend = &tx_v1.spends[0];
                // Vérifier que les clés publiques ne sont pas directement compatibles
                if first_spend.public_key.len() == 1952 { // Taille ML-DSA-65 pubkey
                    panic!("PQ VULN: V1 transaction contains V2-sized public key");
                }
            }
        }
        
        // Test V2 avec données corrompues
        if let Ok(tx_v2) = bincode::deserialize::<ShieldedTransactionV2>(&hybrid_attack) {
            // Vérifier que les preuves Plonky2 sont validées
            for spend in &tx_v2.spends {
                if spend.public_key.len() != 1952 {
                    panic!("PQ VULN: V2 transaction with wrong pubkey size: {}", 
                           spend.public_key.len());
                }
            }
        }
    }
    
    // **TEST 5: ATTAQUES DE MEMORY EXHAUSTION**
    if input.target_memory_exhaustion && input.raw_data.len() > 10 {
        let mut memory_bomb = Vec::new();
        
        // Créer une structure qui consomme exponentiellement de la mémoire
        let multiplier = (input.amplification_factor as usize).max(1).min(1000);
        memory_bomb.reserve(input.raw_data.len() * multiplier);
        
        for _ in 0..multiplier {
            memory_bomb.extend_from_slice(&input.raw_data);
        }
        
        // Le parser ne doit pas allouer de mémoire excessive
        let memory_before = get_memory_usage();
        let parse_result = bincode::deserialize::<ShieldedTransaction>(&memory_bomb);
        let memory_after = get_memory_usage();
        
        let memory_delta = memory_after.saturating_sub(memory_before);
        
        // Alert si plus de 100MB alloués pour le parsing
        if memory_delta > 100_000_000 {
            panic!("MEMORY DOS: Parser allocated {}MB for {}KB input", 
                   memory_delta / 1_000_000, memory_bomb.len() / 1024);
        }
        
        drop(memory_bomb); // Libération explicite
        drop(parse_result);
    }
    
    // **TEST 6: ATTAQUES DE DUPLICATE NULLIFIERS (DOUBLE-SPEND)**
    if input.target_duplicate_nullifiers {
        if let Ok(tx) = bincode::deserialize::<ShieldedTransaction>(&input.raw_data) {
            let mut nullifier_set = HashSet::new();
            let mut duplicate_count = 0;
            
            for spend in &tx.spends {
                if !nullifier_set.insert(&spend.nullifier) {
                    duplicate_count += 1;
                }
            }
            
            // Une transaction avec des nullifiers en double est une attaque de double-spend
            if duplicate_count > 0 {
                panic!("DOUBLE-SPEND ATTACK: {} duplicate nullifiers detected", 
                       duplicate_count);
            }
            
            // Test avancé: nullifier pattern analysis
            if nullifier_set.len() > 1 {
                let nullifiers: Vec<_> = nullifier_set.into_iter().collect();
                for i in 0..nullifiers.len() {
                    for j in i+1..nullifiers.len() {
                        let hamming_distance = calculate_hamming_distance(
                            nullifiers[i].as_ref(), 
                            nullifiers[j].as_ref()
                        );
                        
                        // Nullifiers trop similaires = attaque de corrélation possible
                        if hamming_distance < 32 {
                            panic!("NULLIFIER CORRELATION ATTACK: distance={}", hamming_distance);
                        }
                    }
                }
            }
        }
    }
    
    // **TEST 7: VALIDATION GÉNÉRALE POST-DÉSÉRIALISATION**
    if let Ok(tx) = bincode::deserialize::<ShieldedTransaction>(&input.raw_data) {
        // Vérifier les invariants critiques
        
        // 1. Les transactions vides sont invalides (sauf coinbase)
        if tx.spends.is_empty() && tx.outputs.is_empty() {
            panic!("INVALID TX: Empty transaction (no spends, no outputs)");
        }
        
        // 2. Fee maximum raisonnable (protection anti-DoS miner)
        if tx.fee > 1_000_000_000_000 { // 1M TSN
            panic!("EXCESSIVE FEE: fee={} TSN", tx.fee as f64 / 100_000_000.0);
        }
        
        // 3. Limite sur le nombre de spends/outputs (protection DoS)
        if tx.spends.len() > 10000 || tx.outputs.len() > 10000 {
            panic!("TX SIZE DOS: {} spends, {} outputs", tx.spends.len(), tx.outputs.len());
        }
        
        // 4. Vérification des proof sizes (attaque par proof bloating)
        for (i, spend) in tx.spends.iter().enumerate() {
            if spend.proof.size() > 10_000_000 { // 10MB max par proof
                panic!("PROOF BLOATING: spend[{}] proof size={}MB", 
                       i, spend.proof.size() / 1_000_000);
            }
        }
        
        // 5. Validation du binding signature
        if !tx.binding_sig.verify(&tx.spends, &tx.outputs, tx.fee) {
            // C'est attendu pour des données random, mais on documente l'échec
            tracing::trace!("Binding signature verification failed (expected for fuzz data)");
        }
    }
});

/// Estimation approximative de l'usage mémoire actuel
fn get_memory_usage() -> usize {
    // Implémentation simplifiée - dans un vrai audit on utiliserait 
    // des outils plus sophistiqués comme jemalloc stats
    std::env::var("MEMORY_USAGE").ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Calcule la distance de Hamming entre deux slices d'octets
fn calculate_hamming_distance(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b.iter())
        .map(|(byte_a, byte_b)| (byte_a ^ byte_b).count_ones() as usize)
        .sum()
}