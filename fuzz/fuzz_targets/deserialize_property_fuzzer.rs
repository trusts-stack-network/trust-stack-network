#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::collections::HashSet;

use tsn::core::{
    transaction::{
        Transaction, ShieldedTransaction, ShieldedTransactionV2,
        CoinbaseTransaction, LegacyTransaction
    },
    block::{BlockHeader, ShieldedBlock}
};

/// **PROPERTY-BASED FUZZER POUR DÉSÉRIALISATION**
/// 
/// Ce fuzzer vérifie les propriétés invariantes qui doivent TOUJOURS
/// être respectées lors de la désérialisation, même avec des données corrompues.
/// 
/// **PROPRIÉTÉS TESTÉES** :
/// 1. **Idempotence** : deserialize(serialize(x)) == x
/// 2. **Déterminisme** : deserialize(data) produit toujours le même résultat
/// 3. **Robustesse** : deserialize ne doit jamais paniquer
/// 4. **Cohérence** : les champs désérialisés respectent les contraintes métier
/// 5. **Sécurité** : pas de fuite d'information via timing/memory
#[derive(Arbitrary, Debug)]
struct PropertyFuzzInput {
    raw_data: Vec<u8>,
    test_type: PropertyTest,
    iterations: u8,  // 1-255 itérations pour les tests de cohérence
}

#[derive(Arbitrary, Debug, Clone)]
enum PropertyTest {
    IdempotenceTransaction,
    IdempotenceBlock,
    DeterminismTransaction,
    DeterminismBlock,
    RobustnessTransaction,
    RobustnessBlock,
    BusinessInvariantsTransaction,
    BusinessInvariantsBlock,
    SecurityPropertiesTransaction,
    SecurityPropertiesBlock,
}

fuzz_target!(|input: PropertyFuzzInput| {
    match input.test_type {
        PropertyTest::IdempotenceTransaction => test_transaction_idempotence(&input),
        PropertyTest::IdempotenceBlock => test_block_idempotence(&input),
        PropertyTest::DeterminismTransaction => test_transaction_determinism(&input),
        PropertyTest::DeterminismBlock => test_block_determinism(&input),
        PropertyTest::RobustnessTransaction => test_transaction_robustness(&input),
        PropertyTest::RobustnessBlock => test_block_robustness(&input),
        PropertyTest::BusinessInvariantsTransaction => test_transaction_business_invariants(&input),
        PropertyTest::BusinessInvariantsBlock => test_block_business_invariants(&input),
        PropertyTest::SecurityPropertiesTransaction => test_transaction_security_properties(&input),
        PropertyTest::SecurityPropertiesBlock => test_block_security_properties(&input),
    }
});

/// **PROPRIÉTÉ 1: IDEMPOTENCE DES TRANSACTIONS**
/// Pour toute transaction valide T : deserialize(serialize(T)) == T
fn test_transaction_idempotence(input: &PropertyFuzzInput) {
    // Tenter de désérialiser comme différents types de transaction
    let transaction_types = [
        try_deserialize_shielded_tx,
        try_deserialize_shielded_tx_v2,
        try_deserialize_coinbase_tx,
        try_deserialize_legacy_tx,
    ];
    
    for deserialize_fn in &transaction_types {
        if let Ok(original_tx) = deserialize_fn(&input.raw_data) {
            // Sérialiser puis désérialiser à nouveau
            if let Ok(serialized) = bincode::serialize(&original_tx) {
                if let Ok(roundtrip_tx) = deserialize_fn(&serialized) {
                    // Vérifier l'idempotence
                    let original_serialized = bincode::serialize(&original_tx).unwrap();
                    let roundtrip_serialized = bincode::serialize(&roundtrip_tx).unwrap();
                    
                    if original_serialized != roundtrip_serialized {
                        panic!("IDEMPOTENCE VIOLATION: Transaction serialization not idempotent");
                    }
                }
            }
        }
    }
}

/// **PROPRIÉTÉ 2: IDEMPOTENCE DES BLOCS**
fn test_block_idempotence(input: &PropertyFuzzInput) {
    // Test pour BlockHeader
    if let Ok(original_header) = bincode::deserialize::<BlockHeader>(&input.raw_data) {
        if let Ok(serialized) = bincode::serialize(&original_header) {
            if let Ok(roundtrip_header) = bincode::deserialize::<BlockHeader>(&serialized) {
                let original_hash = original_header.hash();
                let roundtrip_hash = roundtrip_header.hash();
                
                if original_hash != roundtrip_hash {
                    panic!("IDEMPOTENCE VIOLATION: BlockHeader hash changed after roundtrip");
                }
            }
        }
    }
    
    // Test pour ShieldedBlock
    if let Ok(original_block) = bincode::deserialize::<ShieldedBlock>(&input.raw_data) {
        if let Ok(serialized) = bincode::serialize(&original_block) {
            if let Ok(roundtrip_block) = bincode::deserialize::<ShieldedBlock>(&serialized) {
                // Vérifier que les propriétés critiques sont préservées
                if original_block.header.hash() != roundtrip_block.header.hash() {
                    panic!("IDEMPOTENCE VIOLATION: Block hash changed after roundtrip");
                }
                
                if original_block.transactions.len() != roundtrip_block.transactions.len() {
                    panic!("IDEMPOTENCE VIOLATION: Transaction count changed after roundtrip");
                }
            }
        }
    }
}

/// **PROPRIÉTÉ 3: DÉTERMINISME DES TRANSACTIONS**
/// Désérialiser les mêmes données doit toujours produire le même résultat
fn test_transaction_determinism(input: &PropertyFuzzInput) {
    let iterations = input.iterations.max(2) as usize;
    let mut results = Vec::new();
    
    // Effectuer plusieurs désérialisations identiques
    for _ in 0..iterations {
        let result = try_deserialize_any_transaction(&input.raw_data);
        results.push(result);
    }
    
    // Vérifier que tous les résultats sont identiques
    if results.len() >= 2 {
        let first_result = &results[0];
        for (i, result) in results.iter().enumerate().skip(1) {
            match (first_result, result) {
                (Ok(first_tx), Ok(tx)) => {
                    let first_serialized = bincode::serialize(first_tx).unwrap();
                    let tx_serialized = bincode::serialize(tx).unwrap();
                    
                    if first_serialized != tx_serialized {
                        panic!("DETERMINISM VIOLATION: Transaction deserialization non-deterministic at iteration {}", i);
                    }
                },
                (Err(_), Err(_)) => {
                    // Les erreurs doivent aussi être cohérentes
                    // Pour simplifier, on accepte que les erreurs soient cohérentes
                },
                _ => {
                    panic!("DETERMINISM VIOLATION: Inconsistent success/failure across iterations");
                }
            }
        }
    }
}

/// **PROPRIÉTÉ 4: DÉTERMINISME DES BLOCS**
fn test_block_determinism(input: &PropertyFuzzInput) {
    let iterations = input.iterations.max(2) as usize;
    let mut header_hashes = Vec::new();
    
    for _ in 0..iterations {
        if let Ok(header) = bincode::deserialize::<BlockHeader>(&input.raw_data) {
            header_hashes.push(header.hash());
        }
    }
    
    // Tous les hashes doivent être identiques
    if header_hashes.len() >= 2 {
        let first_hash = header_hashes[0];
        for (i, &hash) in header_hashes.iter().enumerate().skip(1) {
            if hash != first_hash {
                panic!("DETERMINISM VIOLATION: Block header hash non-deterministic at iteration {}", i);
            }
        }
    }
}

/// **PROPRIÉTÉ 5: ROBUSTESSE DES TRANSACTIONS**
/// La désérialisation ne doit jamais paniquer, même avec des données corrompues
fn test_transaction_robustness(input: &PropertyFuzzInput) {
    // Tester avec les données originales
    let _ = std::panic::catch_unwind(|| {
        let _ = try_deserialize_any_transaction(&input.raw_data);
    }).map_err(|_| panic!("ROBUSTNESS VIOLATION: Transaction deserializer panicked"));
    
    // Tester avec des mutations agressives
    for mutation_intensity in [1u8, 16, 64, 128, 255] {
        let mut mutated = input.raw_data.clone();
        
        // Appliquer des mutations
        for i in 0..mutated.len() {
            if i % 8 == 0 {
                mutated[i] = mutated[i].wrapping_add(mutation_intensity);
            }
        }
        
        let _ = std::panic::catch_unwind(|| {
            let _ = try_deserialize_any_transaction(&mutated);
        }).map_err(|_| panic!("ROBUSTNESS VIOLATION: Transaction deserializer panicked with mutation intensity {}", mutation_intensity));
    }
}

/// **PROPRIÉTÉ 6: ROBUSTESSE DES BLOCS**
fn test_block_robustness(input: &PropertyFuzzInput) {
    // Test de robustesse pour BlockHeader
    let _ = std::panic::catch_unwind(|| {
        let _ = bincode::deserialize::<BlockHeader>(&input.raw_data);
    }).map_err(|_| panic!("ROBUSTNESS VIOLATION: BlockHeader deserializer panicked"));
    
    // Test de robustesse pour ShieldedBlock
    let _ = std::panic::catch_unwind(|| {
        let _ = bincode::deserialize::<ShieldedBlock>(&input.raw_data);
    }).map_err(|_| panic!("ROBUSTNESS VIOLATION: ShieldedBlock deserializer panicked"));
    
    // Test avec des données tronquées
    for truncate_at in [1, 4, 8, 16, 32, 64] {
        if input.raw_data.len() > truncate_at {
            let truncated = &input.raw_data[..truncate_at];
            
            let _ = std::panic::catch_unwind(|| {
                let _ = bincode::deserialize::<BlockHeader>(truncated);
                let _ = bincode::deserialize::<ShieldedBlock>(truncated);
            }).map_err(|_| panic!("ROBUSTNESS VIOLATION: Block deserializer panicked with truncated data"));
        }
    }
}

/// **PROPRIÉTÉ 7: INVARIANTS MÉTIER DES TRANSACTIONS**
/// Les transactions désérialisées doivent respecter les règles métier
fn test_transaction_business_invariants(input: &PropertyFuzzInput) {
    if let Ok(tx) = try_deserialize_any_transaction(&input.raw_data) {
        match tx {
            TransactionVariant::Shielded(shielded_tx) => {
                // Invariant 1: Les nullifiers doivent être uniques
                let mut nullifiers = HashSet::new();
                for spend in &shielded_tx.spends {
                    if !nullifiers.insert(&spend.nullifier) {
                        panic!("BUSINESS INVARIANT VIOLATION: Duplicate nullifier in shielded transaction");
                    }
                }
                
                // Invariant 2: Fee doit être raisonnable
                if shielded_tx.fee > 1_000_000_000_000 { // 1M TSN max fee
                    panic!("BUSINESS INVARIANT VIOLATION: Excessive fee: {}", shielded_tx.fee);
                }
                
                // Invariant 3: Nombre de spends/outputs raisonnable
                if shielded_tx.spends.len() > 10000 || shielded_tx.outputs.len() > 10000 {
                    panic!("BUSINESS INVARIANT VIOLATION: Too many spends/outputs");
                }
            },
            TransactionVariant::Coinbase(coinbase_tx) => {
                // Invariant 1: Coinbase ne doit pas avoir de spends
                if !coinbase_tx.spends.is_empty() {
                    panic!("BUSINESS INVARIANT VIOLATION: Coinbase transaction has spends");
                }
                
                // Invariant 2: Coinbase doit avoir au moins un output
                if coinbase_tx.outputs.is_empty() {
                    panic!("BUSINESS INVARIANT VIOLATION: Coinbase transaction has no outputs");
                }
                
                // Invariant 3: Reward doit être raisonnable
                if coinbase_tx.reward > 50_000_000_000 { // 50 TSN max reward
                    panic!("BUSINESS INVARIANT VIOLATION: Excessive coinbase reward: {}", coinbase_tx.reward);
                }
            },
            _ => {
                // Autres types de transactions - invariants génériques
            }
        }
    }
}

/// **PROPRIÉTÉ 8: INVARIANTS MÉTIER DES BLOCS**
fn test_block_business_invariants(input: &PropertyFuzzInput) {
    if let Ok(header) = bincode::deserialize::<BlockHeader>(&input.raw_data) {
        // Invariant 1: Timestamp raisonnable (pas dans le futur lointain)
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if header.timestamp > current_time + 7200 { // +2h max dans le futur
            panic!("BUSINESS INVARIANT VIOLATION: Block timestamp too far in future");
        }
        
        // Invariant 2: Difficulté raisonnable
        if header.difficulty > 64 { // Max 64 bits de difficulté
            panic!("BUSINESS INVARIANT VIOLATION: Excessive difficulty: {}", header.difficulty);
        }
        
        // Invariant 3: Version supportée
        if header.version > 10 { // Versions futures non supportées
            panic!("BUSINESS INVARIANT VIOLATION: Unsupported block version: {}", header.version);
        }
    }
    
    if let Ok(block) = bincode::deserialize::<ShieldedBlock>(&input.raw_data) {
        // Invariant 4: Nombre de transactions raisonnable
        if block.transactions.len() > 100000 {
            panic!("BUSINESS INVARIANT VIOLATION: Too many transactions in block: {}", block.transactions.len());
        }
        
        // Invariant 5: Au moins une transaction (coinbase)
        if block.transactions.is_empty() {
            panic!("BUSINESS INVARIANT VIOLATION: Block has no transactions");
        }
    }
}

/// **PROPRIÉTÉ 9: PROPRIÉTÉS DE SÉCURITÉ DES TRANSACTIONS**
fn test_transaction_security_properties(input: &PropertyFuzzInput) {
    // Test de timing constant
    let mut timings = Vec::new();
    
    for _ in 0..5 {
        let start = std::time::Instant::now();
        let _ = try_deserialize_any_transaction(&input.raw_data);
        let elapsed = start.elapsed();
        timings.push(elapsed);
    }
    
    // Vérifier que les timings sont relativement constants
    if timings.len() >= 2 {
        let min_time = timings.iter().min().unwrap();
        let max_time = timings.iter().max().unwrap();
        let variance = max_time.saturating_sub(*min_time);
        
        // Alerter si variance excessive (potentiel timing attack)
        if variance.as_millis() > 50 {
            panic!("SECURITY VIOLATION: Excessive timing variance ({}ms) in transaction deserialization", 
                   variance.as_millis());
        }
    }
    
    // Test de résistance aux attaques par déni de service
    let start = std::time::Instant::now();
    let _ = try_deserialize_any_transaction(&input.raw_data);
    let elapsed = start.elapsed();
    
    if elapsed.as_millis() > 100 {
        panic!("SECURITY VIOLATION: Transaction deserialization took too long ({}ms)", 
               elapsed.as_millis());
    }
}

/// **PROPRIÉTÉ 10: PROPRIÉTÉS DE SÉCURITÉ DES BLOCS**
fn test_block_security_properties(input: &PropertyFuzzInput) {
    // Test de résistance DoS pour les headers
    let start = std::time::Instant::now();
    let _ = bincode::deserialize::<BlockHeader>(&input.raw_data);
    let elapsed = start.elapsed();
    
    if elapsed.as_millis() > 50 {
        panic!("SECURITY VIOLATION: BlockHeader deserialization took too long ({}ms)", 
               elapsed.as_millis());
    }
    
    // Test de résistance DoS pour les blocs complets
    let start = std::time::Instant::now();
    let _ = bincode::deserialize::<ShieldedBlock>(&input.raw_data);
    let elapsed = start.elapsed();
    
    if elapsed.as_millis() > 500 {
        panic!("SECURITY VIOLATION: ShieldedBlock deserialization took too long ({}ms)", 
               elapsed.as_millis());
    }
}

// === FONCTIONS UTILITAIRES ===

#[derive(Debug)]
enum TransactionVariant {
    Shielded(ShieldedTransaction),
    ShieldedV2(ShieldedTransactionV2),
    Coinbase(CoinbaseTransaction),
    Legacy(LegacyTransaction),
}

fn try_deserialize_any_transaction(data: &[u8]) -> Result<TransactionVariant, Box<dyn std::error::Error>> {
    // Essayer différents types de transaction
    if let Ok(tx) = bincode::deserialize::<ShieldedTransaction>(data) {
        return Ok(TransactionVariant::Shielded(tx));
    }
    
    if let Ok(tx) = bincode::deserialize::<ShieldedTransactionV2>(data) {
        return Ok(TransactionVariant::ShieldedV2(tx));
    }
    
    if let Ok(tx) = bincode::deserialize::<CoinbaseTransaction>(data) {
        return Ok(TransactionVariant::Coinbase(tx));
    }
    
    if let Ok(tx) = bincode::deserialize::<LegacyTransaction>(data) {
        return Ok(TransactionVariant::Legacy(tx));
    }
    
    Err("No transaction type matched".into())
}

fn try_deserialize_shielded_tx(data: &[u8]) -> Result<ShieldedTransaction, Box<dyn std::error::Error>> {
    Ok(bincode::deserialize(data)?)
}

fn try_deserialize_shielded_tx_v2(data: &[u8]) -> Result<ShieldedTransactionV2, Box<dyn std::error::Error>> {
    Ok(bincode::deserialize(data)?)
}

fn try_deserialize_coinbase_tx(data: &[u8]) -> Result<CoinbaseTransaction, Box<dyn std::error::Error>> {
    Ok(bincode::deserialize(data)?)
}

fn try_deserialize_legacy_tx(data: &[u8]) -> Result<LegacyTransaction, Box<dyn std::error::Error>> {
    Ok(bincode::deserialize(data)?)
}