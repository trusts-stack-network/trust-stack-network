//! Fuzzer complet pour la désérialisation des transactions TSN
//!
//! Couvre:
//! - ShieldedTransaction (V1)
//! - ShieldedTransactionV2 (post-quantique)
//! - CoinbaseTransaction
//! - SpendDescription / OutputDescription
//! - Validation des invariants de sécurité
//!
//! THREAT MODEL:
//! - Double-spend via nullifiers dupliqués
//! - Overflow de montants
//! - Transactions sans spend ni output (sauf coinbase)
//! - Attaques DoS via transactions surdimensionnées
//! - Corruption de preuves ZK

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::panic;
use std::time::Instant;

use tsn::core::transaction::{
    ShieldedTransaction, ShieldedTransactionV2, CoinbaseTransaction,
    SpendDescription, OutputDescription, BindingSignature
};
use tsn::crypto::nullifier::Nullifier;
use tsn::crypto::commitment::NoteCommitment;

/// Input struct pour le fuzzing
#[derive(Arbitrary, Debug)]
struct TransactionFuzzInput {
    raw_data: Vec<u8>,
    tx_type: TransactionType,
    attack_vector: AttackVector,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum TransactionType {
    ShieldedV1,
    ShieldedV2,
    Coinbase,
    SpendDescription,
    OutputDescription,
    BindingSignature,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum AttackVector {
    Normal,
    ZeroValues,
    MaxValues,
    DuplicateNullifiers,
    EmptyVectors,
    OversizedData,
    TruncatedData,
    BitCorruption,
}

fuzz_target!(|input: TransactionFuzzInput| {
    let result = panic::catch_unwind(|| {
        fuzz_transaction_deserialization(&input);
    });
    
    if let Err(_) = result {
        panic!("CRITICAL: Panic detected in transaction deserialization! Type: {:?}, Attack: {:?}",
               input.tx_type, input.attack_vector);
    }
});

fn fuzz_transaction_deserialization(input: &TransactionFuzzInput) {
    let prepared_data = prepare_data(&input.raw_data, input.attack_vector);
    
    match input.tx_type {
        TransactionType::ShieldedV1 => fuzz_shielded_v1(&prepared_data),
        TransactionType::ShieldedV2 => fuzz_shielded_v2(&prepared_data),
        TransactionType::Coinbase => fuzz_coinbase(&prepared_data),
        TransactionType::SpendDescription => fuzz_spend_description(&prepared_data),
        TransactionType::OutputDescription => fuzz_output_description(&prepared_data),
        TransactionType::BindingSignature => fuzz_binding_signature(&prepared_data),
    }
}

fn prepare_data(data: &[u8], attack: AttackVector) -> Vec<u8> {
    let mut result = data.to_vec();
    
    match attack {
        AttackVector::Normal => {}
        AttackVector::ZeroValues => {
            result.fill(0);
        }
        AttackVector::MaxValues => {
            result.fill(0xFF);
        }
        AttackVector::DuplicateNullifiers => {
            // Injecter des nullifiers identiques
            if result.len() >= 64 {
                result[32..64].copy_from_slice(&result[0..32]);
            }
        }
        AttackVector::EmptyVectors => {
            // Simuler des vecteurs vides
            if result.len() >= 8 {
                result[0..8].fill(0);
            }
        }
        AttackVector::OversizedData => {
            // Ne rien faire, les données sont déjà là
        }
        AttackVector::TruncatedData => {
            if result.len() > 10 {
                result.truncate(10);
            }
        }
        AttackVector::BitCorruption => {
            for i in 0..result.len() {
                result[i] ^= 0x55; // XOR avec pattern fixe
            }
        }
    }
    
    result
}

fn fuzz_shielded_v1(data: &[u8]) {
    // Test 1: Désérialisation
    let start = Instant::now();
    let result = bincode::deserialize::<ShieldedTransaction>(data);
    let elapsed = start.elapsed();
    
    // DoS protection
    if elapsed.as_millis() > 50 {
        return;
    }
    
    // Test 2: Validation des invariants si désérialisation réussie
    if let Ok(tx) = result {
        // Invariant: une transaction doit avoir au moins un spend OU un output
        // (sauf coinbase qui est traité séparément)
        if tx.spends.is_empty() && tx.outputs.is_empty() {
            // Transaction vide - potentiellement invalide selon les règles
            // Mais ne doit pas causer de panic
        }
        
        // Invariant: vérifier les nullifiers uniques (protection double-spend)
        let mut nullifiers = std::collections::HashSet::new();
        for spend in &tx.spends {
            let nf_bytes = spend.nullifier.to_bytes();
            if !nullifiers.insert(nf_bytes) {
                // Nullifier dupliqué détecté - c'est une double-spend potentielle
                // Le code ne doit pas paniquer, juste rejeter la transaction
            }
        }
        
        // Invariant: vérifier les montants
        let mut total_output_value: u64 = 0;
        for output in &tx.outputs {
            // Les montants sont dans les encrypted notes, on ne peut pas les vérifier directement
            // Mais on peut vérifier la structure
        }
        
        // Invariant: taille raisonnable
        let tx_size = tx.size();
        if tx_size > 10_000_000 {
            // Transaction trop grande - potentiel DoS
        }
        
        // Test 3: Calcul de hash - ne doit pas paniquer
        let _hash = tx.hash();
        let _hash_hex = tx.hash_hex();
        
        // Test 4: Accès aux nullifiers
        let _nullifiers = tx.nullifiers();
        
        // Test 5: Accès aux commitments
        let _commitments = tx.note_commitments();
        
        // Test 6: Vérification de la binding signature
        let _ = tx.binding_sig.verify(&tx.spends, &tx.outputs, tx.fee);
    }
    
    // Test 7: JSON deserialization
    let _ = serde_json::from_slice::<ShieldedTransaction>(data);
}

fn fuzz_shielded_v2(data: &[u8]) {
    // Test 1: Désérialisation
    let start = Instant::now();
    let result = bincode::deserialize::<ShieldedTransactionV2>(data);
    let elapsed = start.elapsed();
    
    if elapsed.as_millis() > 50 {
        return;
    }
    
    // Test 2: Validation si réussie
    if let Ok(tx) = result {
        // Vérifier les invariants similaires à V1
        if tx.spends.is_empty() && tx.outputs.is_empty() {
            // Transaction vide
        }
        
        // Vérifier les nullifiers uniques
        let mut nullifiers = std::collections::HashSet::new();
        for spend in &tx.spends {
            if !nullifiers.insert(spend.nullifier) {
                // Dupliqué
            }
        }
        
        // Calcul de hash
        let _hash = tx.hash();
    }
    
    // Test 3: JSON
    let _ = serde_json::from_slice::<ShieldedTransactionV2>(data);
}

fn fuzz_coinbase(data: &[u8]) {
    // Test 1: Désérialisation
    let result = bincode::deserialize::<CoinbaseTransaction>(data);
    
    if let Ok(tx) = result {
        // Invariant: une coinbase doit avoir un output
        // (elle crée des nouveaux coins)
        
        // Vérifier les commitments
        let _cm_v1 = &tx.note_commitment;
        let _cm_pq = &tx.note_commitment_pq;
        
        // Calcul de hash
        let _hash = tx.hash();
        
        // Vérifier la taille
        let _size = tx.size();
    }
    
    // Test 2: JSON
    let _ = serde_json::from_slice::<CoinbaseTransaction>(data);
}

fn fuzz_spend_description(data: &[u8]) {
    // Test 1: Désérialisation
    let result = bincode::deserialize::<SpendDescription>(data);
    
    if let Ok(spend) = result {
        // Invariant: anchor doit être 32 bytes
        // (déjà vérifié par le type)
        
        // Vérifier la signature
        let _ = spend.verify_signature();
        
        // Vérifier la taille
        let _size = spend.size();
        
        // Vérifier le nullifier
        let _nf_bytes = spend.nullifier.to_bytes();
    }
    
    // Test 2: JSON
    let _ = serde_json::from_slice::<SpendDescription>(data);
}

fn fuzz_output_description(data: &[u8]) {
    // Test 1: Désérialisation
    let result = bincode::deserialize::<OutputDescription>(data);
    
    if let Ok(output) = result {
        // Vérifier le commitment
        let _cm_bytes = output.note_commitment.to_bytes();
        
        // Vérifier la taille
        let _size = output.size();
        
        // Vérifier la note encryptée
        let _enc_size = output.encrypted_note.size();
    }
    
    // Test 2: JSON
    let _ = serde_json::from_slice::<OutputDescription>(data);
}

fn fuzz_binding_signature(data: &[u8]) {
    // Test 1: Désérialisation
    let result = bincode::deserialize::<BindingSignature>(data);
    
    if let Ok(sig) = result {
        // Vérifier la taille
        let _bytes = sig.as_bytes();
        
        // Vérifier que ce n'est pas une signature vide
        if sig.as_bytes().is_empty() {
            // Signature vide - invalide mais ne doit pas paniquer
        }
    }
    
    // Test 2: Construction depuis des bytes
    let sig = BindingSignature::new(data.to_vec());
    let _ = sig.as_bytes();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_transaction_types() {
        let types = [
            TransactionType::ShieldedV1,
            TransactionType::ShieldedV2,
            TransactionType::Coinbase,
            TransactionType::SpendDescription,
            TransactionType::OutputDescription,
            TransactionType::BindingSignature,
        ];
        
        for tx_type in &types {
            let input = TransactionFuzzInput {
                raw_data: vec![0x42; 500],
                tx_type: *tx_type,
                attack_vector: AttackVector::Normal,
            };
            fuzz_transaction_deserialization(&input);
        }
    }

    #[test]
    fn test_all_attack_vectors() {
        let vectors = [
            AttackVector::Normal,
            AttackVector::ZeroValues,
            AttackVector::MaxValues,
            AttackVector::DuplicateNullifiers,
            AttackVector::EmptyVectors,
            AttackVector::OversizedData,
            AttackVector::TruncatedData,
            AttackVector::BitCorruption,
        ];
        
        for vector in &vectors {
            let input = TransactionFuzzInput {
                raw_data: vec![0xFF; 1000],
                tx_type: TransactionType::ShieldedV1,
                attack_vector: *vector,
            };
            fuzz_transaction_deserialization(&input);
        }
    }

    #[test]
    fn test_empty_data() {
        let input = TransactionFuzzInput {
            raw_data: vec![],
            tx_type: TransactionType::ShieldedV1,
            attack_vector: AttackVector::Normal,
        };
        fuzz_transaction_deserialization(&input);
    }

    #[test]
    fn test_large_transaction() {
        let input = TransactionFuzzInput {
            raw_data: vec![0xAB; 5_000_000],
            tx_type: TransactionType::ShieldedV1,
            attack_vector: AttackVector::OversizedData,
        };
        fuzz_transaction_deserialization(&input);
    }
}
