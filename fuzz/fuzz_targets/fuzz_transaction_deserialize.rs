#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use tsn::core::transaction::{Transaction, TransactionInput, TransactionOutput};
use tsn::crypto::nullifier::Nullifier;

#[derive(Arbitrary, Debug)]
struct FuzzTxInput {
    data: Vec<u8>,
    zero_inputs: bool,
    duplicate_nullifiers: bool,
    overflow_outputs: bool,
}

fuzz_target!(|input: FuzzTxInput| {
    // Test 1: Désérialisation avec validation
    if let Ok(tx) = Transaction::deserialize(&input.data) {
        // Vérification: pas de transaction avec uniquement des outputs (sauf coinbase)
        if tx.inputs.is_empty() && !tx.outputs.is_empty() {
            // Doit être une transaction coinbase - vérifier la hauteur
            if let Some(height) = tx.coinbase_height {
                if height == 0 {
                    panic!("Invalid coinbase height: 0");
                }
            } else {
                // Transaction non-coinbase sans inputs - double spend potentiel
                panic!("Non-coinbase transaction without inputs");
            }
        }
        
        // Test 2: Vérification des nullifiers uniques (protection contre double spend)
        if input.duplicate_nullifiers && !tx.inputs.is_empty() {
            let mut nullifiers = std::collections::HashSet::new();
            for input in &tx.inputs {
                if let Some(nullifier) = &input.nullifier {
                    if !nullifiers.insert(nullifier.clone()) {
                        // Nullifier en double détecté - FAIL
                        panic!("Duplicate nullifier detected: {:?}", nullifier);
                    }
                }
            }
        }
        
        // Test 3: Vérification des montants (prévention overflow)
        if input.overflow_outputs {
            let mut total_output: u64 = 0;
            for output in &tx.outputs {
                total_output = match total_output.checked_add(output.amount) {
                    Some(sum) => sum,
                    None => {
                        // Overflow détecté - FAIL
                        panic!("Output amount overflow detected");
                    }
                };
            }
            
            // Vérifier que le total n'est pas déraisonnable
            if total_output > 21_000_000_000_000_000 { // 21M TSN avec 8 décimales
                panic!("Total output exceeds max supply: {}", total_output);
            }
        }
        
        // Test 4: Vérification de la taille
        if tx.inputs.len() > 1000 || tx.outputs.len() > 1000 {
            // DoS potentiel - transaction trop grande
            panic!("Transaction too large: {} inputs, {} outputs", 
                   tx.inputs.len(), tx.outputs.len());
        }
    }
    
    // Test 5: Attaque par transaction ciculaire (output qui référence input)
    if input.data.len() > 64 {
        // Tenter de créer une référence circulaire
        let mut circular_data = input.data.clone();
        // Copier les 32 premiers octets vers la fin
        let len = circular_data.len();
        for i in 0..32 {
            if len > 32 + i {
                circular_data[len - 32 + i] = circular_data[i];
            }
        }
        
        // Ne doit pas parser en transaction valide
        if let Ok(tx) = Transaction::deserialize(&circular_data) {
            // Si ça parse, vérifier qu'il n'y a pas de référence circulaire
            for (i, input) in tx.inputs.iter().enumerate() {
                for (j, output) in tx.outputs.iter().enumerate() {
                    if i == j && input.nullifier.is_some() {
                        // Référence suspecte détectée
                        panic!("Potential circular reference in transaction");
                    }
                }
            }
        }
    }
});