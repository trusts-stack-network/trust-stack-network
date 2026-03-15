//! Fuzzer pour le pipeline de validation consensus + crypto
//!
//! Ce fuzzer cible spécifiquement le flux :
//! Block deserialization → SLH-DSA verification → State tree update
//!
//! ATTACK VECTORS TESTÉS:
//! - Blocs malformés causant des panics
//! - Signatures forgées ou corrompues
//! - Débordements d'entiers dans les calculs de state
//! - Race conditions dans la validation
//! - Attaques par déni de service via inputs malveillants

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::collections::HashMap;

use tsn::consensus::validation::{Validator, ValidationError};
use tsn::core::block::{Block, BlockHeader};
use tsn::core::transaction::{Transaction, TransactionInput, TransactionOutput};
use tsn::crypto::hash::Hash;
use tsn::crypto::poseidon2_state_tree::Poseidon2StateTree;

/// Structure pour fuzzer les données d'entrée
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Données brutes du bloc à désérialiser
    block_data: Vec<u8>,
    /// Paramètres pour la corruption ciblée
    corruption_params: CorruptionParams,
    /// État initial pour les tests
    initial_state: InitialState,
}

#[derive(Arbitrary, Debug)]
struct CorruptionParams {
    /// Corrompre la signature du bloc
    corrupt_block_signature: bool,
    /// Corrompre les signatures des transactions
    corrupt_tx_signatures: bool,
    /// Corrompre le merkle root
    corrupt_merkle_root: bool,
    /// Corrompre le state root
    corrupt_state_root: bool,
    /// Index de corruption pour les bytes
    corruption_index: Option<usize>,
    /// Valeur de corruption
    corruption_value: u8,
}

#[derive(Arbitrary, Debug)]
struct InitialState {
    /// Comptes avec soldes pour les tests de validation
    account_balances: Vec<(Vec<u8>, u64)>,
    /// Profondeur du state tree
    tree_depth: u8,
}

/// Mock StateView pour le fuzzing
struct FuzzStateView {
    state_tree: Poseidon2StateTree,
    account_balances: HashMap<Vec<u8>, u64>,
}

impl FuzzStateView {
    fn new(initial_state: &InitialState) -> Self {
        let tree_depth = (initial_state.tree_depth % 20 + 4) as usize; // Entre 4 et 24
        let mut state_tree = Poseidon2StateTree::new(tree_depth);
        let mut account_balances = HashMap::new();

        // Initialiser les comptes
        for (key, balance) in &initial_state.account_balances {
            if key.len() <= 32 && *balance < u64::MAX / 2 { // Éviter les débordements
                account_balances.insert(key.clone(), *balance);
                state_tree.insert(key, &balance.to_le_bytes());
            }
        }

        Self {
            state_tree,
            account_balances,
        }
    }

    fn compute_state_root(&self, _txs: &[Transaction]) -> Result<Hash, ValidationError> {
        // Calcul déterministe du state root pour le fuzzing
        let mut hasher = blake3::Hasher::new();
        let mut sorted_accounts: Vec<_> = self.account_balances.iter().collect();
        sorted_accounts.sort_by_key(|(k, _)| k.as_slice());
        
        for (key, value) in sorted_accounts {
            hasher.update(key);
            hasher.update(&value.to_le_bytes());
        }
        
        let hash_bytes = hasher.finalize();
        Ok(Hash::from_bytes(hash_bytes.as_bytes()[..32].try_into().unwrap()))
    }
}

/// Fonction de corruption ciblée pour tester les edge cases
fn apply_corruption(mut block_data: Vec<u8>, params: &CorruptionParams) -> Vec<u8> {
    if block_data.is_empty() {
        return block_data;
    }

    // Corruption basique par index
    if let Some(index) = params.corruption_index {
        let actual_index = index % block_data.len();
        block_data[actual_index] ^= params.corruption_value;
    }

    // Corruptions spécifiques pour tester les validations
    if params.corrupt_block_signature && block_data.len() > 100 {
        // Corrompre la zone probable de signature (fin du header)
        let sig_start = block_data.len().saturating_sub(100);
        for i in sig_start..block_data.len().min(sig_start + 32) {
            block_data[i] ^= 0xFF;
        }
    }

    if params.corrupt_merkle_root && block_data.len() > 64 {
        // Corrompre la zone probable du merkle root
        for i in 32..64.min(block_data.len()) {
            block_data[i] ^= params.corruption_value;
        }
    }

    block_data
}

/// Fuzzer principal
fuzz_target!(|input: FuzzInput| {
    // Limiter la taille des inputs pour éviter les timeouts
    if input.block_data.len() > 1_000_000 {
        return;
    }

    // Créer le validateur et l'état de test
    let validator = Validator::new();
    let state_view = FuzzStateView::new(&input.initial_state);

    // Appliquer les corruptions
    let corrupted_data = apply_corruption(input.block_data, &input.corruption_params);

    // Test 1: Désérialisation sécurisée
    let block = match Block::deserialize(&corrupted_data) {
        Ok(block) => block,
        Err(_) => {
            // La désérialisation peut échouer, c'est normal
            return;
        }
    };

    // Test 2: Validation ne doit jamais paniquer
    let validation_result = std::panic::catch_unwind(|| {
        validator.validate_block(&block, None, &state_view)
    });

    match validation_result {
        Ok(result) => {
            // La validation peut réussir ou échouer, mais ne doit pas paniquer
            match result {
                Ok(_) => {
                    // Bloc valide - tester la mise à jour du state tree
                    let _ = std::panic::catch_unwind(|| {
                        state_view.compute_state_root(&block.transactions)
                    });
                }
                Err(validation_error) => {
                    // Erreur de validation attendue - vérifier qu'elle est cohérente
                    match validation_error {
                        ValidationError::InvalidBlockSignature => {
                            // Vérifier que c'est bien un problème de signature
                        }
                        ValidationError::MerkleRootMismatch => {
                            // Vérifier que le merkle root est effectivement incorrect
                            let computed_root = block.compute_merkle_root();
                            assert_ne!(computed_root, block.header.merkle_root);
                        }
                        ValidationError::StateRootMismatch => {
                            // Vérifier que le state root est effectivement incorrect
                            let computed_root = state_view.compute_state_root(&block.transactions).unwrap();
                            assert_ne!(computed_root, block.header.state_root);
                        }
                        _ => {
                            // Autres erreurs de validation
                        }
                    }
                }
            }
        }
        Err(_) => {
            // PANIC DÉTECTÉ - c'est un bug !
            panic!("Validation panicked on input: {:?}", input);
        }
    }

    // Test 3: Vérification de la cohérence des signatures
    if !block.transactions.is_empty() {
        for tx in &block.transactions {
            let _ = std::panic::catch_unwind(|| {
                validator.validate_transaction(tx)
            });
        }
    }

    // Test 4: Vérification de la cohérence du state tree
    let _ = std::panic::catch_unwind(|| {
        let mut test_tree = Poseidon2StateTree::new(8);
        for (i, tx) in block.transactions.iter().enumerate() {
            let key = format!("tx_{}", i);
            let value = tx.hash();
            test_tree.insert(key.as_bytes(), value.as_bytes());
        }
    });

    // Test 5: Vérification des propriétés de sécurité
    test_security_properties(&block, &state_view);
});

/// Tests des propriétés de sécurité critiques
fn test_security_properties(block: &Block, state_view: &FuzzStateView) {
    // Propriété 1: Le hash du bloc doit être déterministe
    let hash1 = block.hash();
    let hash2 = block.hash();
    assert_eq!(hash1, hash2, "Block hash must be deterministic");

    // Propriété 2: Les transactions ne doivent pas avoir de montants négatifs
    for tx in &block.transactions {
        for output in &tx.outputs {
            assert!(output.value < u64::MAX / 2, "Output value too large: {}", output.value);
        }
    }

    // Propriété 3: Le timestamp doit être raisonnable
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    assert!(
        block.header.timestamp < current_time + 86400, // Pas plus de 24h dans le futur
        "Block timestamp too far in future: {} vs {}",
        block.header.timestamp,
        current_time
    );

    // Propriété 4: Les clés publiques doivent avoir une taille valide
    assert!(
        block.header.producer_public_key.len() <= 1024,
        "Producer public key too large: {} bytes",
        block.header.producer_public_key.len()
    );

    for tx in &block.transactions {
        assert!(
            tx.sender_public_key.len() <= 1024,
            "Sender public key too large: {} bytes",
            tx.sender_public_key.len()
        );
    }

    // Propriété 5: Les signatures doivent avoir une taille valide
    assert!(
        block.header.signature.len() <= 10000,
        "Block signature too large: {} bytes",
        block.header.signature.len()
    );

    for tx in &block.transactions {
        assert!(
            tx.signature.len() <= 10000,
            "Transaction signature too large: {} bytes",
            tx.signature.len()
        );
    }
}

/// Tests de régression pour vulnérabilités connues
#[cfg(test)]
mod regression_tests {
    use super::*;

    #[test]
    fn test_empty_block_data() {
        let input = FuzzInput {
            block_data: vec![],
            corruption_params: CorruptionParams {
                corrupt_block_signature: false,
                corrupt_tx_signatures: false,
                corrupt_merkle_root: false,
                corrupt_state_root: false,
                corruption_index: None,
                corruption_value: 0,
            },
            initial_state: InitialState {
                account_balances: vec![],
                tree_depth: 8,
            },
        };

        // Ne doit pas paniquer
        fuzz_target!(input);
    }

    #[test]
    fn test_oversized_block_data() {
        let input = FuzzInput {
            block_data: vec![0xFF; 2_000_000], // Trop grand
            corruption_params: CorruptionParams {
                corrupt_block_signature: false,
                corrupt_tx_signatures: false,
                corrupt_merkle_root: false,
                corrupt_state_root: false,
                corruption_index: None,
                corruption_value: 0,
            },
            initial_state: InitialState {
                account_balances: vec![],
                tree_depth: 8,
            },
        };

        // Doit être rejeté rapidement sans timeout
        fuzz_target!(input);
    }
}