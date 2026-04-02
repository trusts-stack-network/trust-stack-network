// DISABLED: uses API/modules that no longer exist in current codebase
#![cfg(feature = "disabled_test")]
//! Tests d'intégration consensus + crypto
//!
//! Suite de tests qui vérifie l'ensemble du pipeline :
//! validation de blocs → vérification SLH-DSA → mise à jour du state tree Poseidon2
//!
//! THREAT MODEL:
//! - Adversaire peut forger des blocs malformés
//! - Adversaire peut tenter des attaques par signature forgée
//! - Adversaire peut tenter de corrompre le state tree
//! - Adversaire peut exploiter des race conditions dans la validation

use proptest::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tsn::consensus::validation::{Validator, ValidationError};
use tsn::core::block::{Block, BlockHeader};
use tsn::core::transaction::{Transaction, TransactionInput, TransactionOutput};
use tsn::core::state::ShieldedState;
use tsn::crypto::hash::Hash;
use tsn::crypto::merkle_tree::MerkleTree;
use tsn::crypto::poseidon2_state_tree::Poseidon2StateTree;
use tsn::crypto::pq::slh_dsa::{SlhDsaSigner, SlhDsaVerifier, SLH_DSA_SHA2_128S};
use tsn::crypto::keys::{PublicKey, PrivateKey};

/// Mock StateView pour les tests
struct TestStateView {
    state_tree: Poseidon2StateTree,
    account_balances: HashMap<Vec<u8>, u64>,
}

impl TestStateView {
    fn new() -> Self {
        Self {
            state_tree: Poseidon2StateTree::new(32), // Profondeur 32 pour les tests
            account_balances: HashMap::new(),
        }
    }

    fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), ValidationError> {
        // Simulation simple : débit/crédit des comptes
        for input in &tx.inputs {
            let key = input.previous_output.as_bytes();
            let balance = self.account_balances.get(key).unwrap_or(&0);
            if *balance < 100 { // Montant fixe pour les tests
                return Err(ValidationError::InvalidTransactionSignature);
            }
            self.account_balances.insert(key.to_vec(), balance - 100);
            
            // Mise à jour du state tree
            self.state_tree.insert(key, &(balance - 100).to_le_bytes());
        }

        for (i, output) in tx.outputs.iter().enumerate() {
            let key = format!("{}:{}", hex::encode(&tx.hash().as_bytes()), i);
            self.account_balances.insert(key.as_bytes().to_vec(), output.value);
            
            // Mise à jour du state tree
            self.state_tree.insert(key.as_bytes(), &output.value.to_le_bytes());
        }

        Ok(())
    }

    fn compute_state_root(&self, _txs: &[Transaction]) -> Result<Hash, ValidationError> {
        // Pour les tests, on retourne un hash déterministe basé sur l'état
        let mut hasher = blake3::Hasher::new();
        for (key, value) in &self.account_balances {
            hasher.update(key);
            hasher.update(&value.to_le_bytes());
        }
        let hash_bytes = hasher.finalize();
        Ok(Hash::from_bytes(hash_bytes.as_bytes()[..32].try_into().unwrap()))
    }
}

/// Générateur de blocs valides pour les tests
struct TestBlockGenerator {
    signer: SlhDsaSigner,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

impl TestBlockGenerator {
    fn new() -> Self {
        let signer = SlhDsaSigner::new(SLH_DSA_SHA2_128S);
        let (pk, sk) = signer.generate_keypair().unwrap();
        
        Self {
            signer,
            public_key: pk.to_bytes(),
            private_key: sk.to_bytes(),
        }
    }

    fn create_valid_block(&self, transactions: Vec<Transaction>, previous_hash: Hash, state_root: Hash) -> Block {
        let mut merkle_tree = MerkleTree::new();
        for tx in &transactions {
            merkle_tree.insert(tx.hash()).unwrap();
        }
        let merkle_root = merkle_tree.root();

        let mut header = BlockHeader {
            version: 1,
            previous_block_hash: previous_hash,
            merkle_root,
            state_root,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nonce: 0,
            difficulty: 100,
            producer_public_key: self.public_key.clone(),
            signature: vec![],
        };

        // Signer le header
        let message = header.signature_message();
        let sk = self.signer.secret_key_from_bytes(&self.private_key).unwrap();
        let signature = self.signer.sign(&sk, &message).unwrap();
        header.signature = signature.to_bytes();

        Block {
            header,
            transactions,
        }
    }

    fn create_transaction(&self, inputs: Vec<Hash>, outputs: Vec<u64>) -> Transaction {
        let tx_inputs: Vec<TransactionInput> = inputs.into_iter()
            .map(|hash| TransactionInput {
                previous_output: hash,
                script: vec![],
            })
            .collect();

        let tx_outputs: Vec<TransactionOutput> = outputs.into_iter()
            .map(|value| TransactionOutput {
                value,
                script: vec![],
            })
            .collect();

        let mut tx = Transaction {
            inputs: tx_inputs,
            outputs: tx_outputs,
            sender_public_key: self.public_key.clone(),
            signature: vec![],
        };

        // Signer la transaction
        let message = tx.signature_message();
        let sk = self.signer.secret_key_from_bytes(&self.private_key).unwrap();
        let signature = self.signer.sign(&sk, &message).unwrap();
        tx.signature = signature.to_bytes();

        tx
    }
}

#[test]
fn test_valid_block_validation_flow() {
    let validator = Validator::new();
    let generator = TestBlockGenerator::new();
    let mut state_view = TestStateView::new();

    // Créer une transaction valide
    let tx = generator.create_transaction(
        vec![Hash::zero()],
        vec![100, 50]
    );

    // Calculer le state root après application de la transaction
    let mut temp_state = state_view.clone();
    temp_state.apply_transaction(&tx).unwrap();
    let state_root = temp_state.compute_state_root(&[tx.clone()]).unwrap();

    // Créer un bloc valide
    let block = generator.create_valid_block(
        vec![tx.clone()],
        Hash::zero(),
        state_root
    );

    // La validation doit réussir
    assert!(validator.validate_block(&block, None, &state_view).is_ok());

    // Appliquer le bloc à l'état
    state_view.apply_transaction(&tx).unwrap();
}

#[test]
fn test_invalid_signature_rejection() {
    let validator = Validator::new();
    let generator = TestBlockGenerator::new();
    let state_view = TestStateView::new();

    // Créer une transaction valide
    let tx = generator.create_transaction(
        vec![Hash::zero()],
        vec![100]
    );

    let state_root = state_view.compute_state_root(&[tx.clone()]).unwrap();

    // Créer un bloc avec signature corrompue
    let mut block = generator.create_valid_block(
        vec![tx],
        Hash::zero(),
        state_root
    );

    // Corrompre la signature du bloc
    if !block.header.signature.is_empty() {
        block.header.signature[0] ^= 0x01;
    }

    // La validation doit échouer
    assert!(matches!(
        validator.validate_block(&block, None, &state_view),
        Err(ValidationError::InvalidBlockSignature)
    ));
}

#[test]
fn test_merkle_root_mismatch_rejection() {
    let validator = Validator::new();
    let generator = TestBlockGenerator::new();
    let state_view = TestStateView::new();

    // Créer une transaction valide
    let tx = generator.create_transaction(
        vec![Hash::zero()],
        vec![100]
    );

    let state_root = state_view.compute_state_root(&[tx.clone()]).unwrap();

    // Créer un bloc valide
    let mut block = generator.create_valid_block(
        vec![tx],
        Hash::zero(),
        state_root
    );

    // Corrompre le merkle root
    block.header.merkle_root = Hash::from_bytes([0xFF; 32]);

    // La validation doit échouer
    assert!(matches!(
        validator.validate_block(&block, None, &state_view),
        Err(ValidationError::MerkleRootMismatch)
    ));
}

#[test]
fn test_state_root_mismatch_rejection() {
    let validator = Validator::new();
    let generator = TestBlockGenerator::new();
    let state_view = TestStateView::new();

    // Créer une transaction valide
    let tx = generator.create_transaction(
        vec![Hash::zero()],
        vec![100]
    );

    // Créer un bloc avec un mauvais state root
    let mut block = generator.create_valid_block(
        vec![tx],
        Hash::zero(),
        Hash::from_bytes([0xFF; 32]) // State root incorrect
    );

    // La validation doit échouer
    assert!(matches!(
        validator.validate_block(&block, None, &state_view),
        Err(ValidationError::StateRootMismatch)
    ));
}

#[test]
fn test_timestamp_validation() {
    let validator = Validator::new();
    let generator = TestBlockGenerator::new();
    let state_view = TestStateView::new();

    let tx = generator.create_transaction(vec![Hash::zero()], vec![100]);
    let state_root = state_view.compute_state_root(&[tx.clone()]).unwrap();

    // Test timestamp trop dans le futur
    let mut block = generator.create_valid_block(vec![tx.clone()], Hash::zero(), state_root);
    block.header.timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() + 3600; // 1 heure dans le futur

    assert!(matches!(
        validator.validate_block(&block, None, &state_view),
        Err(ValidationError::TimestampTooFarInFuture)
    ));

    // Test timestamp avant le parent
    let parent_header = BlockHeader {
        version: 1,
        previous_block_hash: Hash::zero(),
        merkle_root: Hash::zero(),
        state_root: Hash::zero(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        nonce: 0,
        difficulty: 100,
        producer_public_key: generator.public_key.clone(),
        signature: vec![],
    };

    let mut block = generator.create_valid_block(vec![tx], Hash::zero(), state_root);
    block.header.timestamp = parent_header.timestamp - 1;

    assert!(matches!(
        validator.validate_block(&block, Some(&parent_header), &state_view),
        Err(ValidationError::TimestampBeforeParent)
    ));
}

// Tests property-based pour robustesse
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_signature_verification_is_deterministic(
        message in prop::collection::vec(any::<u8>(), 0..1000),
        seed in any::<u64>()
    ) {
        let signer = SlhDsaSigner::new(SLH_DSA_SHA2_128S);
        let verifier = SlhDsaVerifier::new(SLH_DSA_SHA2_128S);
        let (pk, sk) = signer.generate_keypair().unwrap();

        let signature = signer.sign(&sk, &message).unwrap();

        // La vérification doit être déterministe
        let result1 = verifier.verify(&pk, &message, &signature);
        let result2 = verifier.verify(&pk, &message, &signature);
        prop_assert_eq!(result1.is_ok(), result2.is_ok());

        // Doit vérifier avec les bons paramètres
        prop_assert!(verifier.verify(&pk, &message, &signature).is_ok());
    }

    #[test]
    fn prop_state_tree_consistency(
        operations in prop::collection::vec(
            (prop::collection::vec(any::<u8>(), 1..32), any::<u64>()),
            0..100
        )
    ) {
        let mut state_tree = Poseidon2StateTree::new(16);
        let mut reference_state = HashMap::new();

        for (key, value) in operations {
            state_tree.insert(&key, &value.to_le_bytes());
            reference_state.insert(key.clone(), value);

            // Vérifier que les valeurs insérées sont récupérables
            prop_assert_eq!(
                state_tree.get(&key),
                Some(value.to_le_bytes().as_slice())
            );
        }

        // Vérifier la cohérence globale
        for (key, expected_value) in reference_state {
            prop_assert_eq!(
                state_tree.get(&key),
                Some(expected_value.to_le_bytes().as_slice())
            );
        }
    }

    #[test]
    fn prop_block_validation_rejects_malformed_blocks(
        tx_count in 0usize..10usize,
        corruption_byte in any::<u8>(),
        corruption_index in 0usize..100usize
    ) {
        let validator = Validator::new();
        let generator = TestBlockGenerator::new();
        let state_view = TestStateView::new();

        // Créer des transactions valides
        let transactions: Vec<Transaction> = (0..tx_count)
            .map(|i| generator.create_transaction(
                vec![Hash::from_bytes([i as u8; 32])],
                vec![100 + i as u64]
            ))
            .collect();

        let state_root = state_view.compute_state_root(&transactions).unwrap();
        let mut block = generator.create_valid_block(transactions, Hash::zero(), state_root);

        // Corrompre le bloc de manière aléatoire
        let mut block_bytes = block.serialize();
        if !block_bytes.is_empty() && corruption_index < block_bytes.len() {
            block_bytes[corruption_index] ^= corruption_byte;
            
            // Tenter de désérialiser et valider le bloc corrompu
            if let Ok(corrupted_block) = Block::deserialize(&block_bytes) {
                // Si la désérialisation réussit, la validation doit échouer
                prop_assert!(validator.validate_block(&corrupted_block, None, &state_view).is_err());
            }
        }
    }
}

/// Tests de régression pour vulnérabilités connues
mod regression_tests {
    use super::*;

    #[test]
    fn test_regression_double_spend_prevention() {
        // Régression : s'assurer qu'un double spend est détecté
        let validator = Validator::new();
        let generator = TestBlockGenerator::new();
        let mut state_view = TestStateView::new();

        let same_input = Hash::from_bytes([0x42; 32]);
        
        // Première transaction utilisant l'input
        let tx1 = generator.create_transaction(vec![same_input], vec![50]);
        let state_root1 = state_view.compute_state_root(&[tx1.clone()]).unwrap();
        let block1 = generator.create_valid_block(vec![tx1.clone()], Hash::zero(), state_root1);
        
        assert!(validator.validate_block(&block1, None, &state_view).is_ok());
        state_view.apply_transaction(&tx1).unwrap();

        // Deuxième transaction utilisant le même input (double spend)
        let tx2 = generator.create_transaction(vec![same_input], vec![30]);
        let state_root2 = state_view.compute_state_root(&[tx2.clone()]).unwrap();
        let block2 = generator.create_valid_block(vec![tx2], Hash::zero(), state_root2);

        // Doit être rejeté (solde insuffisant après le premier spend)
        assert!(validator.validate_block(&block2, None, &state_view).is_err());
    }

    #[test]
    fn test_regression_signature_malleability() {
        // Régression : s'assurer qu'une signature ne peut pas être modifiée
        let validator = Validator::new();
        let generator = TestBlockGenerator::new();
        let state_view = TestStateView::new();

        let tx = generator.create_transaction(vec![Hash::zero()], vec![100]);
        let state_root = state_view.compute_state_root(&[tx.clone()]).unwrap();
        let mut block = generator.create_valid_block(vec![tx], Hash::zero(), state_root);

        // Tenter de modifier la signature (attaque de malléabilité)
        if block.header.signature.len() > 10 {
            // Modifier quelques bytes de la signature
            block.header.signature[5] ^= 0x01;
            block.header.signature[10] ^= 0xFF;
        }

        // Doit être rejeté
        assert!(matches!(
            validator.validate_block(&block, None, &state_view),
            Err(ValidationError::InvalidBlockSignature)
        ));
    }
}

/// Tests de performance et résistance aux attaques DoS
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_validation_performance_large_block() {
        let validator = Validator::new();
        let generator = TestBlockGenerator::new();
        let state_view = TestStateView::new();

        // Créer un bloc avec beaucoup de transactions
        let transactions: Vec<Transaction> = (0..1000)
            .map(|i| generator.create_transaction(
                vec![Hash::from_bytes([i as u8; 32])],
                vec![100]
            ))
            .collect();

        let state_root = state_view.compute_state_root(&transactions).unwrap();
        let block = generator.create_valid_block(transactions, Hash::zero(), state_root);

        // Mesurer le temps de validation
        let start = Instant::now();
        let result = validator.validate_block(&block, None, &state_view);
        let duration = start.elapsed();

        // La validation doit réussir et être raisonnablement rapide
        assert!(result.is_ok());
        assert!(duration.as_millis() < 5000, "Validation too slow: {}ms", duration.as_millis());
    }

    #[test]
    fn test_constant_time_signature_verification() {
        let validator = Validator::new();
        let generator = TestBlockGenerator::new();
        let state_view = TestStateView::new();

        let mut times = Vec::new();

        // Tester avec différentes tailles de messages
        for size in [10, 100, 1000, 10000] {
            let tx = generator.create_transaction(
                vec![Hash::from_bytes([0; 32])],
                vec![size]
            );
            let state_root = state_view.compute_state_root(&[tx.clone()]).unwrap();
            let block = generator.create_valid_block(vec![tx], Hash::zero(), state_root);

            let start = Instant::now();
            let _ = validator.validate_block(&block, None, &state_view);
            times.push(start.elapsed().as_nanos());
        }

        // Vérifier que les temps ne varient pas trop (résistance aux timing attacks)
        let avg_time = times.iter().sum::<u128>() / times.len() as u128;
        for &time in &times {
            let deviation = ((time as i128 - avg_time as i128).abs() as f64) / (avg_time as f64);
            assert!(deviation < 0.3, "Timing deviation too high: {:.2}", deviation);
        }
    }
}
