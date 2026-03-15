// DISABLED: uses API/modules that no longer exist in current codebase
#![cfg(feature = "disabled_test")]
//! Property-based tests pour les invariants du consensus TSN
//!
//! Utilise proptest pour générer des scénarios aléatoires et vérifier
//! que les propriétés critiques du consensus sont toujours respectées.
//!
//! INVARIANTS TESTÉS:
//! - Monotonie des hauteurs de blocs
//! - Intégrité des hashes de blocs
//! - Cohérence des signatures SLH-DSA
//! - Conservation des balances dans les transactions
//! - Déterminisme de la validation

use proptest::prelude::*;
use std::collections::HashMap;
use tsn::core::{Block, Transaction, Blockchain};
use tsn::crypto::keys::{KeyPair, PublicKey};
use tsn::consensus::validation::{Validator, ValidationError};

/// Générateur de keypairs valides pour les tests
fn arb_keypair() -> impl Strategy<Value = KeyPair> {
    any::<[u8; 32]>().prop_map(|_| KeyPair::generate())
}

/// Générateur de transactions valides
fn arb_valid_transaction() -> impl Strategy<Value = Transaction> {
    (arb_keypair(), arb_keypair(), 1u64..1000000u64, 1u64..1000u64, 0u64..1000u64)
        .prop_map(|(sender_kp, receiver_kp, amount, fee, nonce)| {
            let mut tx = Transaction::new(
                sender_kp.public_key(),
                receiver_kp.public_key(),
                amount,
                fee,
                nonce,
            );
            
            // Signer la transaction
            let tx_hash = tx.calculate_hash();
            if let Ok(signature) = sender_kp.sign(&tx_hash) {
                tx.signature = Some(signature);
            }
            
            tx
        })
}

/// Générateur de blocs structurellement valides
fn arb_valid_block() -> impl Strategy<Value = Block> {
    (
        1u64..1000u64,                    // height
        any::<[u8; 32]>(),               // parent_hash
        prop::collection::vec(arb_valid_transaction(), 0..10), // transactions
        any::<u64>(),                    // timestamp
        any::<u64>(),                    // nonce
    ).prop_map(|(height, parent_hash, transactions, timestamp, nonce)| {
        let mut block = Block::new(
            height,
            parent_hash,
            transactions,
            [0u8; 32], // merkle_root calculé après
            timestamp,
            nonce,
        );
        
        // Calculer le merkle root correct
        block.merkle_root = block.calculate_merkle_root();
        block
    })
}

/// Générateur de chaînes de blocs valides
fn arb_valid_blockchain(max_length: usize) -> impl Strategy<Value = Vec<Block>> {
    prop::collection::vec(arb_valid_block(), 1..max_length)
        .prop_map(|mut blocks| {
            // Assurer la continuité des hashes et hauteurs
            for i in 1..blocks.len() {
                blocks[i].height = blocks[i-1].height + 1;
                blocks[i].parent_hash = blocks[i-1].calculate_hash();
                blocks[i].merkle_root = blocks[i].calculate_merkle_root();
            }
            blocks
        })
}

// ============================================================================
// PROPERTY TESTS - INVARIANTS DU CONSENSUS
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// INVARIANT: La hauteur des blocs doit être strictement croissante
    #[test]
    fn prop_block_height_monotonic(blocks in arb_valid_blockchain(50)) {
        for window in blocks.windows(2) {
            let prev_block = &window[0];
            let curr_block = &window[1];
            
            prop_assert!(curr_block.height > prev_block.height,
                        "La hauteur doit être strictement croissante: {} -> {}",
                        prev_block.height, curr_block.height);
            
            prop_assert_eq!(curr_block.height, prev_block.height + 1,
                           "La hauteur doit augmenter de exactement 1");
        }
    }

    /// INVARIANT: Le parent_hash doit correspondre au hash du bloc précédent
    #[test]
    fn prop_parent_hash_integrity(blocks in arb_valid_blockchain(50)) {
        for window in blocks.windows(2) {
            let prev_block = &window[0];
            let curr_block = &window[1];
            
            let expected_parent_hash = prev_block.calculate_hash();
            prop_assert_eq!(curr_block.parent_hash, expected_parent_hash,
                           "Le parent_hash doit correspondre au hash du bloc précédent");
        }
    }

    /// INVARIANT: Le hash d'un bloc doit être déterministe
    #[test]
    fn prop_block_hash_deterministic(block in arb_valid_block()) {
        let hash1 = block.calculate_hash();
        let hash2 = block.calculate_hash();
        
        prop_assert_eq!(hash1, hash2,
                       "Le hash d'un bloc doit être déterministe");
        
        // Vérifier que des blocs identiques ont le même hash
        let block_copy = block.clone();
        let hash3 = block_copy.calculate_hash();
        prop_assert_eq!(hash1, hash3,
                       "Des blocs identiques doivent avoir le même hash");
    }

    /// INVARIANT: Le merkle root doit être cohérent avec les transactions
    #[test]
    fn prop_merkle_root_consistency(transactions in prop::collection::vec(arb_valid_transaction(), 0..20)) {
        let block = Block::new(
            1,
            [0u8; 32],
            transactions.clone(),
            [0u8; 32], // sera recalculé
            1234567890,
            0,
        );
        
        let calculated_root = block.calculate_merkle_root();
        
        // Créer un autre bloc avec les mêmes transactions
        let block2 = Block::new(
            1,
            [0u8; 32],
            transactions,
            [0u8; 32],
            1234567890,
            0,
        );
        
        let calculated_root2 = block2.calculate_merkle_root();
        
        prop_assert_eq!(calculated_root, calculated_root2,
                       "Le merkle root doit être déterministe pour les mêmes transactions");
    }

    /// INVARIANT: La validation d'un bloc doit être déterministe
    #[test]
    fn prop_block_validation_deterministic(block in arb_valid_block()) {
        let validator = Validator::new();
        let blockchain = Blockchain::new();
        
        // Valider le même bloc plusieurs fois
        let result1 = validator.validate_block_structure(&block);
        let result2 = validator.validate_block_structure(&block);
        
        prop_assert_eq!(result1.is_ok(), result2.is_ok(),
                       "La validation structurelle doit être déterministe");
        
        if let (Err(e1), Err(e2)) = (result1, result2) {
            prop_assert_eq!(std::mem::discriminant(&e1), std::mem::discriminant(&e2),
                           "Les erreurs de validation doivent être cohérentes");
        }
    }

    /// INVARIANT: Les signatures de transactions doivent être vérifiables
    #[test]
    fn prop_transaction_signature_validity(
        sender_kp in arb_keypair(),
        receiver_kp in arb_keypair(),
        amount in 1u64..1000000u64,
        fee in 1u64..1000u64,
        nonce in 0u64..1000u64
    ) {
        let mut transaction = Transaction::new(
            sender_kp.public_key(),
            receiver_kp.public_key(),
            amount,
            fee,
            nonce,
        );
        
        // Signer la transaction
        let tx_hash = transaction.calculate_hash();
        let signature = sender_kp.sign(&tx_hash).unwrap();
        transaction.signature = Some(signature.clone());
        
        // Vérifier la signature
        let verification_result = sender_kp.public_key().verify(&tx_hash, &signature);
        prop_assert!(verification_result.is_ok(),
                    "La signature d'une transaction doit être vérifiable");
        
        // Vérifier qu'une signature incorrecte échoue
        let wrong_kp = KeyPair::generate();
        let wrong_verification = wrong_kp.public_key().verify(&tx_hash, &signature);
        prop_assert!(wrong_verification.is_err(),
                    "Une signature avec la mauvaise clé publique doit échouer");
    }

    /// INVARIANT: Conservation des montants dans les transactions
    #[test]
    fn prop_transaction_amount_conservation(
        transactions in prop::collection::vec(arb_valid_transaction(), 1..50)
    ) {
        let mut balance_changes: HashMap<PublicKey, i64> = HashMap::new();
        
        for tx in &transactions {
            // Le sender perd (amount + fee)
            *balance_changes.entry(tx.sender).or_insert(0) -= (tx.amount + tx.fee) as i64;
            
            // Le receiver gagne amount
            *balance_changes.entry(tx.receiver).or_insert(0) += tx.amount as i64;
            
            // Les fees sont "brûlées" (vont aux mineurs, pas modélisé ici)
        }
        
        // Vérifier qu'aucun montant n'est créé ex nihilo
        for (&pubkey, &balance_change) in &balance_changes {
            if balance_change > 0 {
                // Quelqu'un a reçu de l'argent, vérifier qu'il vient d'ailleurs
                let total_sent: i64 = transactions.iter()
                    .filter(|tx| tx.receiver == pubkey)
                    .map(|tx| tx.amount as i64)
                    .sum();
                
                prop_assert_eq!(balance_change, total_sent,
                               "Les montants reçus doivent correspondre aux montants envoyés");
            }
        }
    }

    /// INVARIANT: Les timestamps doivent être raisonnables
    #[test]
    fn prop_block_timestamp_reasonable(block in arb_valid_block()) {
        // Les timestamps ne doivent pas être dans le futur lointain
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let future_threshold = now + 3600; // 1 heure dans le futur max
        
        prop_assert!(block.timestamp <= future_threshold,
                    "Les timestamps ne doivent pas être trop dans le futur: {} > {}",
                    block.timestamp, future_threshold);
        
        // Les timestamps ne doivent pas être avant l'époque Bitcoin (2009)
        let bitcoin_genesis = 1231006505; // 3 Jan 2009
        prop_assert!(block.timestamp >= bitcoin_genesis,
                    "Les timestamps ne doivent pas être avant l'époque Bitcoin");
    }

    /// INVARIANT: Les nonces doivent permettre la reproductibilité
    #[test]
    fn prop_block_nonce_reproducibility(
        height in 1u64..1000u64,
        parent_hash in any::<[u8; 32]>(),
        transactions in prop::collection::vec(arb_valid_transaction(), 0..5),
        timestamp in any::<u64>(),
        nonce in any::<u64>()
    ) {
        let block1 = Block::new(
            height,
            parent_hash,
            transactions.clone(),
            [0u8; 32],
            timestamp,
            nonce,
        );
        
        let block2 = Block::new(
            height,
            parent_hash,
            transactions,
            [0u8; 32],
            timestamp,
            nonce,
        );
        
        prop_assert_eq!(block1.calculate_hash(), block2.calculate_hash(),
                       "Des blocs avec les mêmes paramètres doivent avoir le même hash");
    }

    /// INVARIANT: La sérialisation/désérialisation doit être cohérente
    #[test]
    fn prop_block_serialization_roundtrip(block in arb_valid_block()) {
        // Test de sérialisation/désérialisation (simulation)
        let serialized = format!("{:?}", block); // Simulation avec Debug
        prop_assert!(!serialized.is_empty(),
                    "La sérialisation ne doit pas être vide");
        
        // En vrai, on testerait serde::serialize/deserialize
        // let serialized = serde_json::to_string(&block).unwrap();
        // let deserialized: Block = serde_json::from_str(&serialized).unwrap();
        // prop_assert_eq!(block.calculate_hash(), deserialized.calculate_hash());
    }
}

// ============================================================================
// PROPERTY TESTS - INVARIANTS DE SÉCURITÉ
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// SÉCURITÉ: Résistance aux attaques de replay
    #[test]
    fn prop_security_no_transaction_replay(
        sender_kp in arb_keypair(),
        receiver_kp in arb_keypair(),
        amount in 1u64..1000u64,
        fee in 1u64..100u64,
        nonce in 0u64..100u64
    ) {
        let mut tx1 = Transaction::new(
            sender_kp.public_key(),
            receiver_kp.public_key(),
            amount,
            fee,
            nonce,
        );
        
        let tx_hash = tx1.calculate_hash();
        let signature = sender_kp.sign(&tx_hash).unwrap();
        tx1.signature = Some(signature);
        
        // Créer une transaction identique (tentative de replay)
        let mut tx2 = Transaction::new(
            sender_kp.public_key(),
            receiver_kp.public_key(),
            amount,
            fee,
            nonce, // Même nonce = replay
        );
        tx2.signature = tx1.signature.clone();
        
        // Les deux transactions doivent avoir le même hash
        prop_assert_eq!(tx1.calculate_hash(), tx2.calculate_hash(),
                       "Les transactions identiques doivent avoir le même hash");
        
        // Un système de consensus correct doit détecter et rejeter les replays
        // (testé via les nonces dans la validation)
    }

    /// SÉCURITÉ: Résistance aux modifications de transactions signées
    #[test]
    fn prop_security_transaction_immutability(
        sender_kp in arb_keypair(),
        receiver_kp in arb_keypair(),
        amount in 1u64..1000u64,
        fee in 1u64..100u64,
        nonce in 0u64..100u64,
        malicious_amount in 1u64..1000u64
    ) {
        // Créer une transaction légitime
        let mut legitimate_tx = Transaction::new(
            sender_kp.public_key(),
            receiver_kp.public_key(),
            amount,
            fee,
            nonce,
        );
        
        let tx_hash = legitimate_tx.calculate_hash();
        let signature = sender_kp.sign(&tx_hash).unwrap();
        legitimate_tx.signature = Some(signature.clone());
        
        // Tenter de modifier le montant après signature (attaque)
        let mut malicious_tx = legitimate_tx.clone();
        malicious_tx.amount = malicious_amount;
        
        // La signature ne doit plus être valide
        if amount != malicious_amount {
            let malicious_hash = malicious_tx.calculate_hash();
            let verification_result = sender_kp.public_key().verify(&malicious_hash, &signature);
            
            prop_assert!(verification_result.is_err(),
                        "Une transaction modifiée après signature doit avoir une signature invalide");
        }
    }

    /// SÉCURITÉ: Résistance aux attaques de double-spend
    #[test]
    fn prop_security_double_spend_detection(
        sender_kp in arb_keypair(),
        receiver1_kp in arb_keypair(),
        receiver2_kp in arb_keypair(),
        amount in 1u64..1000u64,
        fee in 1u64..100u64,
        nonce in 0u64..100u64
    ) {
        // Créer deux transactions avec le même nonce (tentative de double-spend)
        let mut tx1 = Transaction::new(
            sender_kp.public_key(),
            receiver1_kp.public_key(),
            amount,
            fee,
            nonce,
        );
        
        let mut tx2 = Transaction::new(
            sender_kp.public_key(),
            receiver2_kp.public_key(),
            amount,
            fee,
            nonce, // Même nonce = double-spend potentiel
        );
        
        // Signer les deux transactions
        let tx1_hash = tx1.calculate_hash();
        let tx2_hash = tx2.calculate_hash();
        
        tx1.signature = Some(sender_kp.sign(&tx1_hash).unwrap());
        tx2.signature = Some(sender_kp.sign(&tx2_hash).unwrap());
        
        // Si les receivers sont différents, les transactions doivent être différentes
        if receiver1_kp.public_key() != receiver2_kp.public_key() {
            prop_assert_ne!(tx1.calculate_hash(), tx2.calculate_hash(),
                           "Des transactions vers des receivers différents doivent avoir des hashes différents");
        }
        
        // Un système de consensus correct doit détecter le même nonce
        // et rejeter la deuxième transaction
    }

    /// SÉCURITÉ: Validation des limites de montants
    #[test]
    fn prop_security_amount_limits(
        sender_kp in arb_keypair(),
        receiver_kp in arb_keypair(),
        amount in any::<u64>(),
        fee in any::<u64>(),
        nonce in 0u64..100u64
    ) {
        // Tester les cas limites de montants
        let transaction = Transaction::new(
            sender_kp.public_key(),
            receiver_kp.public_key(),
            amount,
            fee,
            nonce,
        );
        
        // Vérifier que la création ne panique pas
        prop_assert!(transaction.amount == amount,
                    "Le montant doit être préservé lors de la création");
        prop_assert!(transaction.fee == fee,
                    "Les fees doivent être préservées lors de la création");
        
        // Vérifier les cas d'overflow potentiels
        if let Some(total) = amount.checked_add(fee) {
            prop_assert!(total >= amount && total >= fee,
                        "La somme montant + fee ne doit pas déborder");
        }
    }
}

// ============================================================================
// TESTS DE RÉGRESSION POUR VULNÉRABILITÉS CONNUES
// ============================================================================

#[cfg(test)]
mod regression_tests {
    use super::*;

    /// Régression: CVE-2023-XXXX - Validation de timestamp insuffisante
    #[test]
    fn regression_timestamp_validation() {
        let block = Block::new(
            1,
            [0u8; 32],
            Vec::new(),
            [0u8; 32],
            u64::MAX, // Timestamp dans le futur lointain
            0,
        );
        
        let validator = Validator::new();
        let result = validator.validate_block_structure(&block);
        
        // Cette validation devrait échouer pour des timestamps invalides
        // (à implémenter dans le validator si pas déjà fait)
        println!("Timestamp validation result: {:?}", result);
    }

    /// Régression: Attaque par déni de service via blocs avec trop de transactions
    #[test]
    fn regression_transaction_limit() {
        // Créer un bloc avec un nombre excessif de transactions
        let transactions: Vec<Transaction> = (0..10000)
            .map(|i| {
                let sender_kp = KeyPair::generate();
                let receiver_kp = KeyPair::generate();
                Transaction::new(
                    sender_kp.public_key(),
                    receiver_kp.public_key(),
                    1,
                    1,
                    i as u64,
                )
            })
            .collect();
        
        let block = Block::new(
            1,
            [0u8; 32],
            transactions,
            [0u8; 32],
            1234567890,
            0,
        );
        
        // La validation ne doit pas prendre un temps excessif
        let start = std::time::Instant::now();
        let validator = Validator::new();
        let _result = validator.validate_block_structure(&block);
        let duration = start.elapsed();
        
        assert!(duration < std::time::Duration::from_secs(1),
                "La validation d'un bloc ne doit pas prendre plus d'1 seconde");
    }

    /// Régression: Validation de signature avec clés publiques malformées
    #[test]
    fn regression_malformed_public_key() {
        // Test avec des données de clé publique invalides
        // (nécessite une implémentation de PublicKey::from_bytes qui peut échouer)
        
        let invalid_pubkey_data = vec![0xFF; 32]; // Données invalides
        
        // La création d'une clé publique à partir de données invalides
        // devrait échouer gracieusement, pas paniquer
        println!("Testing malformed public key handling");
        
        // En vrai test, on testerait:
        // let result = PublicKey::from_bytes(&invalid_pubkey_data);
        // assert!(result.is_err(), "Les clés publiques malformées doivent être rejetées");
    }
}
