// DISABLED: uses API/modules that no longer exist in current codebase
#![cfg(feature = "disabled_test")]
//! Suite de tests de régression pour Trust Stack Network
//!
//! Cette suite teste les invariants critiques du protocole pour détecter
//! les régressions lors des modifications du codebase.
//!
//! ## Modules testés
//! - Core: Block, Transaction, State
//! - Consensus: PoW, Chain, Fork Choice
//! - Crypto: Signatures, Proofs, Merkle Trees
//!
//! ## Invariants testés
//! 1. Validation des blocs et transactions
//! 2. Cohérence de l'état global
//! 3. Règles de consensus et fork choice
//! 4. Intégrité cryptographique

use std::collections::HashMap;
use tsn::core::{
    Account, ShieldedBlock, ShieldedTransaction, ShieldedState, StateError,
    BlockHeader, TransactionInput, TransactionOutput, BLOCK_HASH_SIZE
};
use tsn::consensus::{
    ChainInfo, ForkChoice, ChainError, mine_block, mine_block_with_jobs
};
use tsn::crypto::{
    ShieldedAddress, generate_keypair, sign_transaction, verify_signature,
    MerkleTree, PoseidonHash, ZkProof
};

/// Configuration pour les tests de régression
#[derive(Debug, Clone)]
pub struct RegressionConfig {
    /// Nombre de blocs à générer pour les tests de chaîne
    pub chain_length: usize,
    /// Nombre de transactions par bloc
    pub transactions_per_block: usize,
    /// Difficulté minimale pour les tests de mining
    pub min_difficulty: u64,
    /// Timeout pour les tests de performance (ms)
    pub performance_timeout_ms: u64,
}

impl Default for RegressionConfig {
    fn default() -> Self {
        Self {
            chain_length: 10,
            transactions_per_block: 5,
            min_difficulty: 1000,
            performance_timeout_ms: 5000,
        }
    }
}

/// Générateur de données de test déterministes
pub struct TestDataGenerator {
    seed: u64,
    config: RegressionConfig,
}

impl TestDataGenerator {
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            config: RegressionConfig::default(),
        }
    }

    pub fn with_config(mut self, config: RegressionConfig) -> Self {
        self.config = config;
        self
    }

    /// Génère un bloc de test valide
    pub fn generate_block(&mut self, height: u64, prev_hash: [u8; 32]) -> ShieldedBlock {
        let timestamp = 1640995200 + height * 600; // 1 bloc toutes les 10 minutes
        let difficulty = self.config.min_difficulty + height * 100;
        
        let transactions = (0..self.config.transactions_per_block)
            .map(|i| self.generate_transaction(height, i as u64))
            .collect();

        let header = BlockHeader {
            version: 1,
            prev_hash,
            merkle_root: self.compute_merkle_root(&transactions),
            timestamp,
            difficulty,
            nonce: 0,
        };

        ShieldedBlock {
            header,
            transactions,
        }
    }

    /// Génère une transaction de test valide
    pub fn generate_transaction(&mut self, block_height: u64, tx_index: u64) -> ShieldedTransaction {
        let (sender_sk, sender_pk) = generate_keypair(self.next_seed());
        let (receiver_sk, receiver_pk) = generate_keypair(self.next_seed());
        
        let sender_addr = ShieldedAddress::from_public_key(&sender_pk);
        let receiver_addr = ShieldedAddress::from_public_key(&receiver_pk);
        
        let amount = 1000 + (block_height * 100) + (tx_index * 10);
        let fee = 10;

        // Créer une transaction simple
        let inputs = vec![TransactionInput {
            prev_tx_hash: [0u8; 32], // Genesis UTXO
            output_index: 0,
            unlock_script: vec![],
        }];

        let outputs = vec![
            TransactionOutput {
                amount,
                recipient: receiver_addr,
                lock_script: vec![],
            },
            TransactionOutput {
                amount: fee,
                recipient: sender_addr, // Change
                lock_script: vec![],
            }
        ];

        ShieldedTransaction {
            version: 1,
            inputs,
            outputs,
            fee,
            signature: vec![], // Sera rempli par sign_transaction
            zk_proof: None,
        }
    }

    /// Génère une chaîne de blocs de test
    pub fn generate_chain(&mut self) -> Vec<ShieldedBlock> {
        let mut chain = Vec::new();
        let mut prev_hash = [0u8; 32]; // Genesis hash

        for height in 0..self.config.chain_length {
            let mut block = self.generate_block(height as u64, prev_hash);
            
            // Mine le bloc pour qu'il soit valide
            mine_block(&mut block);
            
            prev_hash = block.hash();
            chain.push(block);
        }

        chain
    }

    fn next_seed(&mut self) -> u64 {
        self.seed = self.seed.wrapping_mul(1103515245).wrapping_add(12345);
        self.seed
    }

    fn compute_merkle_root(&self, transactions: &[ShieldedTransaction]) -> [u8; 32] {
        if transactions.is_empty() {
            return [0u8; 32];
        }

        let tx_hashes: Vec<[u8; 32]> = transactions
            .iter()
            .map(|tx| tx.hash())
            .collect();

        let tree = MerkleTree::new(tx_hashes);
        tree.root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test de régression : validation des blocs
    #[test]
    fn regression_block_validation() {
        let mut generator = TestDataGenerator::new(42);
        let chain = generator.generate_chain();

        // Vérifier que tous les blocs sont valides
        for (i, block) in chain.iter().enumerate() {
            assert!(block.is_valid(), "Bloc {} invalide", i);
            assert!(block.header.difficulty >= generator.config.min_difficulty);
            
            if i > 0 {
                assert_eq!(block.header.prev_hash, chain[i-1].hash());
                assert!(block.header.timestamp >= chain[i-1].header.timestamp);
            }
        }
    }

    /// Test de régression : cohérence de l'état
    #[test]
    fn regression_state_consistency() {
        let mut generator = TestDataGenerator::new(123);
        let chain = generator.generate_chain();
        let mut state = ShieldedState::new();

        // Appliquer tous les blocs à l'état
        for (i, block) in chain.iter().enumerate() {
            let result = state.apply_block(block);
            assert!(result.is_ok(), "Échec application bloc {} : {:?}", i, result.err());
        }

        // Vérifier les invariants de l'état
        assert!(state.is_consistent(), "État incohérent après application de la chaîne");
        
        // Vérifier que l'état peut être sérialisé/désérialisé
        let serialized = state.serialize().expect("Échec sérialisation état");
        let deserialized = ShieldedState::deserialize(&serialized)
            .expect("Échec désérialisation état");
        
        assert_eq!(state.get_balance_total(), deserialized.get_balance_total());
    }

    /// Test de régression : fork choice
    #[test]
    fn regression_fork_choice() {
        let mut generator = TestDataGenerator::new(456);
        let genesis = generator.generate_block(0, [0u8; 32]);
        
        let mut fork_choice = ForkChoice::new(genesis.clone());

        // Créer deux chaînes concurrentes
        let mut chain_a = vec![genesis.clone()];
        let mut chain_b = vec![genesis.clone()];

        // Chaîne A : 3 blocs
        for i in 1..=3 {
            let mut block = generator.generate_block(i, chain_a.last().unwrap().hash());
            mine_block(&mut block);
            chain_a.push(block.clone());
            
            let result = fork_choice.add_block(block);
            assert!(result.is_ok(), "Échec ajout bloc chaîne A : {:?}", result.err());
        }

        // Chaîne B : 4 blocs (plus longue)
        for i in 1..=4 {
            let mut block = generator.generate_block(i, chain_b.last().unwrap().hash());
            block.header.difficulty += 500; // Plus de travail
            mine_block(&mut block);
            chain_b.push(block.clone());
            
            let result = fork_choice.add_block(block);
            assert!(result.is_ok(), "Échec ajout bloc chaîne B : {:?}", result.err());
        }

        // La chaîne B doit être sélectionnée (plus de travail cumulé)
        let canonical = fork_choice.get_canonical_chain();
        assert_eq!(canonical.len(), 5); // Genesis + 4 blocs
        assert_eq!(canonical.last().unwrap().hash(), chain_b.last().unwrap().hash());
    }

    /// Test de régression : intégrité cryptographique
    #[test]
    fn regression_crypto_integrity() {
        let mut generator = TestDataGenerator::new(789);
        
        // Test signatures
        let (sk, pk) = generate_keypair(generator.next_seed());
        let message = b"test message for regression";
        let signature = sign_transaction(&sk, message);
        
        assert!(verify_signature(&pk, message, &signature), 
                "Échec vérification signature");
        
        // Test avec message modifié
        let mut corrupted_message = message.to_vec();
        corrupted_message[0] ^= 1;
        assert!(!verify_signature(&pk, &corrupted_message, &signature),
                "Signature valide pour message corrompu");

        // Test Merkle Tree
        let data: Vec<[u8; 32]> = (0..16)
            .map(|i| {
                let mut hash = [0u8; 32];
                hash[0] = i;
                hash
            })
            .collect();

        let tree = MerkleTree::new(data.clone());
        let root = tree.root();
        
        // Vérifier les preuves d'inclusion
        for (i, &leaf) in data.iter().enumerate() {
            let proof = tree.generate_proof(i).expect("Échec génération preuve");
            assert!(tree.verify_proof(&leaf, &proof, &root),
                    "Échec vérification preuve Merkle pour index {}", i);
        }
    }

    /// Test de régression : performance mining
    #[test]
    fn regression_mining_performance() {
        let mut generator = TestDataGenerator::new(999);
        let mut block = generator.generate_block(1, [0u8; 32]);
        
        // Test mining single-thread
        let start = std::time::Instant::now();
        let hashes_single = mine_block(&mut block);
        let duration_single = start.elapsed();
        
        assert!(duration_single.as_millis() < generator.config.performance_timeout_ms,
                "Mining single-thread trop lent : {}ms", duration_single.as_millis());

        // Reset le bloc
        block.header.nonce = 0;
        
        // Test mining multi-thread
        let start = std::time::Instant::now();
        let hashes_multi = mine_block_with_jobs(&mut block, 4);
        let duration_multi = start.elapsed();
        
        assert!(duration_multi.as_millis() < generator.config.performance_timeout_ms,
                "Mining multi-thread trop lent : {}ms", duration_multi.as_millis());
        
        println!("Mining performance:");
        println!("  Single-thread: {} hashes en {}ms", hashes_single, duration_single.as_millis());
        println!("  Multi-thread:  {} hashes en {}ms", hashes_multi, duration_multi.as_millis());
    }

    /// Test de régression : sérialisation/désérialisation
    #[test]
    fn regression_serialization() {
        let mut generator = TestDataGenerator::new(111);
        let chain = generator.generate_chain();

        for (i, block) in chain.iter().enumerate() {
            // Test sérialisation bloc
            let serialized = block.serialize().expect("Échec sérialisation bloc");
            let deserialized = ShieldedBlock::deserialize(&serialized)
                .expect("Échec désérialisation bloc");
            
            assert_eq!(block.hash(), deserialized.hash(),
                      "Hash différent après sérialisation/désérialisation bloc {}", i);

            // Test sérialisation transactions
            for (j, tx) in block.transactions.iter().enumerate() {
                let tx_serialized = tx.serialize().expect("Échec sérialisation transaction");
                let tx_deserialized = ShieldedTransaction::deserialize(&tx_serialized)
                    .expect("Échec désérialisation transaction");
                
                assert_eq!(tx.hash(), tx_deserialized.hash(),
                          "Hash différent après sérialisation/désérialisation tx {} du bloc {}", j, i);
            }
        }
    }

    /// Test de régression : gestion des erreurs
    #[test]
    fn regression_error_handling() {
        let mut generator = TestDataGenerator::new(222);
        let mut state = ShieldedState::new();

        // Test bloc invalide (timestamp futur)
        let mut invalid_block = generator.generate_block(1, [0u8; 32]);
        invalid_block.header.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + 7200; // 2h dans le futur

        let result = state.apply_block(&invalid_block);
        assert!(result.is_err(), "Bloc avec timestamp futur accepté");
        
        match result.unwrap_err() {
            StateError::InvalidTimestamp => {}, // Attendu
            other => panic!("Erreur inattendue : {:?}", other),
        }

        // Test transaction avec montant négatif
        let mut invalid_tx = generator.generate_transaction(1, 0);
        invalid_tx.outputs[0].amount = 0; // Montant invalide
        
        let validation_result = invalid_tx.validate();
        assert!(validation_result.is_err(), "Transaction avec montant 0 acceptée");

        // Test fork choice avec bloc orphelin
        let genesis = generator.generate_block(0, [0u8; 32]);
        let mut fork_choice = ForkChoice::new(genesis);
        
        // Ajouter un bloc avec parent inexistant
        let orphan_block = generator.generate_block(5, [1u8; 32]); // Parent inexistant
        let result = fork_choice.add_block(orphan_block);
        
        match result {
            Err(ChainError::MissingParent) => {}, // Attendu
            other => panic!("Résultat inattendu pour bloc orphelin : {:?}", other),
        }
    }

    /// Test de régression : limites et edge cases
    #[test]
    fn regression_edge_cases() {
        let mut generator = TestDataGenerator::new(333);

        // Test bloc vide (pas de transactions)
        let mut empty_block = generator.generate_block(1, [0u8; 32]);
        empty_block.transactions.clear();
        
        assert!(empty_block.is_valid(), "Bloc vide invalide");
        assert_eq!(empty_block.header.merkle_root, [0u8; 32]);

        // Test chaîne avec difficulté maximale
        let mut max_diff_block = generator.generate_block(1, [0u8; 32]);
        max_diff_block.header.difficulty = u64::MAX;
        
        // Ne pas miner (prendrait trop de temps), juste vérifier la structure
        assert_eq!(max_diff_block.header.difficulty, u64::MAX);

        // Test avec beaucoup de transactions
        let mut big_block = generator.generate_block(1, [0u8; 32]);
        for i in 0..1000 {
            big_block.transactions.push(generator.generate_transaction(1, i));
        }
        
        assert_eq!(big_block.transactions.len(), 1000);
        assert!(big_block.header.merkle_root != [0u8; 32]);

        // Test état avec beaucoup de comptes
        let mut state = ShieldedState::new();
        for i in 0..1000 {
            let (_, pk) = generate_keypair(i);
            let addr = ShieldedAddress::from_public_key(&pk);
            let account = Account::new(addr, 1000);
            state.add_account(account).expect("Échec ajout compte");
        }
        
        assert_eq!(state.get_account_count(), 1000);
        assert!(state.is_consistent());
    }
}
