//! Tests unitaires complets pour les modules storage/
//!
//! Couvre database.rs, sled_backend.rs et faucet_store.rs avec tests d'erreur,
//! persistence et cohérence des données lors des opérations CRUD.

#[cfg(test)]
mod database_tests {
    use super::super::database::{Database, DatabaseError};
    use super::super::sled_backend::SledBackend;
    use crate::core::{Block, BlockHeader, BlockId, Transaction, TransactionId};
    use crate::core::transaction::{CoinbaseTransaction, ShieldedTransaction};
    use crate::crypto::{Address, Signature};
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio;

    /// Constantes pour les tests
    const TEST_BLOCK_HASH_SIZE: usize = 32;
    const TEST_DIFFICULTY: u64 = 1000;
    const TEST_TIMESTAMP: u64 = 1640995200; // 1er janvier 2022

    /// Crée une base de données temporaire pour les tests
    async fn create_test_database() -> (Arc<dyn Database>, TempDir) {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("test.db");
        let backend = SledBackend::new(db_path.to_str().unwrap())
            .await
            .expect("Failed to create test database");
        (Arc::new(backend), temp_dir)
    }

    /// Crée un bloc de test valide
    fn create_test_block(height: u64, prev_hash: [u8; TEST_BLOCK_HASH_SIZE]) -> Block {
        let header = BlockHeader {
            version: 1,
            prev_hash,
            merkle_root: [0u8; TEST_BLOCK_HASH_SIZE],
            commitment_root: [1u8; TEST_BLOCK_HASH_SIZE],
            nullifier_root: [2u8; TEST_BLOCK_HASH_SIZE],
            state_root: [0u8; 32],
            timestamp: TEST_TIMESTAMP + height * 600, // 10 minutes par bloc
            difficulty: TEST_DIFFICULTY,
            nonce: height * 12345,
        };

        let coinbase = CoinbaseTransaction {
            outputs: vec![],
            fee: 0,
            signature: Signature::default(),
            public_key: vec![0u8; 32],
        };

        Block {
            header,
            coinbase,
            shielded_transactions: vec![],
        }
    }

    /// Crée une transaction de test
    fn create_test_transaction() -> Transaction {
        Transaction::Coinbase(CoinbaseTransaction {
            outputs: vec![],
            fee: 1000,
            signature: Signature::default(),
            public_key: vec![0u8; 32],
        })
    }

    #[tokio::test]
    async fn test_store_and_get_block_success() {
        let (db, _temp_dir) = create_test_database().await;
        let block = create_test_block(1, [0u8; TEST_BLOCK_HASH_SIZE]);
        let block_id = BlockId::from_hash(block.header.hash());

        // Test store
        let result = db.store_block(&block_id, &block).await;
        assert!(result.is_ok(), "Failed to store block: {:?}", result);

        // Test get
        let retrieved = db.get_block(&block_id).await;
        assert!(retrieved.is_ok(), "Failed to get block: {:?}", retrieved);
        
        let retrieved_block = retrieved.unwrap();
        assert!(retrieved_block.is_some(), "Block not found");
        
        let retrieved_block = retrieved_block.unwrap();
        assert_eq!(retrieved_block.header.version, block.header.version);
        assert_eq!(retrieved_block.header.prev_hash, block.header.prev_hash);
        assert_eq!(retrieved_block.header.timestamp, block.header.timestamp);
    }

    #[tokio::test]
    async fn test_get_nonexistent_block() {
        let (db, _temp_dir) = create_test_database().await;
        let fake_id = BlockId::from_hash([99u8; TEST_BLOCK_HASH_SIZE]);

        let result = db.get_block(&fake_id).await;
        assert!(result.is_ok(), "Should not error on missing block");
        assert!(result.unwrap().is_none(), "Should return None for missing block");
    }

    #[tokio::test]
    async fn test_store_and_get_transaction_success() {
        let (db, _temp_dir) = create_test_database().await;
        let transaction = create_test_transaction();
        let tx_id = TransactionId::from_hash([42u8; TEST_BLOCK_HASH_SIZE]);

        // Test store
        let result = db.store_transaction(&tx_id, &transaction).await;
        assert!(result.is_ok(), "Failed to store transaction: {:?}", result);

        // Test get
        let retrieved = db.get_transaction(&tx_id).await;
        assert!(retrieved.is_ok(), "Failed to get transaction: {:?}", retrieved);
        
        let retrieved_tx = retrieved.unwrap();
        assert!(retrieved_tx.is_some(), "Transaction not found");
        
        // Vérifier que la transaction récupérée correspond
        match (&transaction, &retrieved_tx.unwrap()) {
            (Transaction::Coinbase(orig), Transaction::Coinbase(retrieved)) => {
                assert_eq!(orig.fee, retrieved.fee);
                assert_eq!(orig.public_key, retrieved.public_key);
            }
            _ => panic!("Transaction type mismatch"),
        }
    }

    #[tokio::test]
    async fn test_get_nonexistent_transaction() {
        let (db, _temp_dir) = create_test_database().await;
        let fake_id = TransactionId::from_hash([88u8; TEST_BLOCK_HASH_SIZE]);

        let result = db.get_transaction(&fake_id).await;
        assert!(result.is_ok(), "Should not error on missing transaction");
        assert!(result.unwrap().is_none(), "Should return None for missing transaction");
    }

    #[tokio::test]
    async fn test_block_height_operations() {
        let (db, _temp_dir) = create_test_database().await;
        
        // Test initial height
        let initial_height = db.get_block_height().await;
        assert!(initial_height.is_ok(), "Failed to get initial height");
        assert_eq!(initial_height.unwrap(), 0, "Initial height should be 0");

        // Store blocks at different heights
        for height in 1..=5 {
            let block = create_test_block(height, [height as u8; TEST_BLOCK_HASH_SIZE]);
            let block_id = BlockId::from_hash(block.header.hash());
            
            let store_result = db.store_block(&block_id, &block).await;
            assert!(store_result.is_ok(), "Failed to store block at height {}: {:?}", height, store_result);
            
            let set_height_result = db.set_block_height(height).await;
            assert!(set_height_result.is_ok(), "Failed to set height {}: {:?}", height, set_height_result);
        }

        // Verify final height
        let final_height = db.get_block_height().await;
        assert!(final_height.is_ok(), "Failed to get final height");
        assert_eq!(final_height.unwrap(), 5, "Final height should be 5");
    }

    #[tokio::test]
    async fn test_block_persistence_across_reopens() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("persistence_test.db");
        let db_path_str = db_path.to_str().unwrap();

        let block = create_test_block(1, [0u8; TEST_BLOCK_HASH_SIZE]);
        let block_id = BlockId::from_hash(block.header.hash());

        // Store block in first database instance
        {
            let backend = SledBackend::new(db_path_str)
                .await
                .expect("Failed to create first database instance");
            let db: Arc<dyn Database> = Arc::new(backend);
            
            let result = db.store_block(&block_id, &block).await;
            assert!(result.is_ok(), "Failed to store block in first instance");
        }

        // Retrieve block from second database instance
        {
            let backend = SledBackend::new(db_path_str)
                .await
                .expect("Failed to create second database instance");
            let db: Arc<dyn Database> = Arc::new(backend);
            
            let retrieved = db.get_block(&block_id).await;
            assert!(retrieved.is_ok(), "Failed to get block from second instance");
            
            let retrieved_block = retrieved.unwrap();
            assert!(retrieved_block.is_some(), "Block should persist across reopens");
            
            let retrieved_block = retrieved_block.unwrap();
            assert_eq!(retrieved_block.header.timestamp, block.header.timestamp);
        }
    }

    #[tokio::test]
    async fn test_concurrent_operations() {
        let (db, _temp_dir) = create_test_database().await;
        
        // Créer plusieurs tâches concurrentes
        let mut handles = vec![];
        
        for i in 0..10 {
            let db_clone = Arc::clone(&db);
            let handle = tokio::spawn(async move {
                let block = create_test_block(i, [i as u8; TEST_BLOCK_HASH_SIZE]);
                let block_id = BlockId::from_hash(block.header.hash());
                
                // Store et retrieve en parallèle
                let store_result = db_clone.store_block(&block_id, &block).await;
                assert!(store_result.is_ok(), "Concurrent store failed for block {}", i);
                
                let get_result = db_clone.get_block(&block_id).await;
                assert!(get_result.is_ok(), "Concurrent get failed for block {}", i);
                assert!(get_result.unwrap().is_some(), "Block {} not found after concurrent store", i);
            });
            handles.push(handle);
        }
        
        // Attendre que toutes les tâches se terminent
        for handle in handles {
            handle.await.expect("Concurrent task failed");
        }
    }
}

#[cfg(test)]
mod sled_backend_tests {
    use super::super::sled_backend::SledBackend;
    use super::super::database::Database;
    use crate::core::{Block, BlockHeader, BlockId};
    use crate::core::transaction::CoinbaseTransaction;
    use crate::crypto::Signature;
    use std::sync::Arc;
    use tempfile::TempDir;

    const TEST_BLOCK_HASH_SIZE: usize = 32;

    #[tokio::test]
    async fn test_sled_backend_creation() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("sled_test.db");
        
        let backend = SledBackend::new(db_path.to_str().unwrap()).await;
        assert!(backend.is_ok(), "Failed to create SledBackend: {:?}", backend);
    }

    #[tokio::test]
    async fn test_sled_backend_invalid_path() {
        // Tenter de créer une base avec un chemin invalide
        let result = SledBackend::new("/invalid/path/that/does/not/exist").await;
        assert!(result.is_err(), "Should fail with invalid path");
    }

    #[tokio::test]
    async fn test_sled_serialization_roundtrip() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("serialization_test.db");
        
        let backend = SledBackend::new(db_path.to_str().unwrap())
            .await
            .expect("Failed to create backend");
        let db: Arc<dyn Database> = Arc::new(backend);

        // Créer un bloc avec des données spécifiques pour tester la sérialisation
        let header = BlockHeader {
            version: 42,
            prev_hash: [0xABu8; TEST_BLOCK_HASH_SIZE],
            merkle_root: [0xCDu8; TEST_BLOCK_HASH_SIZE],
            commitment_root: [0xEFu8; TEST_BLOCK_HASH_SIZE],
            nullifier_root: [0x12u8; TEST_BLOCK_HASH_SIZE],
            state_root: [0u8; 32],
            timestamp: 1234567890,
            difficulty: 999999,
            nonce: 0xDEADBEEF,
        };

        let coinbase = CoinbaseTransaction {
            outputs: vec![],
            fee: 5000,
            signature: Signature::default(),
            public_key: vec![0x42u8; 64], // Clé plus longue pour tester
        };

        let block = Block {
            header,
            coinbase,
            shielded_transactions: vec![],
        };

        let block_id = BlockId::from_hash(block.header.hash());

        // Store et retrieve
        let store_result = db.store_block(&block_id, &block).await;
        assert!(store_result.is_ok(), "Failed to store block with specific data");

        let retrieved = db.get_block(&block_id).await;
        assert!(retrieved.is_ok(), "Failed to retrieve block");
        
        let retrieved_block = retrieved.unwrap().unwrap();
        
        // Vérifier que tous les champs sont correctement sérialisés/désérialisés
        assert_eq!(retrieved_block.header.version, 42);
        assert_eq!(retrieved_block.header.prev_hash, [0xABu8; TEST_BLOCK_HASH_SIZE]);
        assert_eq!(retrieved_block.header.merkle_root, [0xCDu8; TEST_BLOCK_HASH_SIZE]);
        assert_eq!(retrieved_block.header.commitment_root, [0xEFu8; TEST_BLOCK_HASH_SIZE]);
        assert_eq!(retrieved_block.header.nullifier_root, [0x12u8; TEST_BLOCK_HASH_SIZE]);
        assert_eq!(retrieved_block.header.timestamp, 1234567890);
        assert_eq!(retrieved_block.header.difficulty, 999999);
        assert_eq!(retrieved_block.header.nonce, 0xDEADBEEF);
        assert_eq!(retrieved_block.coinbase.fee, 5000);
        assert_eq!(retrieved_block.coinbase.public_key.len(), 64);
        assert_eq!(retrieved_block.coinbase.public_key[0], 0x42);
    }

    #[tokio::test]
    async fn test_sled_large_data_handling() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("large_data_test.db");
        
        let backend = SledBackend::new(db_path.to_str().unwrap())
            .await
            .expect("Failed to create backend");
        let db: Arc<dyn Database> = Arc::new(backend);

        // Créer un bloc avec une grande clé publique pour tester les limites
        let large_public_key = vec![0xFFu8; 10000]; // 10KB de données
        
        let header = BlockHeader {
            version: 1,
            prev_hash: [0u8; TEST_BLOCK_HASH_SIZE],
            merkle_root: [0u8; TEST_BLOCK_HASH_SIZE],
            commitment_root: [0u8; TEST_BLOCK_HASH_SIZE],
            nullifier_root: [0u8; TEST_BLOCK_HASH_SIZE],
            state_root: [0u8; 32],
            timestamp: 1640995200,
            difficulty: 1000,
            nonce: 0,
        };

        let coinbase = CoinbaseTransaction {
            outputs: vec![],
            fee: 0,
            signature: Signature::default(),
            public_key: large_public_key.clone(),
        };

        let block = Block {
            header,
            coinbase,
            shielded_transactions: vec![],
        };

        let block_id = BlockId::from_hash(block.header.hash());

        // Test que Sled peut gérer de grandes données
        let store_result = db.store_block(&block_id, &block).await;
        assert!(store_result.is_ok(), "Failed to store block with large data");

        let retrieved = db.get_block(&block_id).await;
        assert!(retrieved.is_ok(), "Failed to retrieve block with large data");
        
        let retrieved_block = retrieved.unwrap().unwrap();
        assert_eq!(retrieved_block.coinbase.public_key.len(), 10000);
        assert_eq!(retrieved_block.coinbase.public_key, large_public_key);
    }
}

#[cfg(test)]
mod faucet_store_tests {
    use super::super::faucet_store::{FaucetClaim, FaucetStore};
    use crate::crypto::Address;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::TempDir;

    /// Crée une adresse de test
    fn create_test_address(seed: u8) -> Address {
        Address::new([seed; 32])
    }

    /// Crée un timestamp de test
    fn create_test_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
    }

    #[tokio::test]
    async fn test_faucet_store_creation() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("faucet_test.db");
        
        let store = FaucetStore::new(db_path.to_str().unwrap()).await;
        assert!(store.is_ok(), "Failed to create FaucetStore: {:?}", store);
    }

    #[tokio::test]
    async fn test_record_and_check_claim() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("faucet_claim_test.db");
        
        let store = FaucetStore::new(db_path.to_str().unwrap())
            .await
            .expect("Failed to create FaucetStore");

        let address = create_test_address(42);
        let amount = 1000000; // 1 TSN
        let timestamp = create_test_timestamp();

        // Vérifier qu'aucune claim n'existe initialement
        let initial_check = store.has_claimed(&address).await;
        assert!(initial_check.is_ok(), "Failed to check initial claim status");
        assert!(!initial_check.unwrap(), "Address should not have claimed initially");

        // Enregistrer une claim
        let record_result = store.record_claim(&address, amount, timestamp).await;
        assert!(record_result.is_ok(), "Failed to record claim: {:?}", record_result);

        // Vérifier que la claim existe maintenant
        let post_claim_check = store.has_claimed(&address).await;
        assert!(post_claim_check.is_ok(), "Failed to check post-claim status");
        assert!(post_claim_check.unwrap(), "Address should have claimed after recording");

        // Récupérer les détails de la claim
        let claim_details = store.get_claim(&address).await;
        assert!(claim_details.is_ok(), "Failed to get claim details");
        
        let claim = claim_details.unwrap();
        assert!(claim.is_some(), "Claim should exist");
        
        let claim = claim.unwrap();
        assert_eq!(claim.address, address);
        assert_eq!(claim.amount, amount);
        assert_eq!(claim.timestamp, timestamp);
    }

    #[tokio::test]
    async fn test_multiple_claims_same_address() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("multiple_claims_test.db");
        
        let store = FaucetStore::new(db_path.to_str().unwrap())
            .await
            .expect("Failed to create FaucetStore");

        let address = create_test_address(123);
        let first_amount = 500000;
        let second_amount = 750000;
        let first_timestamp = create_test_timestamp();
        let second_timestamp = first_timestamp + 3600; // 1 heure plus tard

        // Première claim
        let first_record = store.record_claim(&address, first_amount, first_timestamp).await;
        assert!(first_record.is_ok(), "Failed to record first claim");

        // Deuxième claim (devrait écraser la première)
        let second_record = store.record_claim(&address, second_amount, second_timestamp).await;
        assert!(second_record.is_ok(), "Failed to record second claim");

        // Vérifier que seule la dernière claim est conservée
        let claim_details = store.get_claim(&address).await;
        assert!(claim_details.is_ok(), "Failed to get claim details");
        
        let claim = claim_details.unwrap().unwrap();
        assert_eq!(claim.amount, second_amount, "Should have the latest amount");
        assert_eq!(claim.timestamp, second_timestamp, "Should have the latest timestamp");
    }

    #[tokio::test]
    async fn test_different_addresses() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("different_addresses_test.db");
        
        let store = FaucetStore::new(db_path.to_str().unwrap())
            .await
            .expect("Failed to create FaucetStore");

        let address1 = create_test_address(1);
        let address2 = create_test_address(2);
        let address3 = create_test_address(3);
        
        let amount1 = 1000000;
        let amount2 = 2000000;
        let timestamp = create_test_timestamp();

        // Enregistrer des claims pour différentes adresses
        let record1 = store.record_claim(&address1, amount1, timestamp).await;
        assert!(record1.is_ok(), "Failed to record claim for address1");

        let record2 = store.record_claim(&address2, amount2, timestamp + 60).await;
        assert!(record2.is_ok(), "Failed to record claim for address2");

        // Vérifier les statuts individuels
        assert!(store.has_claimed(&address1).await.unwrap(), "Address1 should have claimed");
        assert!(store.has_claimed(&address2).await.unwrap(), "Address2 should have claimed");
        assert!(!store.has_claimed(&address3).await.unwrap(), "Address3 should not have claimed");

        // Vérifier les détails individuels
        let claim1 = store.get_claim(&address1).await.unwrap().unwrap();
        assert_eq!(claim1.amount, amount1);

        let claim2 = store.get_claim(&address2).await.unwrap().unwrap();
        assert_eq!(claim2.amount, amount2);

        let claim3 = store.get_claim(&address3).await.unwrap();
        assert!(claim3.is_none(), "Address3 should have no claim");
    }

    #[tokio::test]
    async fn test_faucet_persistence() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("faucet_persistence_test.db");
        let db_path_str = db_path.to_str().unwrap();

        let address = create_test_address(99);
        let amount = 3000000;
        let timestamp = create_test_timestamp();

        // Enregistrer une claim dans la première instance
        {
            let store = FaucetStore::new(db_path_str)
                .await
                .expect("Failed to create first FaucetStore instance");
            
            let record_result = store.record_claim(&address, amount, timestamp).await;
            assert!(record_result.is_ok(), "Failed to record claim in first instance");
        }

        // Vérifier la persistence dans une nouvelle instance
        {
            let store = FaucetStore::new(db_path_str)
                .await
                .expect("Failed to create second FaucetStore instance");
            
            let has_claimed = store.has_claimed(&address).await;
            assert!(has_claimed.is_ok(), "Failed to check claim in second instance");
            assert!(has_claimed.unwrap(), "Claim should persist across instances");
            
            let claim_details = store.get_claim(&address).await;
            assert!(claim_details.is_ok(), "Failed to get claim details in second instance");
            
            let claim = claim_details.unwrap().unwrap();
            assert_eq!(claim.amount, amount, "Amount should persist");
            assert_eq!(claim.timestamp, timestamp, "Timestamp should persist");
        }
    }

    #[tokio::test]
    async fn test_faucet_claim_serialization() {
        // Test de la sérialisation/désérialisation de FaucetClaim
        let address = create_test_address(200);
        let amount = 5000000;
        let timestamp = 1640995200;

        let original_claim = FaucetClaim {
            address: address.clone(),
            amount,
            timestamp,
        };

        // Sérialiser
        let serialized = bincode::serialize(&original_claim);
        assert!(serialized.is_ok(), "Failed to serialize FaucetClaim");

        // Désérialiser
        let deserialized: Result<FaucetClaim, _> = bincode::deserialize(&serialized.unwrap());
        assert!(deserialized.is_ok(), "Failed to deserialize FaucetClaim");

        let deserialized_claim = deserialized.unwrap();
        assert_eq!(deserialized_claim.address, address);
        assert_eq!(deserialized_claim.amount, amount);
        assert_eq!(deserialized_claim.timestamp, timestamp);
    }

    #[tokio::test]
    async fn test_faucet_edge_cases() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("faucet_edge_cases_test.db");
        
        let store = FaucetStore::new(db_path.to_str().unwrap())
            .await
            .expect("Failed to create FaucetStore");

        let address = create_test_address(255);

        // Test avec amount = 0
        let zero_amount_result = store.record_claim(&address, 0, create_test_timestamp()).await;
        assert!(zero_amount_result.is_ok(), "Should allow zero amount claims");

        // Test avec timestamp = 0
        let zero_timestamp_result = store.record_claim(&address, 1000, 0).await;
        assert!(zero_timestamp_result.is_ok(), "Should allow zero timestamp");

        // Test avec amount très grand
        let large_amount = u64::MAX;
        let large_amount_result = store.record_claim(&address, large_amount, create_test_timestamp()).await;
        assert!(large_amount_result.is_ok(), "Should allow maximum amount");

        // Vérifier que la dernière valeur est conservée
        let final_claim = store.get_claim(&address).await.unwrap().unwrap();
        assert_eq!(final_claim.amount, large_amount);
    }
}