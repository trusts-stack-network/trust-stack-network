// DISABLED: uses API/modules that no longer exist in current codebase
#![cfg(feature = "disabled_test")]
use proptest::prelude::*;
use tsn::core::block::{Block, BlockHeader};
use tsn::core::transaction::Transaction;
use tsn::crypto::hash::Hash;
use tsn::crypto::merkle_tree::MerkleTree;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10000))]

    #[test]
    fn prop_block_header_invariants(
        height in 0u64..1_000_000u64,
        timestamp in 0u64..4_000_000_000u64,
        nonce in proptest::num::u64::ANY
    ) {
        // Test que le header respecte les invariants de sécurité
        let header = BlockHeader {
            height,
            timestamp,
            previous_hash: Hash::zero(),
            merkle_root: Hash::zero(),
            nonce,
            difficulty: 1000,
        };
        
        // Le hash doit être déterministe
        let hash1 = header.hash();
        let hash2 = header.hash();
        prop_assert_eq!(hash1, hash2, "Header hash must be deterministic");
        
        // Le hash doit changer si n'importe quel champ change
        let mut header_modified = header.clone();
        header_modified.nonce = nonce.wrapping_add(1);
        let hash_modified = header_modified.hash();
        prop_assert_ne!(hash1, hash_modified, "Header hash must change with nonce");
    }

    #[test]
    fn prop_block_merkle_integrity(
        tx_count in 0usize..100usize
    ) {
        // Test l'intégrité du Merkle root
        let mut transactions = Vec::new();
        for i in 0..tx_count {
            transactions.push(Transaction::mock(i as u64));
        }
        
        let mut tree = MerkleTree::new();
        for tx in &transactions {
            tree.insert(tx.hash()).expect("Failed to insert transaction");
        }
        
        let merkle_root = tree.root();
        
        // Créer un bloc avec ces transactions
        let block = Block {
            header: BlockHeader {
                height: 1,
                timestamp: 1234567890,
                previous_hash: Hash::zero(),
                merkle_root,
                nonce: 12345,
                difficulty: 1000,
            },
            transactions,
        };
        
        // Vérifier que le Merkle root est cohérent
        let computed_root = block.compute_merkle_root()
            .expect("Failed to compute Merkle root");
        prop_assert_eq!(merkle_root, computed_root, "Merkle root mismatch");
    }

    #[test]
    fn prop_block_size_limits(
        tx_count in 1000usize..100_000usize
    ) {
        // Test que les blocs trop grands sont rejetés
        let transactions = vec![Transaction::mock(0); tx_count];
        
        let block = Block {
            header: BlockHeader {
                height: 1,
                timestamp: 1234567890,
                previous_hash: Hash::zero(),
                merkle_root: Hash::zero(),
                nonce: 12345,
                difficulty: 1000,
            },
            transactions,
        };
        
        // Vérifier que le bloc est rejeté s'il est trop grand
        let serialized = block.serialize();
        prop_assert!(serialized.len() < 10_000_000, "Block too large: {} bytes", serialized.len());
    }
}

#[test]
fn test_block_deserialization_edge_cases() {
    // Test 1: Buffer vide
    let empty = vec![];
    assert!(Block::deserialize(&empty).is_err(), "Empty buffer should fail");
    
    // Test 2: Buffer trop petit pour un header
    let tiny = vec![0u8; 10];
    assert!(Block::deserialize(&tiny).is_err(), "Tiny buffer should fail");
    
    // Test 3: Payload avec taille déclarée mensongère
    let mut fake_size = vec![0xFF, 0xFF, 0xFF, 0xFF]; // Taille déclarée: 4GB
    fake_size.extend_from_slice(&[0u8; 100]);
    assert!(Block::deserialize(&fake_size).is_err(), "Fake size should fail");
    
    // Test 4: Régression: ancien bug de parsing
    let regression_test = hex::decode("010000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
    assert!(Block::deserialize(&regression_test).is_err(), "Regression test should fail");
}

#[test]
fn test_block_timing_attack_resistance() {
    use std::time::Instant;
    
    // Vérifier que le parsing prend un temps constant quelle que soit l'input
    let inputs = vec![
        vec![0u8; 1000],
        vec![0xFF; 1000],
        (0..1000).map(|i| (i % 256) as u8).collect(),
    ];
    
    let mut times = Vec::new();
    for input in inputs {
        let start = Instant::now();
        let _ = Block::deserialize(&input);
        times.push(start.elapsed().as_nanos());
    }
    
    // Vérifier que les temps ne varient pas trop (pas de timing leak)
    let avg_time = times.iter().sum::<u128>() / times.len() as u128;
    for &time in &times {
        let deviation = ((time as i128 - avg_time as i128).abs() as f64) / (avg_time as f64);
        assert!(deviation < 0.5, "Timing deviation too high: {}", deviation);
    }
}
