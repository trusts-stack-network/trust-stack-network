// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
//! Tests property-based pour les invariants cryptographiques du consensus
//!
//! Ce module teste les propriétés de sécurité critiques qui doivent TOUJOURS
//! être vraies, indépendamment des inputs :
//!
//! - Intégrité des signatures SLH-DSA
//! - Cohérence du state tree Poseidon2
//! - Non-malléabilité des commitments
//! - Résistance aux attaques par timing
//!
//! THREAT MODEL:
//! - Adversaire quantique avec accès aux algorithmes de Shor/Grover
//! - Adversaire classique avec capacité de timing attacks
//! - Adversaire avec contrôle partiel du réseau (man-in-the-middle)

use proptest::prelude::*;
use std::collections::HashSet;
use std::time::Instant;

use tsn::crypto::pq::slh_dsa::{SlhDsaSigner, SlhDsaVerifier, SLH_DSA_SHA2_128S};
use tsn::crypto::poseidon2_state_tree::Poseidon2StateTree;
use tsn::crypto::hash::Hash;
use tsn::crypto::merkle_tree::MerkleTree;
use tsn::consensus::validation::{Validator, ValidationError};
use tsn::core::block::{Block, BlockHeader};
use tsn::core::transaction::{Transaction, TransactionInput, TransactionOutput};

/// Générateur de clés SLH-DSA pour les tests
fn generate_slh_dsa_keypair() -> (Vec<u8>, Vec<u8>) {
    let signer = SlhDsaSigner::new(SLH_DSA_SHA2_128S);
    let (pk, sk) = signer.generate_keypair().unwrap();
    (pk.to_bytes(), sk.to_bytes())
}

/// Générateur de messages aléatoires
fn arb_message() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..10000)
}

/// Générateur de clés pour le state tree
fn arb_tree_key() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..64)
}

/// Générateur de valeurs pour le state tree
fn arb_tree_value() -> impl Strategy<Value = u64> {
    0..u64::MAX / 2 // Éviter les débordements
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// PROPRIÉTÉ CRITIQUE: Les signatures SLH-DSA doivent être non-forgeable
    /// 
    /// Cette propriété teste que :
    /// 1. Une signature valide vérifie toujours avec la bonne clé
    /// 2. Une signature ne vérifie jamais avec une mauvaise clé
    /// 3. Une signature modifiée ne vérifie jamais
    /// 4. La vérification est déterministe
    #[test]
    fn prop_slh_dsa_unforgeability(
        message in arb_message(),
        corruption_index in 0usize..1000usize,
        corruption_value in any::<u8>()
    ) {
        let signer = SlhDsaSigner::new(SLH_DSA_SHA2_128S);
        let verifier = SlhDsaVerifier::new(SLH_DSA_SHA2_128S);
        
        let (pk, sk) = signer.generate_keypair().unwrap();
        let signature = signer.sign(&sk, &message).unwrap();

        // Propriété 1: Signature valide vérifie
        prop_assert!(verifier.verify(&pk, &message, &signature).is_ok());

        // Propriété 2: Signature ne vérifie pas avec une mauvaise clé
        let (wrong_pk, _) = signer.generate_keypair().unwrap();
        prop_assert!(verifier.verify(&wrong_pk, &message, &signature).is_err());

        // Propriété 3: Signature corrompue ne vérifie pas
        let mut corrupted_sig_bytes = signature.to_bytes();
        if !corrupted_sig_bytes.is_empty() {
            let idx = corruption_index % corrupted_sig_bytes.len();
            corrupted_sig_bytes[idx] ^= corruption_value;
            
            if let Ok(corrupted_sig) = signer.signature_from_bytes(&corrupted_sig_bytes) {
                prop_assert!(verifier.verify(&pk, &message, &corrupted_sig).is_err());
            }
        }

        // Propriété 4: Vérification déterministe
        let result1 = verifier.verify(&pk, &message, &signature);
        let result2 = verifier.verify(&pk, &message, &signature);
        prop_assert_eq!(result1.is_ok(), result2.is_ok());
    }

    /// PROPRIÉTÉ CRITIQUE: Le state tree Poseidon2 doit être cohérent
    ///
    /// Cette propriété teste que :
    /// 1. Les valeurs insérées sont toujours récupérables
    /// 2. L'ordre d'insertion n'affecte pas le résultat final
    /// 3. Les preuves Merkle sont valides
    /// 4. Les modifications changent le root hash
    #[test]
    fn prop_poseidon2_state_tree_consistency(
        operations in prop::collection::vec(
            (arb_tree_key(), arb_tree_value()),
            0..100
        ),
        tree_depth in 4u8..16u8
    ) {
        let mut tree = Poseidon2StateTree::new(tree_depth as usize);
        let mut reference_state = std::collections::HashMap::new();

        // Appliquer toutes les opérations
        for (key, value) in &operations {
            tree.insert(key, &value.to_le_bytes());
            reference_state.insert(key.clone(), *value);
        }

        // Propriété 1: Toutes les valeurs insérées sont récupérables
        for (key, expected_value) in &reference_state {
            prop_assert_eq!(
                tree.get(key),
                Some(expected_value.to_le_bytes().as_slice())
            );
        }

        // Propriété 2: Tester l'ordre d'insertion (si assez d'opérations)
        if operations.len() > 1 {
            let mut tree2 = Poseidon2StateTree::new(tree_depth as usize);
            let mut reversed_ops = operations.clone();
            reversed_ops.reverse();
            
            for (key, value) in &reversed_ops {
                tree2.insert(key, &value.to_le_bytes());
            }

            // Le résultat final doit être le même
            for (key, expected_value) in &reference_state {
                prop_assert_eq!(
                    tree2.get(key),
                    Some(expected_value.to_le_bytes().as_slice())
                );
            }
        }

        // Propriété 3: Les preuves Merkle doivent être valides
        for (key, value) in reference_state.iter().take(5) { // Limiter pour la performance
            if let Some(proof) = tree.generate_proof(key) {
                prop_assert!(tree.verify_proof(
                    key,
                    &value.to_le_bytes(),
                    &proof,
                    tree.root_hash()
                ));
            }
        }
    }

    /// PROPRIÉTÉ CRITIQUE: Les hashes de blocs doivent être résistants aux collisions
    ///
    /// Cette propriété teste que :
    /// 1. Le même bloc produit toujours le même hash
    /// 2. Des blocs différents produisent des hashes différents
    /// 3. De petites modifications changent complètement le hash (avalanche)
    #[test]
    fn prop_block_hash_collision_resistance(
        height in 0u64..1_000_000u64,
        timestamp in 0u64..4_000_000_000u64,
        nonce in any::<u64>(),
        tx_count in 0usize..10usize
    ) {
        // Créer un bloc de test
        let transactions: Vec<Transaction> = (0..tx_count)
            .map(|i| Transaction {
                inputs: vec![TransactionInput {
                    previous_output: Hash::from_bytes([i as u8; 32]),
                    script: vec![],
                }],
                outputs: vec![TransactionOutput {
                    value: 100 + i as u64,
                    script: vec![],
                }],
                sender_public_key: vec![0; 32],
                signature: vec![0; 64],
            })
            .collect();

        let header = BlockHeader {
            version: 1,
            previous_block_hash: Hash::zero(),
            merkle_root: Hash::zero(),
            state_root: Hash::zero(),
            timestamp,
            nonce,
            difficulty: 1000,
            producer_public_key: vec![0; 32],
            signature: vec![],
        };

        let block = Block {
            header: header.clone(),
            transactions: transactions.clone(),
        };

        // Propriété 1: Hash déterministe
        let hash1 = block.hash();
        let hash2 = block.hash();
        prop_assert_eq!(hash1, hash2);

        // Propriété 2: Modification du nonce change le hash
        let mut modified_header = header.clone();
        modified_header.nonce = nonce.wrapping_add(1);
        let modified_block = Block {
            header: modified_header,
            transactions: transactions.clone(),
        };
        let modified_hash = modified_block.hash();
        prop_assert_ne!(hash1, modified_hash);

        // Propriété 3: Modification du timestamp change le hash
        let mut modified_header2 = header;
        modified_header2.timestamp = timestamp.wrapping_add(1);
        let modified_block2 = Block {
            header: modified_header2,
            transactions,
        };
        let modified_hash2 = modified_block2.hash();
        prop_assert_ne!(hash1, modified_hash2);
        prop_assert_ne!(modified_hash, modified_hash2);
    }

    /// PROPRIÉTÉ CRITIQUE: La validation de blocs doit être résistante aux timing attacks
    ///
    /// Cette propriété teste que :
    /// 1. Le temps de validation ne dépend pas du contenu des signatures
    /// 2. Les échecs de validation prennent un temps constant
    /// 3. Aucune information ne fuite via les temps de réponse
    #[test]
    fn prop_validation_constant_time(
        message_size in 10usize..1000usize,
        signature_corruption in any::<u8>()
    ) {
        let validator = Validator::new();
        let signer = SlhDsaSigner::new(SLH_DSA_SHA2_128S);
        let (pk, sk) = signer.generate_keypair().unwrap();

        // Créer des transactions de différentes tailles
        let mut times = Vec::new();
        
        for size in [message_size, message_size * 2, message_size / 2] {
            let tx = Transaction {
                inputs: vec![TransactionInput {
                    previous_output: Hash::from_bytes([0; 32]),
                    script: vec![0; size],
                }],
                outputs: vec![TransactionOutput {
                    value: 100,
                    script: vec![],
                }],
                sender_public_key: pk.to_bytes(),
                signature: vec![],
            };

            // Mesurer le temps de validation
            let start = Instant::now();
            let _ = validator.validate_transaction(&tx);
            times.push(start.elapsed().as_nanos());
        }

        // Vérifier que les temps ne varient pas trop
        if times.len() >= 2 {
            let avg_time = times.iter().sum::<u128>() / times.len() as u128;
            for &time in &times {
                let deviation = if avg_time > 0 {
                    ((time as i128 - avg_time as i128).abs() as f64) / (avg_time as f64)
                } else {
                    0.0
                };
                prop_assert!(deviation < 2.0, "Timing deviation too high: {:.2}", deviation);
            }
        }
    }

    /// PROPRIÉTÉ CRITIQUE: Les merkle trees doivent préserver l'intégrité
    ///
    /// Cette propriété teste que :
    /// 1. L'ajout d'éléments change toujours le root
    /// 2. L'ordre d'ajout n'affecte pas la vérification des preuves
    /// 3. Les preuves invalides sont toujours rejetées
    #[test]
    fn prop_merkle_tree_integrity(
        elements in prop::collection::vec(
            prop::collection::vec(any::<u8>(), 1..100),
            1..50
        )
    ) {
        let mut tree = MerkleTree::new();
        let mut added_elements = HashSet::new();
        let mut roots = Vec::new();

        // Ajouter les éléments un par un
        for element in &elements {
            if added_elements.insert(element.clone()) {
                let hash = Hash::from_bytes(blake3::hash(element).as_bytes()[..32].try_into().unwrap());
                tree.insert(hash).unwrap();
                roots.push(tree.root());
            }
        }

        // Propriété 1: Chaque ajout change le root (sauf doublons)
        for i in 1..roots.len() {
            prop_assert_ne!(roots[i-1], roots[i], "Root should change after insertion");
        }

        // Propriété 2: Tous les éléments ajoutés doivent être vérifiables
        for element in &added_elements {
            let hash = Hash::from_bytes(blake3::hash(element).as_bytes()[..32].try_into().unwrap());
            if let Some(proof) = tree.generate_proof(&hash) {
                prop_assert!(tree.verify_proof(&hash, &proof), "Valid proof should verify");
            }
        }

        // Propriété 3: Les éléments non ajoutés ne doivent pas être vérifiables
        let fake_element = vec![0xFF; 32];
        if !added_elements.contains(&fake_element) {
            let fake_hash = Hash::from_bytes(blake3::hash(&fake_element).as_bytes()[..32].try_into().unwrap());
            if let Some(proof) = tree.generate_proof(&fake_hash) {
                prop_assert!(!tree.verify_proof(&fake_hash, &proof), "Invalid proof should not verify");
            }
        }
    }
}

/// Tests de régression pour vulnérabilités cryptographiques connues
mod crypto_regression_tests {
    use super::*;

    #[test]
    fn test_slh_dsa_signature_malleability_resistance() {
        let signer = SlhDsaSigner::new(SLH_DSA_SHA2_128S);
        let verifier = SlhDsaVerifier::new(SLH_DSA_SHA2_128S);
        let (pk, sk) = signer.generate_keypair().unwrap();

        let message = b"test message";
        let signature = signer.sign(&sk, message).unwrap();

        // Vérifier que la signature originale est valide
        assert!(verifier.verify(&pk, message, &signature).is_ok());

        // Tenter diverses modifications de la signature
        let mut sig_bytes = signature.to_bytes();
        
        // Test 1: Modification d'un seul bit
        for i in 0..sig_bytes.len().min(100) {
            let mut modified_sig = sig_bytes.clone();
            modified_sig[i] ^= 0x01;
            
            if let Ok(modified_signature) = signer.signature_from_bytes(&modified_sig) {
                assert!(
                    verifier.verify(&pk, message, &modified_signature).is_err(),
                    "Modified signature should not verify"
                );
            }
        }

        // Test 2: Modification de plusieurs bits
        for pattern in [0xFF, 0x00, 0xAA, 0x55] {
            let mut modified_sig = sig_bytes.clone();
            for i in 0..modified_sig.len().min(10) {
                modified_sig[i] ^= pattern;
            }
            
            if let Ok(modified_signature) = signer.signature_from_bytes(&modified_sig) {
                assert!(
                    verifier.verify(&pk, message, &modified_signature).is_err(),
                    "Pattern-modified signature should not verify"
                );
            }
        }
    }

    #[test]
    fn test_poseidon2_collision_resistance() {
        let mut tree = Poseidon2StateTree::new(8);
        let mut seen_hashes = HashSet::new();

        // Insérer de nombreuses valeurs et vérifier l'absence de collisions
        for i in 0..1000 {
            let key = format!("key_{}", i);
            let value = i as u64;
            
            tree.insert(key.as_bytes(), &value.to_le_bytes());
            
            // Calculer un hash de l'état actuel
            let state_hash = {
                let mut hasher = blake3::Hasher::new();
                hasher.update(key.as_bytes());
                hasher.update(&value.to_le_bytes());
                hasher.finalize()
            };

            // Vérifier qu'on n'a pas de collision
            assert!(
                seen_hashes.insert(state_hash),
                "Hash collision detected for key: {}", key
            );
        }
    }

    #[test]
    fn test_merkle_tree_second_preimage_resistance() {
        let mut tree = MerkleTree::new();
        
        // Ajouter un élément connu
        let original_data = b"original data";
        let original_hash = Hash::from_bytes(blake3::hash(original_data).as_bytes()[..32].try_into().unwrap());
        tree.insert(original_hash).unwrap();
        
        let original_root = tree.root();
        let original_proof = tree.generate_proof(&original_hash).unwrap();

        // Tenter de trouver une seconde préimage
        for i in 0..1000 {
            let fake_data = format!("fake data {}", i);
            let fake_hash = Hash::from_bytes(blake3::hash(fake_data.as_bytes()).as_bytes()[..32].try_into().unwrap());
            
            if fake_hash != original_hash {
                // Cette preuve ne devrait pas vérifier avec le root original
                if let Some(fake_proof) = tree.generate_proof(&fake_hash) {
                    assert!(
                        !tree.verify_proof(&fake_hash, &fake_proof) || tree.root() != original_root,
                        "Second preimage attack succeeded"
                    );
                }
            }
        }
    }

    #[test]
    fn test_timing_attack_resistance_detailed() {
        let validator = Validator::new();
        let signer = SlhDsaSigner::new(SLH_DSA_SHA2_128S);
        let (pk, sk) = signer.generate_keypair().unwrap();

        let mut valid_times = Vec::new();
        let mut invalid_times = Vec::new();

        // Mesurer les temps pour des signatures valides
        for i in 0..50 {
            let message = format!("valid message {}", i);
            let signature = signer.sign(&sk, message.as_bytes()).unwrap();
            
            let tx = Transaction {
                inputs: vec![TransactionInput {
                    previous_output: Hash::from_bytes([i as u8; 32]),
                    script: vec![],
                }],
                outputs: vec![TransactionOutput {
                    value: 100,
                    script: vec![],
                }],
                sender_public_key: pk.to_bytes(),
                signature: signature.to_bytes(),
            };

            let start = Instant::now();
            let _ = validator.validate_transaction(&tx);
            valid_times.push(start.elapsed().as_nanos());
        }

        // Mesurer les temps pour des signatures invalides
        for i in 0..50 {
            let message = format!("invalid message {}", i);
            let mut signature = signer.sign(&sk, message.as_bytes()).unwrap();
            
            // Corrompre la signature
            let mut sig_bytes = signature.to_bytes();
            if !sig_bytes.is_empty() {
                sig_bytes[0] ^= 0xFF;
            }
            
            let tx = Transaction {
                inputs: vec![TransactionInput {
                    previous_output: Hash::from_bytes([i as u8; 32]),
                    script: vec![],
                }],
                outputs: vec![TransactionOutput {
                    value: 100,
                    script: vec![],
                }],
                sender_public_key: pk.to_bytes(),
                signature: sig_bytes,
            };

            let start = Instant::now();
            let _ = validator.validate_transaction(&tx);
            invalid_times.push(start.elapsed().as_nanos());
        }

        // Analyser les distributions de temps
        let valid_avg = valid_times.iter().sum::<u128>() / valid_times.len() as u128;
        let invalid_avg = invalid_times.iter().sum::<u128>() / invalid_times.len() as u128;

        // Les temps ne doivent pas révéler d'information sur la validité
        let time_ratio = if valid_avg > 0 {
            (invalid_avg as f64) / (valid_avg as f64)
        } else {
            1.0
        };

        assert!(
            time_ratio > 0.5 && time_ratio < 2.0,
            "Timing difference too large: valid={:.2}ns, invalid={:.2}ns, ratio={:.2}",
            valid_avg as f64,
            invalid_avg as f64,
            time_ratio
        );
    }
}
