//! Tests property-based pour détecter les panics sur entrées arbitraires
//!
//! Ces tests utilisent proptest pour générer des entrées aléatoires et
//! vérifier que les fonctions critiques ne paniquent jamais.

use proptest::prelude::*;
use std::panic;

/// Wrapper sécurisé pour capturer les panics
fn catch_panic<F, R>(f: F) -> Result<R, ()>
where
    F: FnOnce() -> R + panic::UnwindSafe,
{
    match panic::catch_unwind(f) {
        Ok(result) => Ok(result),
        Err(_) => Err(()),
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1000,
        max_shrink_iters: 100,
        ..ProptestConfig::default()
    })]

    /// Test property-based: NoteCommitment::from_bytes ne panique jamais
    #[test]
    fn prop_note_commitment_from_bytes_no_panic(data in any::<Vec<u8>>()) {
        use tsn_core::crypto::commitment::NoteCommitment;

        let result = catch_panic(|| {
            let _ = NoteCommitment::from_bytes(&data);
        });

        prop_assert!(
            result.is_ok(),
            "PANIC détectée dans NoteCommitment::from_bytes avec {:?}",
            &data[..data.len().min(32)]
        );
    }

    /// Test property-based: ValueCommitment::from_bytes ne panique jamais
    #[test]
    fn prop_value_commitment_from_bytes_no_panic(data in any::<Vec<u8>>()) {
        use tsn_core::crypto::commitment::ValueCommitment;

        let result = catch_panic(|| {
            let _ = ValueCommitment::from_bytes(&data);
        });

        prop_assert!(
            result.is_ok(),
            "PANIC détectée dans ValueCommitment::from_bytes avec {:?}",
            &data[..data.len().min(32)]
        );
    }

    /// Test property-based: ShieldedAddress::from_bytes ne panique jamais
    #[test]
    fn prop_shielded_address_from_bytes_no_panic(data in any::<Vec<u8>>()) {
        use tsn_core::crypto::address::ShieldedAddress;

        let result = catch_panic(|| {
            let _ = ShieldedAddress::from_bytes(&data);
        });

        prop_assert!(
            result.is_ok(),
            "PANIC détectée dans ShieldedAddress::from_bytes avec {:?}",
            &data[..data.len().min(32)]
        );
    }

    /// Test property-based: Nullifier::from_bytes ne panique jamais
    #[test]
    fn prop_nullifier_from_bytes_no_panic(data in any::<Vec<u8>>()) {
        use tsn_core::crypto::nullifier::Nullifier;

        let result = catch_panic(|| {
            let _ = Nullifier::from_bytes(&data);
        });

        prop_assert!(
            result.is_ok(),
            "PANIC détectée dans Nullifier::from_bytes avec {:?}",
            &data[..data.len().min(32)]
        );
    }

    /// Test property-based: Signature::from_bytes ne panique jamais
    #[test]
    fn prop_signature_from_bytes_no_panic(data in any::<Vec<u8>>()) {
        use tsn_core::crypto::signature::Signature;

        let result = catch_panic(|| {
            let _ = Signature::from_bytes(&data);
        });

        prop_assert!(
            result.is_ok(),
            "PANIC détectée dans Signature::from_bytes avec {:?}",
            &data[..data.len().min(32)]
        );
    }

    /// Test property-based: ShieldedBlock::deserialize ne panique jamais
    #[test]
    fn prop_block_deserialize_no_panic(data in any::<Vec<u8>>()) {
        use tsn_core::core::ShieldedBlock;

        let result = catch_panic(|| {
            let _ = ShieldedBlock::deserialize(&data);
        });

        prop_assert!(
            result.is_ok(),
            "PANIC détectée dans ShieldedBlock::deserialize avec données de taille {}",
            data.len()
        );
    }

    /// Test property-based: ShieldedTransaction::deserialize ne panique jamais
    #[test]
    fn prop_transaction_deserialize_no_panic(data in any::<Vec<u8>>()) {
        use tsn_core::core::ShieldedTransaction;

        let result = catch_panic(|| {
            let _ = ShieldedTransaction::deserialize(&data);
        });

        prop_assert!(
            result.is_ok(),
            "PANIC détectée dans ShieldedTransaction::deserialize avec données de taille {}",
            data.len()
        );
    }

    /// Test property-based: ZkProof::deserialize ne panique jamais
    #[test]
    fn prop_zkproof_deserialize_no_panic(data in any::<Vec<u8>>()) {
        use tsn_core::crypto::proof::ZkProof;

        let result = catch_panic(|| {
            let _ = ZkProof::deserialize(&data);
        });

        prop_assert!(
            result.is_ok(),
            "PANIC détectée dans ZkProof::deserialize avec données de taille {}",
            data.len()
        );
    }

    /// Test property-based: MerkleTree avec entrées aléatoires
    #[test]
    fn prop_merkle_tree_no_panic(leaves in prop::collection::vec(
        any::<[u8; 32]>(),
        0..100
    )) {
        use tsn_core::crypto::merkle_tree::MerkleTree;

        let result = catch_panic(|| {
            let _ = MerkleTree::new(&leaves);
        });

        prop_assert!(
            result.is_ok(),
            "PANIC détectée dans MerkleTree::new avec {} feuilles",
            leaves.len()
        );
    }

    /// Test property-based: CommitmentTree avec entrées aléatoires
    #[test]
    fn prop_commitment_tree_operations_no_panic(
        commitments in prop::collection::vec(
            any::<[u8; 32]>(),
            0..50
        ),
        query_index in 0usize..100usize
    ) {
        use tsn_core::crypto::merkle_tree::CommitmentTree;
        use tsn_core::crypto::commitment::NoteCommitment;

        let result = catch_panic(|| {
            let mut tree = CommitmentTree::new();
            
            for cm_bytes in &commitments {
                let cm = NoteCommitment(*cm_bytes);
                tree.append(&cm);
            }
            
            // Ces opérations ne doivent jamais paniquer
            let _ = tree.root();
            let _ = tree.get_path(query_index);
            let _ = tree.get_commitment(query_index);
            let _ = tree.witness(query_index);
            let _ = tree.is_empty();
            let _ = tree.len();
        });

        prop_assert!(
            result.is_ok(),
            "PANIC détectée dans CommitmentTree avec {} commitments, index {}",
            commitments.len(),
            query_index
        );
    }

    /// Test property-based: poseidon_hash avec entrées aléatoires
    #[test]
    fn prop_poseidon_hash_no_panic(
        inputs in prop::collection::vec(
            any::<[u8; 32]>(),
            0..20
        ),
        domain in any::<u64>()
    ) {
        use tsn_core::crypto::poseidon::poseidon_hash;
        use ark_bn254::Fr;

        let result = catch_panic(|| {
            let fr_inputs: Vec<Fr> = inputs.iter()
                .map(|b| Fr::from_le_bytes_mod_order(b))
                .collect();
            
            let _ = poseidon_hash(domain, &fr_inputs);
        });

        prop_assert!(
            result.is_ok(),
            "PANIC détectée dans poseidon_hash avec {} inputs, domain {}",
            inputs.len(),
            domain
        );
    }

    /// Test property-based: vérification de signature avec clés aléatoires
    #[test]
    fn prop_signature_verify_no_panic(
        pk in any::<Vec<u8>>(),
        sig in any::<Vec<u8>>(),
        message in any::<Vec<u8>>()
    ) {
        use tsn_core::crypto::signature::Signature;

        let result = catch_panic(|| {
            let _ = Signature::verify(&pk, &message, &sig);
        });

        prop_assert!(
            result.is_ok(),
            "PANIC détectée dans Signature::verify avec pk.len={}, sig.len={}, msg.len={}",
            pk.len(),
            sig.len(),
            message.len()
        );
    }

    /// Test property-based: KeyPair::from_seed avec entrées aléatoires
    #[test]
    fn prop_keypair_from_seed_no_panic(seed in any::<[u8; 32]>()) {
        use tsn_core::crypto::keys::KeyPair;

        let result = catch_panic(|| {
            let _ = KeyPair::from_seed(&seed);
        });

        prop_assert!(
            result.is_ok(),
            "PANIC détectée dans KeyPair::from_seed"
        );
    }

    /// Test property-based: ShieldedAddress::from_str avec chaînes aléatoires
    #[test]
    fn prop_address_from_str_no_panic(s in "[a-zA-Z0-9]*") {
        use tsn_core::crypto::address::ShieldedAddress;
        use std::str::FromStr;

        let result = catch_panic(|| {
            let _ = ShieldedAddress::from_str(&s);
        });

        prop_assert!(
            result.is_ok(),
            "PANIC détectée dans ShieldedAddress::from_str avec '{}'",
            s
        );
    }
}

/// Test de régression spécifique pour les valeurs limites
#[test]
fn test_edge_cases_no_panic() {
    use tsn_core::crypto::commitment::{NoteCommitment, ValueCommitment};
    use tsn_core::crypto::address::ShieldedAddress;
    use tsn_core::crypto::nullifier::Nullifier;
    use tsn_core::crypto::signature::Signature;
    use tsn_core::core::{ShieldedBlock, ShieldedTransaction};
    use tsn_core::crypto::proof::ZkProof;

    // Cas limites pour chaque type
    let edge_cases = vec![
        vec![],
        vec![0u8; 1],
        vec![0xff; 1],
        vec![0u8; 31],
        vec![0xff; 31],
        vec![0u8; 32],
        vec![0xff; 32],
        vec![0u8; 33],
        vec![0xff; 33],
        vec![0u8; 64],
        vec![0xff; 64],
        vec![0u8; 100],
        vec![0xff; 100],
        vec![0u8; 1000],
        vec![0xff; 1000],
        vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
    ];

    for data in &edge_cases {
        // NoteCommitment
        let result = catch_panic(|| {
            let _ = NoteCommitment::from_bytes(data);
        });
        assert!(result.is_ok(), "PANIC dans NoteCommitment::from_bytes");

        // ValueCommitment
        let result = catch_panic(|| {
            let _ = ValueCommitment::from_bytes(data);
        });
        assert!(result.is_ok(), "PANIC dans ValueCommitment::from_bytes");

        // ShieldedAddress
        let result = catch_panic(|| {
            let _ = ShieldedAddress::from_bytes(data);
        });
        assert!(result.is_ok(), "PANIC dans ShieldedAddress::from_bytes");

        // Nullifier
        let result = catch_panic(|| {
            let _ = Nullifier::from_bytes(data);
        });
        assert!(result.is_ok(), "PANIC dans Nullifier::from_bytes");

        // Signature
        let result = catch_panic(|| {
            let _ = Signature::from_bytes(data);
        });
        assert!(result.is_ok(), "PANIC dans Signature::from_bytes");

        // ShieldedBlock
        let result = catch_panic(|| {
            let _ = ShieldedBlock::deserialize(data);
        });
        assert!(result.is_ok(), "PANIC dans ShieldedBlock::deserialize");

        // ShieldedTransaction
        let result = catch_panic(|| {
            let _ = ShieldedTransaction::deserialize(data);
        });
        assert!(result.is_ok(), "PANIC dans ShieldedTransaction::deserialize");

        // ZkProof
        let result = catch_panic(|| {
            let _ = ZkProof::deserialize(data);
        });
        assert!(result.is_ok(), "PANIC dans ZkProof::deserialize");
    }
}
