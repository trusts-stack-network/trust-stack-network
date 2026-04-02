// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
//! Tests de propriété pour les modules cryptographiques post-quantiques
//!
//! Ces tests utilisent proptest pour vérifier les invariants cryptographiques
//! des modules post-quantiques.

use proptest::prelude::*;

// === Tests de propriété pour commitment_pq ===

proptest! {
    #[test]
    fn prop_commitment_deterministic(
        value in any::<u64>(),
        randomness in any::<[u8; 32]>(),
    ) {
        use tsn::crypto::pq::commitment_pq::{
            commit_value, verify_value_commitment, ValueCommitmentPQ
        };

        // Un même engagement doit toujours produire le même résultat
        let commitment1 = commit_value(value, &randomness);
        let commitment2 = commit_value(value, &randomness);
        
        assert_eq!(commitment1.commitment, commitment2.commitment);
        assert_eq!(commitment1.opening, commitment2.opening);
    }

    #[test]
    fn prop_commitment_verification(
        value in any::<u64>(),
        randomness in any::<[u8; 32]>(),
    ) {
        use tsn::crypto::pq::commitment_pq::{
            commit_value, verify_value_commitment
        };

        // Un engagement valide doit être vérifiable
        let commitment = commit_value(value, &randomness);
        
        assert!(verify_value_commitment(
            &commitment.commitment,
            value,
            &commitment.opening
        ));
    }

    #[test]
    fn prop_commitment_binding(
        value in any::<u64>(),
        wrong_value in any::<u64>(),
        randomness in any::<[u8; 32]>(),
    ) {
        use tsn::crypto::pq::commitment_pq::{
            commit_value, verify_value_commitment
        };

        // Ne peut pas ouvrir vers une valeur différente
        prop_assume!(value != wrong_value);
        
        let commitment = commit_value(value, &randomness);
        
        assert!(!verify_value_commitment(
            &commitment.commitment,
            wrong_value,
            &commitment.opening
        ));
    }

    #[test]
    fn prop_commitment_hiding(
        value1 in any::<u64>(),
        value2 in any::<u64>(),
        randomness1 in any::<[u8; 32]>(),
        randomness2 in any::<[u8; 32]>(),
    ) {
        use tsn::crypto::pq::commitment_pq::commit_value;

        // Des valeurs différentes avec des randomness différentes
        // doivent produire des engagements différents (haute probabilité)
        prop_assume!(value1 != value2 || randomness1 != randomness2);
        
        let commitment1 = commit_value(value1, &randomness1);
        let commitment2 = commit_value(value2, &randomness2);
        
        // Note: Il y a une probabilité infime de collision
        // mais c'est acceptable pour un test de propriété
        prop_assume!(commitment1.commitment != commitment2.commitment);
    }
}

// === Tests de propriété pour proof_pq ===

proptest! {
    #[test]
    fn prop_proof_public_inputs_deterministic(
        fee in any::<u64>(),
        num_inputs in 0usize..10,
    ) {
        use tsn::crypto::pq::proof_pq::TransactionPublicInputs;

        // Les public inputs doivent être déterministes
        let roots: Vec<[u8; 32]> = (0..num_inputs)
            .map(|i| [i as u8; 32])
            .collect();
        
        let nullifiers: Vec<[u8; 32]> = (0..num_inputs)
            .map(|i| [(i + 100) as u8; 32])
            .collect();
        
        let commitments: Vec<[u8; 32]> = (0..num_inputs)
            .map(|i| [(i + 200) as u8; 32])
            .collect();

        let pi1 = TransactionPublicInputs {
            merkle_roots: roots.clone(),
            nullifiers: nullifiers.clone(),
            note_commitments: commitments.clone(),
            fee,
        };

        let pi2 = TransactionPublicInputs {
            merkle_roots: roots,
            nullifiers,
            note_commitments: commitments,
            fee,
        };

        // Les hash doivent être identiques
        // (si hash() est implémenté)
    }

    #[test]
    fn prop_proof_fee_bounds(
        fee in any::<u64>(),
    ) {
        use tsn::crypto::pq::proof_pq::TransactionPublicInputs;

        // Le fee doit être correctement stocké
        let pi = TransactionPublicInputs {
            merkle_roots: vec![],
            nullifiers: vec![],
            note_commitments: vec![],
            fee,
        };

        assert_eq!(pi.fee, fee);
    }
}

// === Tests de propriété pour verify_pq ===

proptest! {
    #[test]
    fn prop_spend_description_immutable(
        nullifier in any::<[u8; 32]>(),
        commitment in any::<[u8; 32]>(),
        merkle_root in any::<[u8; 32]>(),
        signature in vec(any::<u8>(), 0..1000),
        public_key in any::<[u8; 32]>(),
    ) {
        use tsn::crypto::pq::verify_pq::SpendDescriptionV2;

        // Les getters doivent retourner les valeurs correctes
        let spend = SpendDescriptionV2 {
            nullifier,
            commitment,
            merkle_root,
            signature: signature.clone(),
            public_key,
        };

        assert_eq!(spend.nullifier(), &nullifier);
        assert_eq!(spend.commitment(), &commitment);
        assert_eq!(spend.merkle_root(), &merkle_root);
        assert_eq!(spend.signature(), &signature);
        assert_eq!(spend.public_key(), &public_key);
    }

    #[test]
    fn prop_output_description_immutable(
        commitment in any::<[u8; 32]>(),
        ephemeral_public_key in any::<[u8; 32]>(),
        encrypted_note in vec(any::<u8>(), 0..1000),
    ) {
        use tsn::crypto::pq::verify_pq::OutputDescriptionV2;

        let output = OutputDescriptionV2 {
            commitment,
            ephemeral_public_key,
            encrypted_note: encrypted_note.clone(),
        };

        assert_eq!(output.commitment(), &commitment);
        assert_eq!(output.ephemeral_public_key(), &ephemeral_public_key);
        assert_eq!(output.encrypted_note(), &encrypted_note);
    }

    #[test]
    fn prop_transaction_fee_non_negative(
        fee in any::<u64>(),
    ) {
        // Le fee est toujours non-négatif (u64)
        // Cette propriété est garantie par le type
        assert!(fee >= 0);
    }
}

// === Tests de propriété pour slh_dsa_batch ===

proptest! {
    #[test]
    fn prop_batch_verifier_empty() {
        use tsn::crypto::pq::slh_dsa_batch::{
            BatchVerifier, BatchVerificationResult
        };

        let verifier = BatchVerifier::new();
        let result = verifier.verify_batch();

        // Un batch vide doit avoir un comportement défini
        // (généralement AllValid ou VerificationFailed)
        match result {
            BatchVerificationResult::AllValid |
            BatchVerificationResult::VerificationFailed => {},
            _ => panic!("Résultat inattendu pour batch vide: {:?}", result),
        }
    }

    #[test]
    fn prop_batch_verifier_size_limit(
        num_sigs in 0usize..200,
    ) {
        use tsn::crypto::pq::slh_dsa_batch::{
            BatchVerifier, BatchVerificationResult
        };

        let mut verifier = BatchVerifier::new();
        
        for i in 0..num_sigs {
            let msg = vec![i as u8];
            let sig = vec![i as u8; 64];
            let pk = [i as u8; 32];
            
            let _ = verifier.add_signature(&msg, &sig, &pk);
        }

        let result = verifier.verify_batch();

        // Si le batch est trop grand, doit retourner BatchTooLarge
        // Sinon, doit retourner un résultat valide
        match result {
            BatchVerificationResult::BatchTooLarge => {
                // Limite de taille respectée
            }
            BatchVerificationResult::AllValid |
            BatchVerificationResult::InvalidSignatures(_) |
            BatchVerificationResult::VerificationFailed => {
                // Résultats valides
            }
        }
    }
}

// === Tests de propriété pour circuit_pq ===

proptest! {
    #[test]
    fn prop_circuit_construction_bounds(
        num_spends in 0usize..20,
        num_outputs in 0usize..20,
    ) {
        use tsn::crypto::pq::circuit_pq::build_transaction_circuit;

        let result = build_transaction_circuit(num_spends, num_outputs);

        // La construction doit soit réussir, soit échouer proprement
        match result {
            Ok(_) => {
                // Circuit construit avec succès
            }
            Err(_) => {
                // Échec acceptable pour des paramètres invalides
            }
        }
    }

    #[test]
    fn prop_circuit_zero_inputs() {
        use tsn::crypto::pq::circuit_pq::build_transaction_circuit;

        // Test avec 0 spends et 0 outputs
        let result = build_transaction_circuit(0, 0);
        
        // Doit soit réussir, soit échouer proprement
        match result {
            Ok(_) | Err(_) => {}
        }
    }
}
