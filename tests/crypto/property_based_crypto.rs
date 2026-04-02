use proptest::prelude::*;
use tsn_crypto::keys::{PublicKey, SecretKey};
use tsn_crypto::signature::{Signature, verify_signature};
use tsn_crypto::commitment::Commitment;
use tsn_crypto::nullifier::Nullifier;
use rand::thread_rng;

proptest! {
    /// Property: La vérification de signature devrait être correcte
    #[test]
    fn prop_signature_verification(
        message in prop::collection::vec(any::<u8>(), 0..1000),
        seed in any::<u64>()
    ) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let sk = SecretKey::generate(&mut rng);
        let pk = PublicKey::from(&sk);
        
        let signature = sk.sign(&message, &mut rng);
        
        // Devrait vérifier avec la bonne clé
        prop_assert!(verify_signature(&pk, &message, &signature));
        
        // Ne devrait pas vérifier avec une mauvaise clé
        let wrong_sk = SecretKey::generate(&mut rng);
        let wrong_pk = PublicKey::from(&wrong_sk);
        prop_assert!(!verify_signature(&wrong_pk, &message, &signature));
        
        // Ne devrait pas vérifier avec un mauvais message
        let mut wrong_message = message.clone();
        if !wrong_message.is_empty() {
            wrong_message[0] ^= 0x01;
            prop_assert!(!verify_signature(&pk, &wrong_message, &signature));
        }
    }
    
    /// Property: Les commitments devraient être contraignants
    #[test]
    fn prop_commitment_binding(
        value in any::<u64>(),
        blinding in any::<[u8; 32]>()
    ) {
        let commitment = Commitment::new(value, &blinding);
        
        // Même valeur et blindage = même commitment
        let commitment2 = Commitment::new(value, &blinding);
        prop_assert_eq!(commitment, commitment2);
        
        // Valeur différente = commitment différent
        let commitment3 = Commitment::new(value.wrapping_add(1), &blinding);
        prop_assert_ne!(commitment, commitment3);
        
        // Blinding différent = commitment différent
        let mut blinding2 = blinding;
        blinding2[0] ^= 0x01;
        let commitment4 = Commitment::new(value, &blinding2);
        prop_assert_ne!(commitment, commitment4);
    }
    
    /// Property: Les nullifiers devraient être uniques
    #[test]
    fn prop_nullifier_uniqueness(
        note_commitment in any::<[u8; 32]>(),
        spender_sk in any::<[u8; 32]>(),
        seed in any::<u64>()
    ) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        
        let nullifier1 = Nullifier::derive(&note_commitment, &spender_sk, &mut rng);
        let nullifier2 = Nullifier::derive(&note_commitment, &spender_sk, &mut rng);
        
        // Même inputs = même nullifier
        prop_assert_eq!(nullifier1, nullifier2);
        
        // Note différente = nullifier différent
        let mut note2 = note_commitment;
        note2[0] ^= 0x01;
        let nullifier3 = Nullifier::derive(&note2, &spender_sk, &mut rng);
        prop_assert_ne!(nullifier1, nullifier3);
    }
}