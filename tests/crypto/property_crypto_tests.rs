use proptest::prelude::*;
use tsn_crypto::{
    keys::{KeyPair, PublicKey},
    signature::Signature,
    commitment::Commitment,
    nullifier::Nullifier,
    poseidon::PoseidonHash,
};
use rand::thread_rng;

proptest! {
    /// Property: La vérification d'une signature valide doit toujours réussir
    #[test]
    fn prop_signature_verification_valid(
        message in prop::collection::vec(any::<u8>(), 0..1024)
    ) {
        let mut rng = thread_rng();
        let kp = KeyPair::generate(&mut rng);
        let sig = kp.secret.sign(&message);
        
        prop_assert!(kp.public.verify(&message, &sig).is_ok());
    }

    /// Property: Une signature ne doit pas être valable pour un message différent
    #[test]
    fn prop_signature_tamper_detection(
        message1 in prop::collection::vec(any::<u8>(), 32..128),
        message2 in prop::collection::vec(any::<u8>(), 32..128)
    ) {
        prop_assume!(message1 != message2);
        
        let mut rng = thread_rng();
        let kp = KeyPair::generate(&mut rng);
        let sig = kp.secret.sign(&message1);
        
        prop_assert!(kp.public.verify(&message2, &sig).is_err());
    }

    /// Property: Le hash de Poseidon doit être déterministe
    #[test]
    fn prop_poseidon_deterministic(
        input in prop::collection::vec(any::<u8>(), 0..256)
    ) {
        let hash1 = PoseidonHash::hash(&input);
        let hash2 = PoseidonHash::hash(&input);
        
        prop_assert_eq!(hash1, hash2);
    }

    /// Property: Des entrées différentes doivent produire des hash différents (résistance à la collision)
    #[test]
    fn prop_poseidon_collision_resistance(
        input1 in prop::collection::vec(any::<u8>(), 32..128),
        input2 in prop::collection::vec(any::<u8>(), 32..128)
    ) {
        prop_assume!(input1 != input2);
        
        let hash1 = PoseidonHash::hash(&input1);
        let hash2 = PoseidonHash::hash(&input2);
        
        prop_assert_ne!(hash1, hash2);
    }

    /// Property: Un nullifier doit être unique par note
    #[test]
    fn prop_nullifier_uniqueness(
        note1 in prop::collection::vec(any::<u8>(), 64),
        note2 in prop::collection::vec(any::<u8>(), 64)
    ) {
        prop_assume!(note1 != note2);
        
        let mut rng = thread_rng();
        let kp = KeyPair::generate(&mut rng);
        
        let nullifier1 = Nullifier::from_note(&note1, &kp.secret);
        let nullifier2 = Nullifier::from_note(&note2, &kp.secret);
        
        prop_assert_ne!(nullifier1, nullifier2);
    }
}