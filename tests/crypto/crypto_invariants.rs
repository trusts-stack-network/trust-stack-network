use proptest::prelude::*;
use tsn_crypto::keys::{PublicKey, SecretKey};
use tsn_crypto::signature::Signature;
use tsn_crypto::commitment::Commitment;
use tsn_crypto::nullifier::Nullifier;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

proptest! {
    #[test]
    fn prop_signature_verification(
        message in prop::collection::vec(any::<u8>(), 0..1024),
        seed in any::<u64>()
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let secret = SecretKey::generate(&mut rng);
        let public = secret.public_key();
        
        let signature = secret.sign(&message);
        
        // La signature doit vérifier avec la clé publique correspondante
        prop_assert!(signature.verify(&public, &message).is_ok());
        
        // Ne doit pas vérifier avec une autre clé
        let other_secret = SecretKey::generate(&mut rng);
        let other_public = other_secret.public_key();
        prop_assert!(signature.verify(&other_public, &message).is_err());
        
        // Ne doit pas vérifier avec un