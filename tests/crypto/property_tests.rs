use proptest::prelude::*;
use tsn_crypto::{
    keys::{KeyPair, PublicKey, PrivateKey},
    signature::{sign, verify_signature},
    commitment::Commitment,
    nullifier::Nullifier,
};

proptest! {
    /// Test que la vérification de signature est correcte
    #[test]
    fn test_signature_verification(
        msg in prop::collection::vec(any::<u8>(), 0..1024),
        key_seed in any::<[u8; 32]>()
    ) {
        let keypair = KeyPair::from_seed(&key_seed);
        let signature = sign(&msg, &keypair.private_key);
        
        // La signature devrait être valide
        prop_assert!(verify_signature(&signature, &msg, &keypair.public_key).is_ok());
        
        // Avec un message modifié, ça devrait échouer
        let mut tampered_msg = msg.clone();
        if !tampered_msg.is_empty() {
            tampered_msg[0] = tampered_msg[0].wrapping_add(1);
            prop_assert!(verify_signature(&signature, &tampered_msg, &keypair.public_key).is_err());
        }
    }
    
    /// Test que les commitments sont binding
    #[test]
    fn test_commitment_binding(
        value1 in any::<u64>(),
        value2 in any::<u64>(),
        blinding1 in any::<[u8; 32]>(),
        blinding2 in any::<[u8; 32]>()
    ) {
        let commitment1 = Commitment::commit(&value1.to_le_bytes(), &blinding1);
        let commitment2 = Commitment::commit(&value2.to_le_bytes(), &blinding2);
        
        if value1 != value2 || blinding1 != blinding2 {
            prop_assert_ne!(commitment1.to_bytes(), commitment2.to_bytes());
        }
    }
    
    /// Test que les nullifiers sont uniques
    #[test]
    fn test_nullifier_uniqueness(
        note1 in any::<[u8; 32]>(),
        note2 in any::<[u8; 32]>(),
        key_seed in any::<[u8; 32]>()
    ) {
        let keypair = KeyPair::from_seed(&key_seed);
        
        let nullifier1 = Nullifier::from_note(&note1, &keypair.private_key);
        let nullifier2 = Nullifier::from_note(&note2,