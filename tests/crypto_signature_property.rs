// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
use proptest::prelude::*;
use tsn_crypto::signature::{SignatureScheme, MLDSASignature};
use tsn_crypto::keys::{KeyPair, PublicKey};
use rand::rngs::OsRng;

proptest! {
    #[test]
    fn prop_signature_verification_deterministic(
        msg in prop::collection::vec(0u8..255, 0..1024),
        tamper_byte in 0usize..32
    ) {
        let keypair = KeyPair::generate(&mut OsRng);
        let sig = MLDSASignature::sign(&keypair.secret, &msg);
        
        // Signature valide doit vérifier
        prop_assert!(sig.verify(&keypair.public, &msg).is_ok());
        
        // Message tampered doit échouer
        let mut tampered = msg.clone();
        if !tampered.is_empty() {
            tampered[tamper_byte % tampered.len()] ^= 1;
            prop_assert!(sig.verify(&keypair.public, &tampered).is_err());
        }
    }

    #[test]
    fn prop_signature_malleability(
        msg in prop::collection::vec(0u8..255, 32..128)
    ) {
        let keypair = KeyPair::generate(&mut OsRng);
        let sig = MLDSASignature::sign(&keypair.secret, &msg);
        
        // Vérifier non-malleabilité
        let mut sig_bytes = sig.to_bytes();
        let last_bit = sig_bytes.len() - 1;
        sig_bytes[last_bit] ^= 0x80; // Flip bit
        
        let modified_sig = MLDSASignature::from_bytes(&sig_bytes);
        prop_assert!(modified_sig.is_err() || modified_sig.unwrap().verify(&keypair.public, &msg).is_err());
    }
}
