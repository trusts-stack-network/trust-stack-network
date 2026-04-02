// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
use proptest::prelude::*;
use tsn_crypto::{
    keys::{KeyPair, PublicKey},
    signature::{SignatureScheme, verify_signature},
    commitment::{Commitment, NoteCommitment},
    nullifier::Nullifier,
    note::Note,
    address::Address,
};
use rand_core::OsRng;
use std::time::Instant;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10000))]

    #[test]
    fn signature_timing_invariant(
        msg1: Vec<u8>,
        msg2: Vec<u8>,
        key_seed: [u8; 32]
    ) {
        let keypair = KeyPair::from_seed(&key_seed);
        
        let sig1 = SignatureScheme::sign(&keypair.secret, &msg1);
        let sig2 = SignatureScheme::sign(&keypair.secret, &msg2);
        
        // Timing should be independent of message content
        let start = Instant::now();
        let _ = verify_signature(&keypair.public, &msg1, &sig1);
        let duration1 = start.elapsed();
        
        let start = Instant::now();
        let _ = verify_signature(&keypair.public, &msg2, &sig2);
        let duration2 = start.elapsed();
        
        // Difference should be within 10% tolerance
        let max_diff = if duration1 > duration2 {
            duration1 / 10
        } else {
            duration2 / 10
        };
        
        prop_assert!((duration1.as_nanos() as i128 - duration2.as_nanos() as i128).abs() 
                    < max_diff.as_nanos() as i128);
    }

    #[test]
    fn commitment_uniqueness(
        value1: u64,
        value2: u64,
        blinding1: [u8; 32],
        blinding2: [u8; 32]
    ) {
        prop_assume!(value1 != value2 || blinding1 != blinding2);
        
        let note1 = Note::new(value1, Address::random(), blinding1);
        let note2 = Note::new(value2, Address::random(), blinding2);
        
        let comm1 = NoteCommitment::commit(&note1);
        let comm2 = NoteCommitment::commit(&note2);
        
        prop_assert_ne!(comm1.to_bytes(), comm2.to_bytes());
    }

    #[test]
    fn nullifier_determinism(
        note_value: u64,
        note_blinding: [u8; 32],
        nullifier_key: [u8; 32]
    ) {
        let note = Note::new(note_value, Address::random(), note_blinding);
        let nullifier1 = Nullifier::derive(&note, &nullifier_key);
        let nullifier2 = Nullifier::derive(&note, &nullifier_key);
        
        prop_assert_eq!(nullifier1.to_bytes(), nullifier2.to_bytes());
    }
}
