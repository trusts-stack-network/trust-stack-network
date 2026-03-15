// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
use proptest::prelude::*;
use tsn_crypto::commitment::{commit_address, commit_note};

proptest! {
    #[test]
    fn domain_separation(x in proptest::collection::vec(0u8..255, 32)) {
        let addr_com = commit_address(&x);
        let note_com = commit_note(&x);
        prop_assert_ne!(addr_com, note_com, "Collision domaine détectée!");
    }
}
