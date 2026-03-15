// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
//! Vérifie l'absence de panic sur index malformé
use tsn_crypto::nullifier::Nullifier;
use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_nullifier_no_panic(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
        let n = Nullifier::from_bytes(&bytes);
        // L'appel suivant ne doit jamais panic
        let _ = n.to_hex();
    }
}
