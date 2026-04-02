// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
//! Property-based tests sur les signatures post-quantiques
use proptest::prelude::*;
use tsn_crypto::keys::{KeyPair, PublicKey};
use tsn_crypto::signature::sign;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000))]

    #[test]
    fn sig_verif(kp in any::<KeyPair>(), msg in prop::collection::vec(any::<u8>(), 0..1_000)) {
        let sig = sign(&kp.secret, &msg);
        prop_assert!(sig.verify(&kp.public, &msg));
    }

    #[test]
    fn sig_tamper(kp in any::<KeyPair>(), msg in prop::collection::vec(any::<u8>(), 0..500)) {
        let mut sig = sign(&kp.secret, &msg);
        // altère un octet
        sig.0[7] = sig.0[7].wrapping_add(1);
        prop_assert!(!sig.verify(&kp.public, &msg));
    }
}
