// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
use tsn_crypto::keys::{PublicKey, SecretKey};
use tsn_crypto::nullifier;

proptest::proptest! {
    #[test]
    fn nullifier_unique_per_note(sk: [u8; 32], rho1: [u8; 32], rho2: [u8; 32]) {
        let sk = SecretKey::from_bytes(&sk).unwrap();
        let pk = PublicKey::from(&sk);
        prop_assume!(rho1 != rho2);
        let nf1 = nullifier::derive(&pk, &rho1);
        let nf2 = nullifier::derive(&pk, &rho2);
        prop_assert_ne!(nf1, nf2);
    }
}
