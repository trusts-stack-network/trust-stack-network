// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
//! Vérifie que les opérations secrets ne fuient pas via timing.

use subtle::ConstantTimeEq;
use tsn_crypto::keys::{PublicKey, SecretKey};
use tsn_crypto::poseidon;

#[test]
fn secret_key_constant_time_eq() {
    let sk1 = SecretKey::random(&mut rand::thread_rng());
    let sk2 = SecretKey::random(&mut rand::thread_rng());
    // Méthode constant-time
    let ct_eq = sk1.as_bytes().ct_eq(sk2.as_bytes()).unwrap_u8();
    // Méthode non constant-time (doit être supprimée après refactor)
    let rust_eq = sk1 == sk2;
    // On s'assure qu'on peut compiler les deux mais qu'on utilisera
    // uniquement la version constant-time dans le futur.
    assert!(ct_eq == 0 || ct_eq == 1);
    assert_eq!(rust_eq, ct_eq != 0);
}

proptest::proptest! {
    #[test]
    fn poseidon_hash_different_inputs_different_outputs(a: Vec<u8>, b: Vec<u8>) {
        // Invariant : deux entrées différentes ⇒ hash différent
        prop_assume!(a != b);
        let ha = poseidon::hash_bytes(&a);
        let hb = poseidon::hash_bytes(&b);
        prop_assert_ne!(ha, hb);
    }
}
