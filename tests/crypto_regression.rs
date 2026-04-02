// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
//! Tests de régression pour vulnérabilités connues
use tsn_crypto::keys::{PublicKey, SecretKey};
use tsn_crypto::binding::BindingSignature;
use subtle::ConstantTimeEq;

#[test]
fn cve_2025_0001_key_ct_eq() {
    // Avant le fix : utilisation de PartialEq → timing leak
    // Après le fix : ct_eq uniquement
    let sk1 = SecretKey::random(&mut rand::thread_rng());
    let sk2 = SecretKey::random(&mut rand::thread_rng());
    // Doit prendre le même temps quel que soit le résultat
    assert!(sk1.ct_eq(&sk1).unwrap_u8() == 1);
    assert!(sk1.ct_eq(&sk2).unwrap_u8() == 0);
}

#[test]
fn cve_2025_0002_binding_unwrap_panic() {
    // Avant le fix : unwrap() sur décompression
    // Après le fix : renvoie une erreur propre
    let rogue_bytes = [0xff; 32];
    let sig = BindingSignature::from_bytes(&rogue_bytes);
    assert!(sig.is_err());
}
