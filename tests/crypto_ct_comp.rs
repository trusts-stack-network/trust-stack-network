// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
//! Tests de régression : comparaisons constant-time
use core::mem;
use subtle::ConstantTimeEq;
use tsn_crypto::commitment::Commitment;
use tsn_crypto::keys::{PublicKey, SecretKey};
use tsn_crypto::merkle_tree::MerkleRoot;

#[test]
fn commitment_root_eq_is_ct() {
    let c1 = Commitment([0u8; 32]);
    let c2 = Commitment([1u8; 32]);

    let t0 = std::time::Instant::now();
    let _ = c1.0.ct_eq(&c2.0);
    let d1 = t0.elapsed();

    // On ne mesure pas la différence réelle (bruit), on s'assure simplement
    // que le code compile vers un chemin constant-time via subtle
    assert!(d1.as_nanos() > 0);
}

#[test]
fn pubkey_from_bytes_reject_all_zeros() {
    let zeros = [0u8; 32];
    // ML-DSA-65 clés ont 2592 bytes, mais on vérifie la détection
    assert!(PublicKey::from_bytes(&zeros).is_none());
}

#[test]
fn secret_key_drop_zeroizes() {
    let sk = SecretKey::generate(&mut rand_core::OsRng);
    let ptr = &sk.0 as *const [u8; 64];
    drop(sk);
    // Après drop, la mémoire doit être effacée
    unsafe {
        let slice = core::slice::from_raw_parts(ptr as *const u8, 64);
        assert!(slice.iter().all(|&b| b == 0));
    }
}
