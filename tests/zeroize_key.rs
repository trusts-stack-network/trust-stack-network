// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
//! Vérifie la zeroisation des clés privées
use tsn_crypto::keys::MlDsaSecretKey;
use zeroize::Zeroize;
use rand::rngs::OsRng;

#[test]
fn secret_key_zeroized_on_drop() {
    let mut sk = MlDsaSecretKey::generate(&mut OsRng).0;
    let ptr = sk.as_ptr();
    drop(sk);
    // Après drop, la mémoire doit être à zero
    unsafe {
        let slice = std::slice::from_raw_parts(ptr, MlDsaSecretKey::SIZE);
        assert!(slice.iter().all(|&b| b == 0));
    }
}
