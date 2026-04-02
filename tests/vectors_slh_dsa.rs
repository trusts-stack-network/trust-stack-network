// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
//! Vecteurs de test officiels NIST ACVP pour SLH-DSA-SHA2-128s
//! (fichier .json externe dans `tests/fixtures/`)
//! Lancer avec : cargo test --test vectors_slh_dsa

use slh_dsa::{keygen_from_seed, sign_msg, verify};
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct Vector {
    seed: String,
    msg: String,
    pk: String,
    sig: String,
}

#[test]
fn nist_vectors() {
    let data = fs::read_to_string("tests/fixtures/slh_dsa_128s.json")
        .expect("missing test vectors");
    let vecs: Vec<Vector> = serde_json::from_str(&data).unwrap();

    for v in vecs {
        let seed = hex::decode(&v.seed).unwrap().try_into().unwrap();
        let msg = hex::decode(&v.msg).unwrap();
        let pk_expected = hex::decode(&v.pk).unwrap().try_into().unwrap();
        let sig_expected = hex::decode(&v.sig).unwrap().try_into().unwrap();

        let kp = keygen_from_seed(&seed);
        assert_eq!(kp.pk.as_bytes(), &pk_expected);
        let sig = sign_msg(&kp.sk, &msg);
        assert_eq!(sig.as_bytes(), &sig_expected);
        assert!(verify(&kp.pk, &msg, &sig).is_ok());
    }
}
