//! ML-DSA-65 (FIPS 204) — LEGACY
//!
//! Conservé uniquement pour la migration depuis l'ancienne version de TSN.
//! Ne pas utiliser pour les nouvelles clés.

use crate::crypto::pq::Error;
use fips204::ml_dsa_65 as ml_impl;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone)]
pub struct SecretKey(ml_impl::SecretKey);

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        unsafe {
            let ptr = &mut self.0 as *mut _ as *mut u8;
            let len = std::mem::size_of_val(&self.0);
            std::ptr::write_bytes(ptr, 0, len);
        }
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKey {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(ml_impl::PublicKey);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(ml_impl::Signature);

pub fn keygen_from_seed(seed: &[u8; 32]) -> Result<(SecretKey, PublicKey), Error> {
    let sk = ml_impl::SecretKey::from_seed(seed);
    let pk = ml_impl::PublicKey::from(&sk);
    Ok((SecretKey(sk), PublicKey(pk)))
}

pub fn sign(sk: &SecretKey, msg: &[u8]) -> Signature {
    Signature(ml_impl::sign(&sk.0, msg))
}

pub fn verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    ml_impl::verify(&pk.0, msg, &sig.0).is_ok()
}