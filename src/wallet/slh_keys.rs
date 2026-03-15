//! Gestion des clés SLH-DSA dans le wallet
//! Compatible avec la dérivation hiérarchique (non-BIP32) pour clés post-quantiques

use crate::crypto::pq::slh_dsa::{self, PublicKey, SecretKey, Signature};
use rand_core::OsRng;
use zeroize::ZeroizeOnDrop;

/// Portefeuille SLH-DSA unique (HD simplifié : 1 clé par compte)
#[derive(ZeroizeOnDrop)]
pub struct SlhWallet {
    sk: SecretKey,
    pk: PublicKey,
}

impl SlhWallet {
    /// Crée un nouveau wallet
    pub fn new() -> Self {
        let (sk, pk) = sl