//! Implémentation sécurisée de référence
//! Utilise subtle pour constant-time operations et zeroize pour la mémoire

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::{RngCore, CryptoRng};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce, Key,
};

/// Clé secrète qui s'auto-efface à la destruction
#[derive(Clone)]
pub struct SecretKey {
    material: Vec<u8>,
}

impl SecretKey {
    pub fn random<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        let mut material = vec![0u8; 32];
        rng.fill_bytes(&mut material);
        Self { material }
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        &self.material
    }
    
    pub fn compare_mac(&self, other: &[u8]) -> bool {
        // Constant-time comparison pour prévenir timing attacks
        self.material.as_slice().ct_eq(other).into()
    }
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.material.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKey {}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Générateur de nonce sécurisé avec compteur et randomisation
pub struct SecureNonceGenerator {
    rng: rand::rngs::OsRng,
}

impl SecureNonceGenerator {
    pub fn new() -> Self {
        Self { rng: OsRng }
    }
    
    pub fn generate(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        self.rng.fill_bytes(&mut nonce);
        nonce
    }
}

/// Chiffrement AEAD avec gestion sûre des nonces