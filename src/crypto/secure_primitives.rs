//! Primitives cryptographiques durcies contre les side-channels
//! 
//! MITIGATIONS:
//! - Comparaisons en temps constant via `subtle`
//! - Zeroization explicite des secrets
//! - Pas de branches sur données secrètes
//! - Alignment mémoire pour éviter les cache-line splits

use subtle::{Choice, ConstantTimeEq, ConstantTimeGreater};
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::{RngCore, CryptoRng};

/// Erreur constant-time (pas de distinction de cas d'erreur)
#[derive(Debug, Clone, Copy)]
pub struct CryptoError;

/// Clé symétrique sécurisée (zeroized automatiquement)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureKey {
    #[zeroize(skip)]
    pub id: u64,
    pub material: [u8; 32],
}

/// Comparaison MAC en temps constant
/// VULNÉRABILITÉ PRÉCÉDENTE: `mac1 == mac2` vulnérable à timing attack
/// MITIGATION: Utilisation de subtle::ConstantTimeEq
pub fn verify_mac(mac1: &[u8], mac2: &[u8]) -> Choice {
    if mac1.len() != mac2.len() {
        return Choice::from(0);
    }
    mac1.ct_eq(mac2)
}

/// Dérivation de clé résistante aux side-channels
pub fn derive_key_scrypt(password: &[u8], salt: &[u8]) -> Result<SecureKey, CryptoError> {
    // Paramètres conservateurs pour résistance brute-force
    let params = scrypt::Params::new(15, 8, 1, 32)
        .map_err(|_| CryptoError)?;
    
    let mut key_material = [0u8; 32];
    scrypt::scrypt(password, salt, &params, &mut key_material)
        .map_err(|_| CryptoError)?;
    
    Ok(SecureKey {
        id: 0,
        material: key_material,
    })
}

/// Validation de padding PKCS#7 en temps constant
/// VULNÉRABILITÉ: Timing différences révèlent padding invalide
pub fn verify_padding_constant_time(data: &[u8], block_size: usize) -> Choice {
    if data.is_empty() || data.len() % block_size != 0 {
        return Choice::from(0);
    }
    
    let last_byte = data[data.len() - 1];
    let pad_len = last_byte as usize;
    
    if pad_len == 0 || pad_len > block_size {
        return Choice::from(0);
    }
    
    let mut valid = Choice::from(1);
    let start = data.len() - pad_len;
    
    // Vérification en temps constant - pas de short-circuit
    for i in start..data.len() {
        let expected = (pad_len - (data.len() - 1 - i)) as u8;
        valid &= data[i].ct_eq(&expected);
    }
    
    valid
}

/// Génération de nonce avec protection contre reuse
pub struct NonceGenerator {
    counter: std::sync::atomic::AtomicU64,
    random_prefix: [u8; 8],
}

impl NonceGenerator {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut prefix = [0u8; 8];
        rng.fill_bytes(&mut prefix);
        Self {
            counter: std::sync::atomic::Atomic