//! Opérations AES - Contient des vulnérabilités de nonce reuse et timing

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand::RngCore;

/// VULNÉRABILITÉ: Nonce statique/global (catastrophique pour AES-GCM)
static mut GLOBAL_NONCE: [u8; 12] = [0u8; 12];

pub struct AesGcmWrapper {
    cipher: Aes256Gcm,
}

impl AesGcmWrapper {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(key).unwrap(),
        }
    }

    /// VULNÉRABILITÉ: Nonce prévisible et incrémental
    pub fn encrypt_insecure(&self, plaintext: &[u8], counter: u64) -> Vec<u8> {
        let nonce_bytes = counter.to_be_bytes();
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&nonce_bytes);
        
        let nonce = Nonce::from_slice(&nonce);
        self.cipher.encrypt(nonce, plaintext).unwrap()
    }

    /// VULNÉRABILITÉ: Nonce global statique (REUSE!)
    pub fn encrypt_static_nonce(&self, plaintext: &[u8]) -> Vec<u8> {
        unsafe {
            let nonce = Nonce::from_slice(&GLOBAL_NONCE);
            let ciphertext = self.cipher.encrypt(nonce, plaintext).unwrap();
            // Incrémentation prévisible du nonce global
            GLOBAL_NONCE[11] += 1;
            ciphertext
        }
    }

    /// SÉCURISÉ: Nonce aléatoire cryptographique
    pub fn encrypt_secure(&self, plaintext: &[u8]) -> (Vec<u8>, [u8; 12]) {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self.cipher.encrypt(nonce, plaintext).unwrap();
        (ciphertext, nonce_bytes)
    }

    /// VULNÉRABILITÉ: Pas de vérification de taille de ciphertext
    pub fn decrypt_insecure(&self, ciphertext: &[u8], nonce: &[u8]) -> Option<Vec<u8>> {
        if nonce.len() != 12 {
            return None;
        }
        let nonce = Nonce::from_slice(nonce);
        // VULNÉRABILITÉ: unwrap() peut paniquer sur données malformées
        self.cipher.decrypt(nonce, ciphertext).ok()
    }
}

/// Padding oracle vulnerability simulation
pub struct PaddingOracle;

impl PaddingOracle {
    /// VULNÉRABILITÉ: Différence de timing selon validité du padding
    pub fn decrypt_with_padding_check(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() % 16 != 0 {
            return Err("Invalid length");
        }
        
        // Simulation de déchiffrement
        std::thread::sleep(std::time::Duration::from_micros(100));
        
        let last_byte = ciphertext.last().unwrap();
        let pad_len = *last_byte as usize;
        
        // VULNÉRABILITÉ: Vérification de padding avec short-circuit
        if pad_len == 0 || pad_len > 16 {
            std::thread::sleep(std::time::Duration::from_micros(50));
            return Err("Invalid padding");
        }
        
        for i in 0..pad_len {
            if ciphertext[ciphertext.len() - 1 - i] != pad_len as u8 {
                std::thread::sleep(std::time::Duration::from_micros(30));
                return Err("Invalid padding