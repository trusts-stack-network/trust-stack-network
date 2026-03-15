use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce, Error as AesError
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AeadError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid key length")]
    InvalidKeyLength,
}

pub struct AeadCipher {
    cipher: Aes256Gcm,
}

impl AeadCipher {
    pub fn new(key: &[u8]) -> Result<Self, AeadError> {
        if key.len() != 32 {
            return Err(AeadError::InvalidKeyLength);
        }
        
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        
        Ok(Self { cipher })
    }
    
    pub fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, AeadError> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        self.cipher
            .encrypt(&nonce, plaintext)
            .map(|ciphertext| {
                let mut result = nonce.to_vec();
                result.extend_from_slice(&ciphertext);
                result
            })
            .map_err(|e| AeadError::EncryptionFailed(e.to_string()))
    }
    
    pub fn decrypt(&self, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, AeadError> {
        if ciphertext.len() < 12 {
            return Err(AeadError::DecryptionFailed("Ciphertext too short".to_string()));
        }
        
        let (nonce_bytes, encrypted) = ciphertext.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        self.cipher
            .decrypt(nonce, encrypted)
            .map_err(|e| AeadError::DecryptionFailed(e.to_string()))
    }
}