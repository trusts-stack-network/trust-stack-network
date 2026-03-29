//! Code vulnérable pour démonstration des tests de régression
//! NE JAMAIS UTILISER EN PRODUCTION

use pbkdf2;
use sha2;

/// Erreur de déchiffrement (démonstration vulnérable)
#[derive(Debug)]
pub enum DecryptionError {
    InvalidLength,
    InvalidPadding,
    InvalidPaddingByte(usize),
    DecryptionFailed,
}

/// Déchiffrement AES-ECB vulnérable (démonstration uniquement)
fn aes_ecb_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DecryptionError> {
    use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
    use aes::Aes128;

    if key.len() != 16 || ciphertext.len() % 16 != 0 {
        return Err(DecryptionError::InvalidLength);
    }

    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut result = Vec::with_capacity(ciphertext.len());

    for chunk in ciphertext.chunks(16) {
        let mut block = *GenericArray::from_slice(chunk);
        cipher.decrypt_block(&mut block);
        result.extend_from_slice(&block);
    }

    Ok(result)
}

pub struct VulnerableCrypto;

impl VulnerableCrypto {
    /// Vulnérabilité: Timing attack sur comparaison de MAC
    pub fn verify_mac_vulnerable(calculated: &[u8], expected: &[u8]) -> bool {
        if calculated.len() != expected.len() {
            return false;
        }
        // Timing attack: retourne early sur premier byte différent
        for i in 0..calculated.len() {
            if calculated[i] != expected[i] {
                return false;
            }
        }
        true
    }

    /// Vulnérabilité: Nonce statique (AES-GCM catastrophic failure)
    pub fn encrypt_aes_gcm_static_nonce(
        key: &[u8; 32],
        plaintext: &[u8],
    ) -> Vec<u8> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        
        // CATASTROPHIQUE: Nonce statique
        let static_nonce = Nonce::from_slice(b"fixed123"); // 96 bits
        
        let cipher = Aes256Gcm::new(key.into());
        cipher.encrypt(static_nonce, plaintext).unwrap()
    }

    /// Vulnérabilité: Padding oracle (différenciation erreurs)
    pub fn decrypt_pkcs7_vulnerable(
        key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        if ciphertext.len() % 16 != 0 {
            return Err(DecryptionError::InvalidLength);
        }
        
        let decrypted = aes_ecb_decrypt(key, ciphertext)?;
        
        // Padding oracle: validation non constant-time + erreur spécifique
        let pad_len = decrypted[decrypted.len() - 1] as usize;
        if pad_len == 0 || pad_len > 16 {
            return Err(DecryptionError::InvalidPadding);
        }
        
        // Check padding - non constant time
        for i in 0..pad_len {
            if decrypted[decrypted.len() - 1 - i] != pad_len as u8 {
                return Err(DecryptionError::InvalidPaddingByte(i));
            }
        }
        
        Ok(decrypted[..decrypted.len() - pad_len].to_vec())
    }

    /// Vulnérabilité: Secret non zeroized
    pub fn derive_key_weak(password: &str, salt: &[u8]) -> Vec<u8> {
        let mut key = [0u8; 32];
        // Mauvais: PBKDF2 avec itérations faibles + pas de zeroize
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
            password.as_bytes(),
            salt,
            1000, // Trop faible (2024)
            &mut key,
        );
        key.to_vec()
    }
}