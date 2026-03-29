//! Exemples de code vulnérable pour démonstration des tests de régression
//! NE PAS UTILISER EN PRODUCTION - Ces implémentations sont intentionnellement faibles

/// Comparaison de MAC vulnérable aux attaques temporelles
pub fn insecure_compare_mac(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // VULNÉRABILITÉ: early return sur différence
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false; // Timing leak ici
        }
    }
    true
}

/// Chiffrement avec nonce réutilisé (catastrophique pour AES-GCM/ChaCha20)
pub struct InsecureNonceGenerator {
    counter: u64,
}

impl InsecureNonceGenerator {
    pub fn new() -> Self {
        Self { counter: 0 }
    }
    
    pub fn next_nonce(&mut self) -> [u8; 12] {
        // VULNÉRABILITÉ: nonce prévisible et potentiellement réutilisé après redémarrage
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&self.counter.to_be_bytes());
        self.counter += 1;
        nonce
    }
}

/// Décryptage avec distinction d'erreurs (Padding Oracle)
#[derive(Debug)]
pub enum InsecureDecryptError {
    PaddingError,
    IntegrityError,
}

pub fn insecure_decrypt_with_padding(
    ciphertext: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, InsecureDecryptError> {
    // Simulation de vérification de padding distincte de l'intégrité
    if ciphertext.len() % 16 != 0 {
        return Err(InsecureDecryptError::PaddingError);
    }
    
    // ... décryptage ...
    
    // VULNÉRABILITÉ: erreurs distinctes permettent padding oracle attack
    if !verify_padding(ciphertext) {
        return Err(InsecureDecryptError::PaddingError);
    }
    
    if !verify_mac(ciphertext) {
        return Err(InsecureDecryptError::IntegrityError);
    }
    
    Ok(vec![]) // plaintext
}

fn verify_padding(_data: &[u8]) -> bool { true }
fn verify_mac(_data: &[u8]) -> bool { true }