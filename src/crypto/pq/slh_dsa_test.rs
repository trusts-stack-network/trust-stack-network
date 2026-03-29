// Importation des crates nécessaires
use super::*;
use fips205::{SLHDSA, SLHDSAPublicKey, SLHDSASecretKey};
use rand::rngs::OsRng;

// Tests avec vecteurs de test
#[cfg(test)]
mod tests {
    use super::*;

    // Test de génération de clés
    #[test]
    fn test_keygen() {
        let (secret_key, public_key) = keygen();
        assert_eq!(secret_key.as_bytes().len(), SECRET_KEY_SIZE);
        assert_eq!(public_key.as_bytes().len(), PUBLIC_KEY_SIZE);
    }

    // Test de signature et vérification
    #[test]
    fn test_sign_verify() {
        let (secret_key, public_key) = keygen();
        let message = b"Hello, World!";
        let signature = sign(&secret_key, message);
        assert_eq!(signature.len(), SIGNATURE_SIZE);
        assert!(verify(&public_key, message, &signature));
    }

    // Test de zeroisation de la clé secrète
    #[test]
    fn test_zeroize_secret_key() {
        let mut secret_key = SLHDSASecretKey::generate(&mut OsRng);
        let secret_key_bytes = secret_key.as_bytes().to_vec();
        zeroize_secret_key(&mut secret_key);
        assert_eq!(secret_key.as_bytes(), vec![0u8; SECRET_KEY_SIZE]);
        assert_ne!(secret_key_bytes, secret_key.as_bytes());
    }
}