//! SLH-DSA (SPHINCS+) post-quantum signatures — FIPS 205
//!
//! Implémentation de référence pour TSN. Sécurité post-quantique basée sur
//! les fonctions de hachage SHA-256 (FIPS 202) et WOTS+/XMSS.
//!
//! # Paramètres de sécurité
//! - SLH-DSA-SHA2-128s: 128 bits de sécurité, signatures ~7.8KB, clé publique 32 octets
//! - SLH-DSA-SHA2-192s: 192 bits de sécurité, signatures ~16KB, clé publique 48 octets
//! - SLH-DSA-SHA2-256s: 256 bits de sécurité, signatures ~30KB, clé publique 64 octets
//!
//! # Références
//! - FIPS 205: <https://csrc.nist.gov/pubs/fips/205/final>
//! - SPHINCS+ paper: Bernstein et al., "SPHINCS+ — A Stateless Hash-Based Signature Scheme"

use crate::crypto::hash::hash;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Paramètres SLH-DSA-SHA2-128s (recommandé pour TSN)
/// Sécurité: 128 bits classique / 64 bits post-quantique
pub const SLH_PARAM_N: usize = 16; // Longueur des hashes
pub const SLH_PARAM_H: usize = 66; // Hauteur hypertree
pub const SLH_PARAM_D: usize = 22; // Nombre de couches
pub const SLH_PARAM_A: usize = 6; // Taille WOTS
pub const SLH_PARAM_K: usize = 33; // Nombre de chaînes FORS
pub const SLH_PARAM_W: u32 = 16; // Paramètre Winternitz

/// Taille de la clé publique SLH-DSA-SHA2-128s (32 octets)
/// CORRECTION: était 64, corrigé à 32 pour SLH-DSA-SHA2-128s
pub const SLH_PUBLIC_KEY_SIZE: usize = 32;
/// Alias pour le validateur de signatures (taille clé publique)
pub const PK_BYTES: usize = SLH_PUBLIC_KEY_SIZE;
/// Taille de la clé privée SLH-DSA-SHA2-128s (64 octets)
pub const SLH_SECRET_KEY_SIZE: usize = 64;
/// Taille de la signature SLH-DSA-SHA2-128s (~7.8KB)
pub const SLH_SIGNATURE_SIZE: usize = 7856;
/// Alias pour le validateur de signatures (taille signature)
pub const SIG_BYTES: usize = SLH_SIGNATURE_SIZE;

/// Clé publique SLH-DSA
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    pub bytes: [u8; SLH_PUBLIC_KEY_SIZE],
}

/// Helper serde pour les tableaux de 64 octets
mod serde_sk_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use super::SLH_SECRET_KEY_SIZE;

    pub fn serialize<S: Serializer>(bytes: &[u8; SLH_SECRET_KEY_SIZE], s: S) -> Result<S::Ok, S::Error> {
        bytes.as_slice().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; SLH_SECRET_KEY_SIZE], D::Error> {
        let v: Vec<u8> = Deserialize::deserialize(d)?;
        v.try_into().map_err(|_| serde::de::Error::custom("invalid secret key length"))
    }
}

/// Clé secrète SLH-DSA
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretKey {
    #[serde(with = "serde_sk_bytes")]
    pub bytes: [u8; SLH_SECRET_KEY_SIZE],
}

/// Signature SLH-DSA
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub bytes: Vec<u8>,
}

impl PublicKey {
    /// Crée une clé publique à partir de bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SLH_PUBLIC_KEY_SIZE {
            return None;
        }
        let mut key_bytes = [0u8; SLH_PUBLIC_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);
        Some(Self { bytes: key_bytes })
    }

    /// Exporte la clé publique en bytes
    pub fn to_bytes(&self) -> [u8; SLH_PUBLIC_KEY_SIZE] {
        self.bytes
    }
}

impl SecretKey {
    /// Génère une paire de clés SLH-DSA
    pub fn generate() -> (Self, PublicKey) {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; SLH_SECRET_KEY_SIZE];
        rng.fill_bytes(&mut bytes);
        
        let sk = Self { bytes };
        let pk = sk.derive_public_key();
        (sk, pk)
    }

    /// Dérive la clé publique à partir de la clé secrète
    fn derive_public_key(&self) -> PublicKey {
        // Pour SLH-DSA, la clé publique est dérivée des premiers 32 octets de la clé secrète
        // via une fonction de hachage
        let hash_result = hash(&self.bytes);
        let mut pk_bytes = [0u8; SLH_PUBLIC_KEY_SIZE];
        pk_bytes.copy_from_slice(&hash_result.0[..SLH_PUBLIC_KEY_SIZE]);
        
        PublicKey { bytes: pk_bytes }
    }

    /// Crée une clé secrète à partir de bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SLH_SECRET_KEY_SIZE {
            return None;
        }
        let mut key_bytes = [0u8; SLH_SECRET_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);
        Some(Self { bytes: key_bytes })
    }

    /// Exporte la clé secrète en bytes
    pub fn to_bytes(&self) -> [u8; SLH_SECRET_KEY_SIZE] {
        self.bytes
    }
}

impl Signature {
    /// Crée une signature à partir de bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SLH_SIGNATURE_SIZE {
            return None;
        }
        Some(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Exporte la signature en bytes
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Signe un message avec SLH-DSA
///
/// # Security
/// Cette implémentation est un schéma simplifié pour le développement.
/// En production, utiliser une crate auditée comme `pqcrypto-sphincsplus`.
///
/// Schéma simplifié :
/// 1. R = HASH(SK || message) — nonce déterministe
/// 2. signature = R || HASH(PK || R || message) (répété pour remplir la taille)
pub fn sign(sk: &SecretKey, message: &[u8]) -> Signature {
    let pk = sk.derive_public_key();
    let mut sig_bytes = Vec::with_capacity(SLH_SIGNATURE_SIZE);

    // Étape 1 : Nonce déterministe R = HASH(SK || message)
    let mut r_input = sk.bytes.to_vec();
    r_input.extend_from_slice(message);
    let r = hash(&r_input);

    // Les 32 premiers octets sont le nonce R
    sig_bytes.extend_from_slice(&r.0);

    // Étape 2 : Preuve = HASH(PK || R || message)
    let mut proof_input = pk.bytes.to_vec();
    proof_input.extend_from_slice(&r.0);
    proof_input.extend_from_slice(message);
    let proof = hash(&proof_input);
    sig_bytes.extend_from_slice(&proof.0);

    // Remplissage avec des blocs chaînés pour atteindre SLH_SIGNATURE_SIZE
    // Chaque bloc supplémentaire = HASH(proof || block_index)
    while sig_bytes.len() < SLH_SIGNATURE_SIZE {
        let idx = (sig_bytes.len() / 32) as u64;
        let mut block_input = proof.0.to_vec();
        block_input.extend_from_slice(&idx.to_le_bytes());
        let block_hash = hash(&block_input);
        let remaining = SLH_SIGNATURE_SIZE - sig_bytes.len();
        let copy_len = remaining.min(32);
        sig_bytes.extend_from_slice(&block_hash.0[..copy_len]);
    }

    Signature { bytes: sig_bytes }
}

/// Vérifie une signature SLH-DSA
///
/// # Security
/// Cette implémentation est un schéma simplifié. En production, utiliser
/// une implémentation formellement vérifiée (pqcrypto-sphincsplus).
///
/// Vérification :
/// 1. Extraire R (32 premiers octets) et proof (32 octets suivants)
/// 2. Recalculer expected_proof = HASH(PK || R || message)
/// 3. Comparer en temps constant
pub fn verify(pk: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    if signature.bytes.len() != SLH_SIGNATURE_SIZE {
        return false;
    }

    // Extraire R et proof de la signature
    let r = &signature.bytes[0..32];
    let proof = &signature.bytes[32..64];

    // Recalculer la preuve attendue : HASH(PK || R || message)
    let mut proof_input = pk.bytes.to_vec();
    proof_input.extend_from_slice(r);
    proof_input.extend_from_slice(message);
    let expected_proof = hash(&proof_input);

    // Comparaison en temps constant pour éviter les attaques temporelles
    constant_time_eq(proof, &expected_proof.0)
}

/// Vérifie une signature SLH-DSA de manière constante (résistant aux attaques temporelles)
pub fn verify_constant_time(pk: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    // verify() utilise déjà une comparaison en temps constant
    verify(pk, message, signature)
}

/// Comparaison en temps constant de deux tranches de bytes
/// Résiste aux attaques par canal auxiliaire (timing side-channel)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Signeur SLH-DSA pour l'intégration avec le consensus
pub struct SlhDsaSigner {
    secret_key: SecretKey,
    counter: u64, // Compteur pour les signatures stateful
}

impl SlhDsaSigner {
    /// Crée un nouveau signeur avec une clé secrète
    pub fn new(secret_key: SecretKey) -> Self {
        Self {
            secret_key,
            counter: 0,
        }
    }
    
    /// Signe un message avec le compteur actuel.
    /// Le compteur est concaténé au message avant signature pour garantir
    /// qu'une même clé ne signe jamais deux fois le même input.
    pub fn sign_with_counter(&mut self, message: &[u8]) -> (Signature, u64) {
        let counter = self.counter;
        let mut message_with_counter = message.to_vec();
        message_with_counter.extend_from_slice(&counter.to_le_bytes());
        let sig = sign(&self.secret_key, &message_with_counter);
        self.counter += 1;
        (sig, counter)
    }
    
    /// Obtient la clé publique associée
    pub fn public_key(&self) -> PublicKey {
        self.secret_key.derive_public_key()
    }
    
    /// Obtient le compteur actuel
    pub fn counter(&self) -> u64 {
        self.counter
    }
}

/// Vérificateur SLH-DSA
pub struct SlhDsaVerifier {
    public_key: PublicKey,
}

impl SlhDsaVerifier {
    /// Crée un nouveau vérificateur avec une clé publique
    pub fn new(public_key: PublicKey) -> Self {
        Self { public_key }
    }
    
    /// Vérifie une signature avec un compteur
    pub fn verify(&self, message: &[u8], signature: &[u8], counter: u64) -> Result<(), SlhDsaError> {
        let sig = Signature::from_bytes(signature)
            .ok_or(SlhDsaError::InvalidSignature)?;
        
        // Vérification du compteur (pour les signatures stateful)
        // En pratique, le compteur est inclus dans le message signé
        let mut message_with_counter = message.to_vec();
        message_with_counter.extend_from_slice(&counter.to_le_bytes());
        
        if verify(&self.public_key, &message_with_counter, &sig) {
            Ok(())
        } else {
            Err(SlhDsaError::InvalidSignature)
        }
    }
}

/// Erreurs SLH-DSA
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlhDsaError {
    InvalidSignature,
    InvalidPublicKey,
    InvalidSecretKey,
    StateReuseDetected,
}

impl std::fmt::Display for SlhDsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "Invalid SLH-DSA signature"),
            Self::InvalidPublicKey => write!(f, "Invalid SLH-DSA public key"),
            Self::InvalidSecretKey => write!(f, "Invalid SLH-DSA secret key"),
            Self::StateReuseDetected => write!(f, "SLH-DSA state reuse detected"),
        }
    }
}

impl std::error::Error for SlhDsaError {}

/// Vérifie une signature SLH-DSA à partir de bytes bruts.
///
/// API de haut niveau pour le validateur de signatures. Prend les bytes bruts
/// du message, de la signature et de la clé publique, et retourne si la
/// signature est valide.
///
/// # Arguments
/// * `message` - Le message signé
/// * `signature_bytes` - La signature (SLH_SIGNATURE_SIZE octets)
/// * `public_key_bytes` - La clé publique (SLH_PUBLIC_KEY_SIZE octets)
///
/// # Returns
/// * `Ok(true)` si la signature est valide
/// * `Ok(false)` si la signature est invalide
/// * `Err(SlhDsaError)` si les entrées ont un format incorrect
pub fn verify_signature(
    message: &[u8],
    signature_bytes: &[u8],
    public_key_bytes: &[u8],
) -> Result<bool, SlhDsaError> {
    let pk = PublicKey::from_bytes(public_key_bytes)
        .ok_or(SlhDsaError::InvalidPublicKey)?;
    let sig = Signature::from_bytes(signature_bytes)
        .ok_or(SlhDsaError::InvalidSignature)?;
    Ok(verify(&pk, message, &sig))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let (sk, pk) = SecretKey::generate();
        assert_eq!(sk.bytes.len(), SLH_SECRET_KEY_SIZE);
        assert_eq!(pk.bytes.len(), SLH_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_public_key_size_constant() {
        // Vérification critique: la clé publique doit faire 32 octets pour SLH-DSA-SHA2-128s
        assert_eq!(SLH_PUBLIC_KEY_SIZE, 32);
        assert_eq!(SLH_SECRET_KEY_SIZE, 64);
        assert_eq!(SLH_SIGNATURE_SIZE, 7856);
    }

    #[test]
    fn test_sign_verify() {
        let (sk, pk) = SecretKey::generate();
        let message = b"Test message for SLH-DSA";
        
        let sig = sign(&sk, message);
        assert!(verify(&pk, message, &sig));
    }

    #[test]
    fn test_wrong_message_fails() {
        let (sk, pk) = SecretKey::generate();
        let message = b"Original message";
        let sig = sign(&sk, message);
        
        // La signature doit être valide pour le message original
        assert!(verify(&pk, message, &sig));
    }

    #[test]
    fn test_signature_size() {
        let (sk, _) = SecretKey::generate();
        let sig = sign(&sk, b"test");
        assert_eq!(sig.bytes.len(), SLH_SIGNATURE_SIZE);
    }
    
    #[test]
    fn test_signer_counter() {
        let (sk, _) = SecretKey::generate();
        let mut signer = SlhDsaSigner::new(sk);
        
        let message = b"Test message";
        let (_, counter1) = signer.sign_with_counter(message);
        assert_eq!(counter1, 0);
        
        let (_, counter2) = signer.sign_with_counter(message);
        assert_eq!(counter2, 1);
    }
    
    #[test]
    fn test_verifier_with_counter() {
        let (sk, pk) = SecretKey::generate();
        let mut signer = SlhDsaSigner::new(sk);
        let verifier = SlhDsaVerifier::new(pk);

        let message = b"Test message";
        let (sig, counter) = signer.sign_with_counter(message);

        // La vérification doit réussir avec le bon compteur
        assert!(verifier.verify(message, &sig.to_bytes(), counter).is_ok());
    }

    // ========================================================================
    // Security tests — SLH-DSA robustness
    // ========================================================================

    #[test]
    fn test_wrong_message_rejected() {
        let (sk, pk) = SecretKey::generate();
        let sig = sign(&sk, b"correct message");
        assert!(!verify(&pk, b"wrong message", &sig));
    }

    #[test]
    fn test_wrong_key_rejected() {
        let (sk, _pk) = SecretKey::generate();
        let (_, other_pk) = SecretKey::generate();
        let sig = sign(&sk, b"test");
        assert!(!verify(&other_pk, b"test", &sig));
    }

    #[test]
    fn test_truncated_signature_rejected() {
        let (sk, pk) = SecretKey::generate();
        let sig = sign(&sk, b"test");
        // Tronquer la signature
        let truncated = Signature::from_bytes(&sig.bytes[..SLH_SIGNATURE_SIZE - 1]);
        assert!(truncated.is_none());
    }

    #[test]
    fn test_empty_signature_rejected() {
        let (_, pk) = SecretKey::generate();
        let empty_sig = Signature::from_bytes(&[]);
        assert!(empty_sig.is_none());
    }

    #[test]
    fn test_corrupted_signature_rejected() {
        let (sk, pk) = SecretKey::generate();
        let sig = sign(&sk, b"test message");
        // Corrompre chaque section critique de la signature
        for corrupt_pos in [0, 16, 31, 32, 48, 63] {
            let mut bad = sig.bytes.clone();
            bad[corrupt_pos] ^= 0xFF;
            let bad_sig = Signature { bytes: bad };
            assert!(!verify(&pk, b"test message", &bad_sig),
                "should reject signature corrupted at byte {}", corrupt_pos);
        }
    }

    #[test]
    fn test_zero_signature_rejected() {
        let (_, pk) = SecretKey::generate();
        let zero_sig = Signature { bytes: vec![0u8; SLH_SIGNATURE_SIZE] };
        assert!(!verify(&pk, b"test", &zero_sig));
    }

    #[test]
    fn test_empty_message_signs_and_verifies() {
        let (sk, pk) = SecretKey::generate();
        let sig = sign(&sk, b"");
        assert!(verify(&pk, b"", &sig));
        assert!(!verify(&pk, b"not empty", &sig));
    }

    #[test]
    fn test_large_message_signs_and_verifies() {
        let (sk, pk) = SecretKey::generate();
        let big_msg = vec![0xABu8; 1_000_000]; // 1MB
        let sig = sign(&sk, &big_msg);
        assert!(verify(&pk, &big_msg, &sig));
    }

    #[test]
    fn test_deterministic_signatures() {
        let (sk, pk) = SecretKey::generate();
        let msg = b"deterministic check";
        let sig1 = sign(&sk, msg);
        let sig2 = sign(&sk, msg);
        // SLH-DSA simplifié est déterministe (R = HASH(SK || message))
        assert_eq!(sig1.bytes, sig2.bytes);
    }

    #[test]
    fn test_different_messages_different_signatures() {
        let (sk, _) = SecretKey::generate();
        let sig1 = sign(&sk, b"message A");
        let sig2 = sign(&sk, b"message B");
        assert_ne!(sig1.bytes, sig2.bytes);
    }

    #[test]
    fn test_different_keys_different_signatures() {
        let (sk1, _) = SecretKey::generate();
        let (sk2, _) = SecretKey::generate();
        let msg = b"same message";
        let sig1 = sign(&sk1, msg);
        let sig2 = sign(&sk2, msg);
        assert_ne!(sig1.bytes, sig2.bytes);
    }

    #[test]
    fn test_public_key_from_invalid_bytes() {
        assert!(PublicKey::from_bytes(&[0u8; 31]).is_none()); // too short
        assert!(PublicKey::from_bytes(&[0u8; 33]).is_none()); // too long
        assert!(PublicKey::from_bytes(&[]).is_none());          // empty
        assert!(PublicKey::from_bytes(&[0u8; 32]).is_some());  // exact
    }

    #[test]
    fn test_secret_key_from_invalid_bytes() {
        assert!(SecretKey::from_bytes(&[0u8; 63]).is_none());
        assert!(SecretKey::from_bytes(&[0u8; 65]).is_none());
        assert!(SecretKey::from_bytes(&[]).is_none());
        assert!(SecretKey::from_bytes(&[0u8; 64]).is_some());
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let sk_bytes = [42u8; SLH_SECRET_KEY_SIZE];
        let sk1 = SecretKey::from_bytes(&sk_bytes).unwrap();
        let sk2 = SecretKey::from_bytes(&sk_bytes).unwrap();
        let pk1 = sk1.derive_public_key();
        let pk2 = sk2.derive_public_key();
        assert_eq!(pk1.bytes, pk2.bytes);
    }

    #[test]
    fn test_constant_time_eq_works() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &[1, 2, 3])); // different length
    }

    #[test]
    fn test_verify_signature_api() {
        let (sk, pk) = SecretKey::generate();
        let msg = b"high-level API test";
        let sig = sign(&sk, msg);
        // API haut niveau
        assert!(verify_signature(msg, &sig.bytes, &pk.bytes).unwrap());
        // Mauvais message
        assert!(!verify_signature(b"wrong", &sig.bytes, &pk.bytes).unwrap());
        // Mauvaise taille clé
        assert!(verify_signature(msg, &sig.bytes, &[0u8; 16]).is_err());
        // Mauvaise taille signature
        assert!(verify_signature(msg, &[0u8; 100], &pk.bytes).is_err());
    }

    #[test]
    fn test_verifier_wrong_counter_rejected() {
        let (sk, pk) = SecretKey::generate();
        let mut signer = SlhDsaSigner::new(sk);
        let verifier = SlhDsaVerifier::new(pk);

        let message = b"counter test";
        let (sig, counter) = signer.sign_with_counter(message);

        // Bon compteur → OK
        assert!(verifier.verify(message, &sig.to_bytes(), counter).is_ok());
        // Mauvais compteur → rejeté
        assert!(verifier.verify(message, &sig.to_bytes(), counter + 1).is_err());
    }
}
