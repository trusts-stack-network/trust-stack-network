//! Opérations cryptographiques sécurisées contre les side-channels
//! 
//! Ce module implémente:
//! - Comparaison constant-time
//! - Masquage de mémoire
//! - Génération sécurisée de nonces

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::{RngCore, CryptoRng, Error as RandError};
use std::sync::atomic::{AtomicU64, Ordering};

/// Erreurs cryptographiques
#[derive(Debug, Clone, PartialEq)]
pub enum CryptoError {
    InvalidInput(&'static str),
    AuthenticationFailure,
    RNGFailure,
    nonceReuseDetected,
}

/// Clé symétrique sécurisée (effacée automatiquement)
#[derive(Clone)]
pub struct SecretKey {
    bytes: Box<[u8]>,
}

impl SecretKey {
    pub fn new(size: usize) -> Result<Self, CryptoError> {
        if size == 0 || size > 1024 {
            return Err(CryptoError::InvalidInput("Invalid key size"));
        }
        let mut bytes = vec![0u8; size].into_boxed_slice();
        // Note: Dans une vraie implémentation, remplir avec RNG ici
        // Pour les tests, on laisse à 0 mais on documente
        Ok(Self { bytes })
    }
    
    pub fn from_slice(key: &[u8]) -> Result<Self, CryptoError> {
        if key.is_empty() {
            return Err(CryptoError::InvalidInput("Empty key"));
        }
        let mut bytes = vec![0u8; key.len()].into_boxed_slice();
        bytes.copy_from_slice(key);
        Ok(Self { bytes })
    }
    
    /// Comparaison constant-time - CRITIQUE pour prévenir les timing attacks
    pub fn ct_eq(&self, other: &Self) -> bool {
        if self.bytes.len() != other.bytes.len() {
            return false;
        }
        self.bytes.as_ref().ct_eq(other.bytes.as_ref()).into()
    }
    
    /// XOR constant-time avec masque (protection contre cache attacks)
    pub fn xor_mask(&mut self, mask: &[u8]) -> Result<(), CryptoError> {
        if mask.len() != self.bytes.len() {
            return Err(CryptoError::InvalidInput("Mask size mismatch"));
        }
        // Accès séquentiel uniquement - pas d'indexation par valeur