//! Mécanisme de rotation automatique des clés SLH-DSA
//!
//! Implémente un système de rotation périodique des clés post-quantiques pour maintenir
//! la sécurité à long terme. Basé sur les recommandations NIST SP 800-57 Part 1 Rev. 5
//! pour la gestion des clés cryptographiques.
//!
//! ## Sécurité
//!
//! La rotation des clés SLH-DSA est critique pour la sécurité post-quantique car :
//! - Limite l'exposition temporelle des clés privées
//! - Réduit l'impact d'une compromission éventuelle
//! - Prépare la transition vers de nouveaux paramètres si nécessaire
//!
//! ## Références
//!
//! - NIST SP 800-57 Part 1 Rev. 5: Recommendation for Key Management
//! - FIPS 205: Stateless Hash-Based Digital Signature Standard
//! - RFC 8391: XMSS: eXtended Merkle Signature Scheme

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{
    keys::{KeyPair, KeyError},
    pq::slh_dsa::{PublicKey as SlhPublicKey, SecretKey as SlhSecretKey, SlhDsaError},
    Address,
};

/// Durée de validité par défaut d'une clé (30 jours)
pub const DEFAULT_KEY_LIFETIME: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Période de transition pendant laquelle l'ancienne et la nouvelle clé coexistent (7 jours)
pub const DEFAULT_TRANSITION_PERIOD: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Nombre maximum de clés actives simultanément
pub const MAX_ACTIVE_KEYS: usize = 3;

/// Identifiant unique d'une clé dans le système de rotation
pub type KeyId = u64;

/// État d'une clé dans le cycle de rotation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    /// Clé en cours de génération
    Generating,
    /// Clé active pour signature
    Active,
    /// Clé en transition (encore valide pour vérification)
    Transitioning,
    /// Clé révoquée (invalide)
    Revoked,
}

/// Métadonnées d'une clé dans le système de rotation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Identifiant unique de la clé
    pub id: KeyId,
    /// État actuel de la clé
    pub state: KeyState,
    /// Timestamp de création (Unix epoch)
    pub created_at: u64,
    /// Timestamp d'activation (Unix epoch)
    pub activated_at: Option<u64>,
    /// Timestamp de révocation (Unix epoch)
    pub revoked_at: Option<u64>,
    /// Durée de vie configurée pour cette clé
    pub lifetime: Duration,
    /// Adresse dérivée de cette clé
    pub address: Address,
    /// Hash de la clé publique pour identification rapide
    pub public_key_hash: [u8; 32],
}

impl KeyMetadata {
    /// Vérifie si la clé est expirée
    pub fn is_expired(&self, now: SystemTime) -> bool {
        if let Some(activated_at) = self.activated_at {
            let activated_time = UNIX_EPOCH + Duration::from_secs(activated_at);
            now.duration_since(activated_time)
                .map(|d| d > self.lifetime)
                .unwrap_or(true)
        } else {
            false
        }
    }

    /// Vérifie si la clé est en période de transition
    pub fn is_in_transition(&self, now: SystemTime) -> bool {
        if let Some(activated_at) = self.activated_at {
            let activated_time = UNIX_EPOCH + Duration::from_secs(activated_at);
            let transition_start = activated_time + self.lifetime - DEFAULT_TRANSITION_PERIOD;
            now >= transition_start && !self.is_expired(now)
        } else {
            false
        }
    }
}

/// Clé avec ses métadonnées, protégée par zeroize
#[derive(ZeroizeOnDrop)]
pub struct ManagedKey {
    /// Métadonnées publiques
    pub metadata: KeyMetadata,
    /// Paire de clés (sera zéroïsée à la destruction)
    keypair: KeyPair,
}

impl ManagedKey {
    /// Crée une nouvelle clé gérée
    pub fn new(id: KeyId, lifetime: Duration) -> Result<Self, KeyRotationError> {
        let keypair = KeyPair::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| KeyRotationError::TimeError)?
            .as_secs();

        // Calcul du hash de la clé publique pour identification
        let public_key_bytes = keypair.public_key_bytes();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&public_key_bytes);
        let public_key_hash: [u8; 32] = hasher.finalize().into();

        let metadata = KeyMetadata {
            id,
            state: KeyState::Generating,
            created_at: now,
            activated_at: None,
            revoked_at: None,
            lifetime,
            address: keypair.address(),
            public_key_hash,
        };

        Ok(Self { metadata, keypair })
    }

    /// Accès en lecture seule à la paire de clés
    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }

    /// Active la clé
    pub fn activate(&mut self) -> Result<(), KeyRotationError> {
        if self.metadata.state != KeyState::Generating {
            return Err(KeyRotationError::InvalidStateTransition);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| KeyRotationError::TimeError)?
            .as_secs();

        self.metadata.state = KeyState::Active;
        self.metadata.activated_at = Some(now);

        Ok(())
    }

    /// Met la clé en transition
    pub fn transition(&mut self) -> Result<(), KeyRotationError> {
        if self.metadata.state != KeyState::Active {
            return Err(KeyRotationError::InvalidStateTransition);
        }

        self.metadata.state = KeyState::Transitioning;
        Ok(())
    }

    /// Révoque la clé
    pub fn revoke(&mut self) -> Result<(), KeyRotationError> {
        if matches!(self.metadata.state, KeyState::Revoked) {
            return Err(KeyRotationError::InvalidStateTransition);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| KeyRotationError::TimeError)?
            .as_secs();

        self.metadata.state = KeyState::Revoked;
        self.metadata.revoked_at = Some(now);

        Ok(())
    }
}

/// Gestionnaire de rotation automatique des clés SLH-DSA
pub struct KeyRotationManager {
    /// Clés gérées indexées par ID
    keys: HashMap<KeyId, ManagedKey>,
    /// ID de la prochaine clé à générer
    next_key_id: KeyId,
    /// Clé actuellement active pour signature
    active_key_id: Option<KeyId>,
    /// Configuration de durée de vie par défaut
    default_lifetime: Duration,
    /// Dernière vérification de rotation
    last_rotation_check: SystemTime,
}

impl KeyRotationManager {
    /// Crée un nouveau gestionnaire de rotation
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            next_key_id: 1,
            active_key_id: None,
            default_lifetime: DEFAULT_KEY_LIFETIME,
            last_rotation_check: SystemTime::now(),
        }
    }

    /// Crée un gestionnaire avec une durée de vie personnalisée
    pub fn with_lifetime(lifetime: Duration) -> Self {
        Self {
            keys: HashMap::new(),
            next_key_id: 1,
            active_key_id: None,
            default_lifetime: lifetime,
            last_rotation_check: SystemTime::now(),
        }
    }

    /// Génère une nouvelle clé
    pub fn generate_key(&mut self) -> Result<KeyId, KeyRotationError> {
        if self.keys.len() >= MAX_ACTIVE_KEYS {
            return Err(KeyRotationError::TooManyKeys);
        }

        let key_id = self.next_key_id;
        self.next_key_id += 1;

        let managed_key = ManagedKey::new(key_id, self.default_lifetime)?;
        self.keys.insert(key_id, managed_key);

        Ok(key_id)
    }

    /// Active une clé pour signature
    pub fn activate_key(&mut self, key_id: KeyId) -> Result<(), KeyRotationError> {
        let key = self.keys.get_mut(&key_id)
            .ok_or(KeyRotationError::KeyNotFound)?;

        key.activate()?;

        // Met l'ancienne clé active en transition si elle existe
        if let Some(old_active_id) = self.active_key_id {
            if old_active_id != key_id {
                if let Some(old_key) = self.keys.get_mut(&old_active_id) {
                    let _ = old_key.transition();
                }
            }
        }

        self.active_key_id = Some(key_id);
        Ok(())
    }

    /// Obtient la clé active pour signature
    pub fn active_key(&self) -> Option<&ManagedKey> {
        self.active_key_id
            .and_then(|id| self.keys.get(&id))
    }

    /// Obtient une clé par son ID
    pub fn get_key(&self, key_id: KeyId) -> Option<&ManagedKey> {
        self.keys.get(&key_id)
    }

    /// Liste toutes les clés avec leur état
    pub fn list_keys(&self) -> Vec<&KeyMetadata> {
        self.keys.values().map(|k| &k.metadata).collect()
    }

    /// Révoque une clé
    pub fn revoke_key(&mut self, key_id: KeyId) -> Result<(), KeyRotationError> {
        let key = self.keys.get_mut(&key_id)
            .ok_or(KeyRotationError::KeyNotFound)?;

        key.revoke()?;

        // Si c'était la clé active, on la désactive
        if self.active_key_id == Some(key_id) {
            self.active_key_id = None;
        }

        Ok(())
    }

    /// Nettoie les clés révoquées anciennes
    pub fn cleanup_revoked_keys(&mut self, retention_period: Duration) -> usize {
        let now = SystemTime::now();
        let mut to_remove = Vec::new();

        for (id, key) in &self.keys {
            if key.metadata.state == KeyState::Revoked {
                if let Some(revoked_at) = key.metadata.revoked_at {
                    let revoked_time = UNIX_EPOCH + Duration::from_secs(revoked_at);
                    if now.duration_since(revoked_time)
                        .map(|d| d > retention_period)
                        .unwrap_or(false)
                    {
                        to_remove.push(*id);
                    }
                }
            }
        }

        let removed_count = to_remove.len();
        for id in to_remove {
            self.keys.remove(&id);
        }

        removed_count
    }

    /// Vérifie si une rotation automatique est nécessaire
    pub fn check_rotation_needed(&mut self) -> Result<bool, KeyRotationError> {
        let now = SystemTime::now();
        self.last_rotation_check = now;

        if let Some(active_key) = self.active_key() {
            // Vérifie si la clé active est en période de transition
            if active_key.metadata.is_in_transition(now) {
                return Ok(true);
            }

            // Vérifie si la clé active est expirée
            if active_key.metadata.is_expired(now) {
                return Ok(true);
            }
        } else {
            // Aucune clé active, rotation nécessaire
            return Ok(true);
        }

        Ok(false)
    }

    /// Effectue une rotation automatique si nécessaire
    pub fn auto_rotate(&mut self) -> Result<Option<KeyId>, KeyRotationError> {
        if !self.check_rotation_needed()? {
            return Ok(None);
        }

        // Génère une nouvelle clé
        let new_key_id = self.generate_key()?;

        // Active immédiatement la nouvelle clé
        self.activate_key(new_key_id)?;

        Ok(Some(new_key_id))
    }

    /// Trouve une clé par son hash de clé publique
    pub fn find_key_by_public_hash(&self, public_key_hash: &[u8; 32]) -> Option<&ManagedKey> {
        self.keys.values()
            .find(|k| &k.metadata.public_key_hash == public_key_hash)
    }

    /// Vérifie si une clé peut être utilisée pour vérification
    pub fn can_verify_with_key(&self, key_id: KeyId) -> bool {
        if let Some(key) = self.keys.get(&key_id) {
            matches!(key.metadata.state, KeyState::Active | KeyState::Transitioning)
        } else {
            false
        }
    }

    /// Obtient les statistiques du gestionnaire
    pub fn stats(&self) -> KeyRotationStats {
        let mut stats = KeyRotationStats::default();

        for key in self.keys.values() {
            match key.metadata.state {
                KeyState::Generating => stats.generating += 1,
                KeyState::Active => stats.active += 1,
                KeyState::Transitioning => stats.transitioning += 1,
                KeyState::Revoked => stats.revoked += 1,
            }
        }

        stats.total = self.keys.len();
        stats
    }
}

impl Default for KeyRotationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistiques du gestionnaire de rotation
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct KeyRotationStats {
    pub total: usize,
    pub generating: usize,
    pub active: usize,
    pub transitioning: usize,
    pub revoked: usize,
}

/// Erreurs du système de rotation des clés
#[derive(Debug, thiserror::Error)]
pub enum KeyRotationError {
    #[error("Clé non trouvée")]
    KeyNotFound,

    #[error("Transition d'état invalide")]
    InvalidStateTransition,

    #[error("Trop de clés actives (maximum: {MAX_ACTIVE_KEYS})")]
    TooManyKeys,

    #[error("Erreur de temps système")]
    TimeError,

    #[error("Erreur de génération de clé: {0}")]
    KeyGenerationError(#[from] KeyError),

    #[error("Erreur SLH-DSA: {0}")]
    SlhDsaError(#[from] SlhDsaError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_key_generation() {
        let mut manager = KeyRotationManager::new();
        let key_id = manager.generate_key().unwrap();
        
        assert_eq!(key_id, 1);
        assert!(manager.get_key(key_id).is_some());
        
        let key = manager.get_key(key_id).unwrap();
        assert_eq!(key.metadata.state, KeyState::Generating);
    }

    #[test]
    fn test_key_activation() {
        let mut manager = KeyRotationManager::new();
        let key_id = manager.generate_key().unwrap();
        
        manager.activate_key(key_id).unwrap();
        
        let key = manager.get_key(key_id).unwrap();
        assert_eq!(key.metadata.state, KeyState::Active);
        assert!(key.metadata.activated_at.is_some());
        assert_eq!(manager.active_key_id, Some(key_id));
    }

    #[test]
    fn test_key_transition() {
        let mut manager = KeyRotationManager::new();
        let key_id1 = manager.generate_key().unwrap();
        let key_id2 = manager.generate_key().unwrap();
        
        manager.activate_key(key_id1).unwrap();
        manager.activate_key(key_id2).unwrap();
        
        // La première clé doit être en transition
        let key1 = manager.get_key(key_id1).unwrap();
        assert_eq!(key1.metadata.state, KeyState::Transitioning);
        
        // La seconde clé doit être active
        let key2 = manager.get_key(key_id2).unwrap();
        assert_eq!(key2.metadata.state, KeyState::Active);
        assert_eq!(manager.active_key_id, Some(key_id2));
    }

    #[test]
    fn test_key_revocation() {
        let mut manager = KeyRotationManager::new();
        let key_id = manager.generate_key().unwrap();
        
        manager.activate_key(key_id).unwrap();
        manager.revoke_key(key_id).unwrap();
        
        let key = manager.get_key(key_id).unwrap();
        assert_eq!(key.metadata.state, KeyState::Revoked);
        assert!(key.metadata.revoked_at.is_some());
        assert_eq!(manager.active_key_id, None);
    }

    #[test]
    fn test_max_keys_limit() {
        let mut manager = KeyRotationManager::new();
        
        // Génère le maximum de clés
        for _ in 0..MAX_ACTIVE_KEYS {
            manager.generate_key().unwrap();
        }
        
        // La suivante doit échouer
        assert!(matches!(
            manager.generate_key(),
            Err(KeyRotationError::TooManyKeys)
        ));
    }

    #[test]
    fn test_cleanup_revoked_keys() {
        let mut manager = KeyRotationManager::new();
        let key_id = manager.generate_key().unwrap();
        
        manager.activate_key(key_id).unwrap();
        manager.revoke_key(key_id).unwrap();
        
        // Nettoyage immédiat (rétention = 0)
        let removed = manager.cleanup_revoked_keys(Duration::from_secs(0));
        assert_eq!(removed, 1);
        assert!(manager.get_key(key_id).is_none());
    }

    #[test]
    fn test_key_expiration() {
        let short_lifetime = Duration::from_millis(100);
        let mut manager = KeyRotationManager::with_lifetime(short_lifetime);
        
        let key_id = manager.generate_key().unwrap();
        manager.activate_key(key_id).unwrap();
        
        // Attendre l'expiration
        thread::sleep(Duration::from_millis(150));
        
        let key = manager.get_key(key_id).unwrap();
        assert!(key.metadata.is_expired(SystemTime::now()));
        
        assert!(manager.check_rotation_needed().unwrap());
    }

    #[test]
    fn test_auto_rotation() {
        let short_lifetime = Duration::from_millis(100);
        let mut manager = KeyRotationManager::with_lifetime(short_lifetime);
        
        let key_id1 = manager.generate_key().unwrap();
        manager.activate_key(key_id1).unwrap();
        
        // Attendre l'expiration
        thread::sleep(Duration::from_millis(150));
        
        // Rotation automatique
        let new_key_id = manager.auto_rotate().unwrap();
        assert!(new_key_id.is_some());
        
        let new_id = new_key_id.unwrap();
        assert_ne!(new_id, key_id1);
        assert_eq!(manager.active_key_id, Some(new_id));
        
        // L'ancienne clé doit être en transition
        let old_key = manager.get_key(key_id1).unwrap();
        assert_eq!(old_key.metadata.state, KeyState::Transitioning);
    }

    #[test]
    fn test_find_key_by_public_hash() {
        let mut manager = KeyRotationManager::new();
        let key_id = manager.generate_key().unwrap();
        
        let key = manager.get_key(key_id).unwrap();
        let public_hash = key.metadata.public_key_hash;
        
        let found_key = manager.find_key_by_public_hash(&public_hash);
        assert!(found_key.is_some());
        assert_eq!(found_key.unwrap().metadata.id, key_id);
    }

    #[test]
    fn test_verification_permissions() {
        let mut manager = KeyRotationManager::new();
        let key_id = manager.generate_key().unwrap();
        
        // Clé en génération - pas de vérification
        assert!(!manager.can_verify_with_key(key_id));
        
        // Clé active - vérification OK
        manager.activate_key(key_id).unwrap();
        assert!(manager.can_verify_with_key(key_id));
        
        // Clé en transition - vérification OK
        let key = manager.keys.get_mut(&key_id).unwrap();
        key.transition().unwrap();
        assert!(manager.can_verify_with_key(key_id));
        
        // Clé révoquée - pas de vérification
        let key = manager.keys.get_mut(&key_id).unwrap();
        key.revoke().unwrap();
        assert!(!manager.can_verify_with_key(key_id));
    }

    #[test]
    fn test_stats() {
        let mut manager = KeyRotationManager::new();
        
        let key_id1 = manager.generate_key().unwrap();
        let key_id2 = manager.generate_key().unwrap();
        let key_id3 = manager.generate_key().unwrap();
        
        manager.activate_key(key_id1).unwrap();
        manager.activate_key(key_id2).unwrap(); // key_id1 passe en transition
        manager.revoke_key(key_id3).unwrap();
        
        let stats = manager.stats();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.active, 1);
        assert_eq!(stats.transitioning, 1);
        assert_eq!(stats.revoked, 1);
        assert_eq!(stats.generating, 0);
    }
}