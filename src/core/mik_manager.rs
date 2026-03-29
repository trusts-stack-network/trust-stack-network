//! Mining Identity Key (MIK) manager for registration, validation, and revocation.
//!
//! This module provides the core logic for managing MIKs in the blockchain state.
//! It handles registration of new MIKs, validation of existing ones, and revocation
//! when malicious behavior is detected.

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::mik::{
    MikError, MikId, MiningIdentityKey, MikRegistrationRequest, MikRevocationRequest, MikStatus
};
use crate::crypto::keys::PublicKey;

/// Errors related to MIK management.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum MikManagerError {
    #[error("MIK error: {0}")]
    Mik(#[from] MikError),
    
    #[error("Duplicate MIK registration in block: {id}")]
    DuplicateRegistration { id: String },
    
    #[error("Cannot revoke MIK that doesn't exist: {id}")]
    CannotRevokeNonExistent { id: String },
    
    #[error("MIK registration limit exceeded: {limit} per block")]
    RegistrationLimitExceeded { limit: usize },
    
    #[error("Public key already has an active MIK: {existing_id}")]
    PublicKeyAlreadyRegistered { existing_id: String },
    
    #[error("Unauthorized revocation attempt for MIK: {id}")]
    UnauthorizedRevocation { id: String },
}

/// Configuration for MIK management.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MikConfig {
    /// Maximum number of MIK registrations per block.
    pub max_registrations_per_block: usize,
    
    /// Default MIK lifetime in blocks (if no expiry specified).
    pub default_lifetime_blocks: Option<u64>,
    
    /// Minimum blocks between registration and first use.
    pub min_activation_delay: u64,
    
    /// Whether to allow self-revocation.
    pub allow_self_revocation: bool,
    
    /// List of authorized revocation public keys (governance).
    pub authorized_revokers: HashSet<PublicKey>,
}

impl Default for MikConfig {
    fn default() -> Self {
        Self {
            max_registrations_per_block: 10,
            default_lifetime_blocks: Some(100_000), // ~1 year at 1 block/10s
            min_activation_delay: 10, // 10 blocks
            allow_self_revocation: true,
            authorized_revokers: HashSet::new(),
        }
    }
}

/// State of all Mining Identity Keys in the system.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MikState {
    /// All registered MIKs by their ID.
    pub miks: HashMap<MikId, MiningIdentityKey>,
    
    /// Mapping from public key to MIK ID for quick lookups.
    pub public_key_to_mik: HashMap<PublicKey, MikId>,
    
    /// Set of active MIK IDs for quick validation.
    pub active_miks: HashSet<MikId>,
    
    /// Configuration for MIK management.
    pub config: MikConfig,
}

impl Default for MikState {
    fn default() -> Self {
        Self {
            miks: HashMap::new(),
            public_key_to_mik: HashMap::new(),
            active_miks: HashSet::new(),
            config: MikConfig::default(),
        }
    }
}

impl MikState {
    /// Create a new empty MIK state with the given configuration.
    pub fn new(config: MikConfig) -> Self {
        Self {
            miks: HashMap::new(),
            public_key_to_mik: HashMap::new(),
            active_miks: HashSet::new(),
            config,
        }
    }

    /// Get a MIK by its ID.
    pub fn get_mik(&self, mik_id: &MikId) -> Option<&MiningIdentityKey> {
        self.miks.get(mik_id)
    }

    /// Get a MIK by public key.
    pub fn get_mik_by_public_key(&self, public_key: &PublicKey) -> Option<&MiningIdentityKey> {
        self.public_key_to_mik
            .get(public_key)
            .and_then(|mik_id| self.miks.get(mik_id))
    }

    /// Check if a MIK is active at the given block height.
    pub fn is_mik_active(&self, mik_id: &MikId, current_block: u64) -> bool {
        if let Some(mik) = self.miks.get(mik_id) {
            mik.is_valid_at_block(current_block).is_ok()
        } else {
            false
        }
    }

    /// Get all active MIKs at the given block height.
    pub fn get_active_miks(&self, current_block: u64) -> Vec<&MiningIdentityKey> {
        self.miks
            .values()
            .filter(|mik| mik.is_valid_at_block(current_block).is_ok())
            .collect()
    }

    /// Get the number of active MIKs.
    pub fn active_mik_count(&self, current_block: u64) -> usize {
        self.get_active_miks(current_block).len()
    }

    /// Register a new MIK from a registration request.
    pub fn register_mik(
        &mut self,
        request: MikRegistrationRequest,
        current_block: u64,
        registrations_in_block: usize,
    ) -> Result<MikId, MikManagerError> {
        // Check registration limit
        if registrations_in_block >= self.config.max_registrations_per_block {
            return Err(MikManagerError::RegistrationLimitExceeded {
                limit: self.config.max_registrations_per_block,
            });
        }

        // Check if public key already has an active MIK
        if let Some(existing_mik_id) = self.public_key_to_mik.get(&request.public_key) {
            if let Some(existing_mik) = self.miks.get(existing_mik_id) {
                if existing_mik.is_valid_at_block(current_block).is_ok() {
                    return Err(MikManagerError::PublicKeyAlreadyRegistered {
                        existing_id: existing_mik.id_hex(),
                    });
                }
            }
        }

        // Convert request to MIK
        let mut mik = request.into_mik()?;

        // Apply default lifetime if not specified
        if mik.expiry_block.is_none() {
            if let Some(default_lifetime) = self.config.default_lifetime_blocks {
                mik.expiry_block = Some(mik.creation_block + default_lifetime);
            }
        }

        let mik_id = mik.id;

        // Check for duplicate registration
        if self.miks.contains_key(&mik_id) {
            return Err(MikManagerError::DuplicateRegistration {
                id: mik.id_hex(),
            });
        }

        // Store the MIK
        self.public_key_to_mik.insert(mik.public_key.clone(), mik_id);
        if mik.is_valid_at_block(current_block).is_ok() {
            self.active_miks.insert(mik_id);
        }
        self.miks.insert(mik_id, mik);

        Ok(mik_id)
    }

    /// Revoke a MIK using a revocation request.
    pub fn revoke_mik(
        &mut self,
        request: MikRevocationRequest,
        current_block: u64,
    ) -> Result<(), MikManagerError> {
        // Verify the revocation signature
        request.verify_signature()?;

        // Check if MIK exists
        let mik = self.miks.get_mut(&request.mik_id)
            .ok_or_else(|| MikManagerError::CannotRevokeNonExistent {
                id: hex::encode(request.mik_id),
            })?;

        // Check authorization
        let is_authorized = if self.config.allow_self_revocation 
            && mik.public_key == request.signer_public_key {
            true // Self-revocation
        } else {
            self.config.authorized_revokers.contains(&request.signer_public_key)
        };

        if !is_authorized {
            return Err(MikManagerError::UnauthorizedRevocation {
                id: mik.id_hex(),
            });
        }

        // Perform the revocation
        mik.revoke(request.reason, request.revoked_at_block);
        self.active_miks.remove(&request.mik_id);

        Ok(())
    }

    /// Update the state for a new block (expire old MIKs, etc.).
    pub fn update_for_block(&mut self, current_block: u64) {
        let mut expired_miks = Vec::new();

        // Check for expired MIKs
        for (mik_id, mik) in &mut self.miks {
            if let Some(expiry_block) = mik.expiry_block {
                if current_block >= expiry_block && mik.is_active() {
                    mik.mark_expired();
                    expired_miks.push(*mik_id);
                }
            }
        }

        // Remove expired MIKs from active set
        for mik_id in expired_miks {
            self.active_miks.remove(&mik_id);
        }

        // Update active set based on current validations
        self.active_miks.clear();
        for (mik_id, mik) in &self.miks {
            if mik.is_valid_at_block(current_block).is_ok() {
                self.active_miks.insert(*mik_id);
            }
        }
    }

    /// Check if a public key can mine at the given block height.
    pub fn can_mine(&self, public_key: &PublicKey, current_block: u64) -> bool {
        if let Some(mik) = self.get_mik_by_public_key(public_key) {
            // Check if MIK is valid
            if mik.is_valid_at_block(current_block).is_err() {
                return false;
            }

            // Check activation delay
            if current_block < mik.creation_block + self.config.min_activation_delay {
                return false;
            }

            true
        } else {
            false
        }
    }

    /// Get statistics about the MIK state.
    pub fn get_stats(&self, current_block: u64) -> MikStats {
        let total_miks = self.miks.len();
        let active_miks = self.get_active_miks(current_block).len();
        let revoked_miks = self.miks.values()
            .filter(|mik| matches!(mik.status, MikStatus::Revoked { .. }))
            .count();
        let expired_miks = self.miks.values()
            .filter(|mik| matches!(mik.status, MikStatus::Expired))
            .count();

        MikStats {
            total_miks,
            active_miks,
            revoked_miks,
            expired_miks,
            current_block,
        }
    }

    /// Validate the entire MIK state for consistency.
    pub fn validate_state(&self, current_block: u64) -> Result<(), MikManagerError> {
        for (mik_id, mik) in &self.miks {
            // Check ID consistency
            let expected_id = MiningIdentityKey::compute_id(&mik.public_key, mik.creation_block);
            if *mik_id != expected_id {
                return Err(MikManagerError::Mik(MikError::NotFound {
                    id: "Inconsistent MIK ID".to_string(),
                }));
            }

            // Check public key mapping consistency
            if let Some(mapped_id) = self.public_key_to_mik.get(&mik.public_key) {
                if *mapped_id != *mik_id {
                    return Err(MikManagerError::Mik(MikError::NotFound {
                        id: "Inconsistent public key mapping".to_string(),
                    }));
                }
            }

            // Check active set consistency
            let should_be_active = mik.is_valid_at_block(current_block).is_ok();
            let is_in_active_set = self.active_miks.contains(mik_id);
            
            if should_be_active != is_in_active_set {
                return Err(MikManagerError::Mik(MikError::NotFound {
                    id: "Inconsistent active set".to_string(),
                }));
            }
        }

        Ok(())
    }
}

/// Statistics about the MIK state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MikStats {
    pub total_miks: usize,
    pub active_miks: usize,
    pub revoked_miks: usize,
    pub expired_miks: usize,
    pub current_block: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyPair;
    use crate::crypto::mik::MikMetadata;

    fn create_test_registration_request(
        keypair: &KeyPair,
        creation_block: u64,
        expiry_block: Option<u64>,
    ) -> MikRegistrationRequest {
        let mut request = MikRegistrationRequest {
            public_key: keypair.public_key(),
            creation_block,
            expiry_block,
            metadata: None,
            signature: Default::default(),
        };

        let signing_data = request.signing_data();
        request.signature = keypair.sign(&signing_data);
        request
    }

    #[test]
    fn test_mik_registration() {
        let mut state = MikState::default();
        let keypair = KeyPair::generate();
        let current_block = 100;

        let request = create_test_registration_request(&keypair, current_block, Some(current_block + 1000));
        
        let mik_id = state.register_mik(request, current_block, 0).unwrap();
        
        assert!(state.miks.contains_key(&mik_id));
        assert!(state.public_key_to_mik.contains_key(&keypair.public_key()));
        assert_eq!(state.active_mik_count(current_block), 1);
    }

    #[test]
    fn test_duplicate_public_key_registration() {
        let mut state = MikState::default();
        let keypair = KeyPair::generate();
        let current_block = 100;

        // First registration should succeed
        let request1 = create_test_registration_request(&keypair, current_block, Some(current_block + 1000));
        assert!(state.register_mik(request1, current_block, 0).is_ok());

        // Second registration with same public key should fail
        let request2 = create_test_registration_request(&keypair, current_block + 1, Some(current_block + 1001));
        assert!(matches!(
            state.register_mik(request2, current_block, 0),
            Err(MikManagerError::PublicKeyAlreadyRegistered { .. })
        ));
    }

    #[test]
    fn test_mik_expiration() {
        let mut state = MikState::default();
        let keypair = KeyPair::generate();
        let current_block = 100;
        let expiry_block = current_block + 50;

        let request = create_test_registration_request(&keypair, current_block, Some(expiry_block));
        let mik_id = state.register_mik(request, current_block, 0).unwrap();

        // Should be active before expiry
        assert!(state.is_mik_active(&mik_id, expiry_block - 1));

        // Update state to expiry block
        state.update_for_block(expiry_block);

        // Should not be active after expiry
        assert!(!state.is_mik_active(&mik_id, expiry_block));
    }

    #[test]
    fn test_mik_revocation() {
        let mut state = MikState::default();
        let keypair = KeyPair::generate();
        let current_block = 100;

        let request = create_test_registration_request(&keypair, current_block, Some(current_block + 1000));
        let mik_id = state.register_mik(request, current_block, 0).unwrap();

        // Create revocation request
        let mut revocation_request = MikRevocationRequest {
            mik_id,
            reason: "Test revocation".to_string(),
            revoked_at_block: current_block + 10,
            signature: Default::default(),
            signer_public_key: keypair.public_key(),
        };

        let signing_data = revocation_request.signing_data();
        revocation_request.signature = keypair.sign(&signing_data);

        // Revoke the MIK
        assert!(state.revoke_mik(revocation_request, current_block + 10).is_ok());

        // Should not be active after revocation
        assert!(!state.is_mik_active(&mik_id, current_block + 10));
    }

    #[test]
    fn test_can_mine_with_activation_delay() {
        let mut state = MikState::default();
        state.config.min_activation_delay = 10;
        
        let keypair = KeyPair::generate();
        let current_block = 100;

        let request = create_test_registration_request(&keypair, current_block, Some(current_block + 1000));
        state.register_mik(request, current_block, 0).unwrap();

        // Should not be able to mine immediately
        assert!(!state.can_mine(&keypair.public_key(), current_block));

        // Should be able to mine after activation delay
        assert!(state.can_mine(&keypair.public_key(), current_block + 10));
    }

    #[test]
    fn test_registration_limit() {
        let mut state = MikState::default();
        state.config.max_registrations_per_block = 2;
        
        let current_block = 100;

        // First two registrations should succeed
        for i in 0..2 {
            let keypair = KeyPair::generate();
            let request = create_test_registration_request(&keypair, current_block, None);
            assert!(state.register_mik(request, current_block, i).is_ok());
        }

        // Third registration should fail
        let keypair = KeyPair::generate();
        let request = create_test_registration_request(&keypair, current_block, None);
        assert!(matches!(
            state.register_mik(request, current_block, 2),
            Err(MikManagerError::RegistrationLimitExceeded { .. })
        ));
    }
}