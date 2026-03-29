//! Mining Identity Key (MIK) system for anti-sybil protection.
//!
//! The MIK system prevents sybil attacks by requiring miners to register
//! a cryptographic identity before participating in consensus. Each MIK
//! is bound to a specific block height and can be revoked if malicious
//! behavior is detected.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;

use crate::crypto::{keys::PublicKey, signature::Signature};

/// Size of a MIK identifier in bytes.
pub const MIK_ID_SIZE: usize = 32;

/// Mining Identity Key identifier.
pub type MikId = [u8; MIK_ID_SIZE];

/// Errors related to MIK operations.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum MikError {
    #[error("MIK not found: {id}")]
    NotFound { id: String },
    
    #[error("MIK already exists: {id}")]
    AlreadyExists { id: String },
    
    #[error("MIK is revoked: {id}")]
    Revoked { id: String },
    
    #[error("MIK has expired at block {expiry_block}, current block: {current_block}")]
    Expired { expiry_block: u64, current_block: u64 },
    
    #[error("Invalid MIK signature")]
    InvalidSignature,
    
    #[error("MIK creation block {creation_block} is in the future, current block: {current_block}")]
    FutureCreationBlock { creation_block: u64, current_block: u64 },
    
    #[error("MIK expiry block {expiry_block} must be after creation block {creation_block}")]
    InvalidExpiryBlock { creation_block: u64, expiry_block: u64 },
}

/// Status of a Mining Identity Key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum MikStatus {
    /// MIK is active and can be used for mining.
    Active,
    /// MIK has been revoked due to malicious behavior.
    Revoked { reason: String, revoked_at_block: u64 },
    /// MIK has expired naturally.
    Expired,
}

/// A Mining Identity Key registration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MiningIdentityKey {
    /// Unique identifier for this MIK.
    pub id: MikId,
    
    /// Public key associated with this MIK.
    pub public_key: PublicKey,
    
    /// Block height at which this MIK was created.
    pub creation_block: u64,
    
    /// Block height at which this MIK expires (optional).
    /// If None, the MIK never expires naturally.
    pub expiry_block: Option<u64>,
    
    /// Current status of the MIK.
    pub status: MikStatus,
    
    /// Metadata about the miner (optional).
    pub metadata: Option<MikMetadata>,
}

/// Optional metadata for a Mining Identity Key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MikMetadata {
    /// Human-readable name for the miner.
    pub name: Option<String>,
    
    /// Contact information (email, website, etc.).
    pub contact: Option<String>,
    
    /// Additional arbitrary data.
    pub extra: HashMap<String, String>,
}

impl MiningIdentityKey {
    /// Create a new MIK with the given parameters.
    pub fn new(
        public_key: PublicKey,
        creation_block: u64,
        expiry_block: Option<u64>,
        metadata: Option<MikMetadata>,
    ) -> Result<Self, MikError> {
        // Validate expiry block if provided
        if let Some(expiry) = expiry_block {
            if expiry <= creation_block {
                return Err(MikError::InvalidExpiryBlock {
                    creation_block,
                    expiry_block: expiry,
                });
            }
        }

        let id = Self::compute_id(&public_key, creation_block);

        Ok(Self {
            id,
            public_key,
            creation_block,
            expiry_block,
            status: MikStatus::Active,
            metadata,
        })
    }

    /// Compute the MIK ID from public key and creation block.
    pub fn compute_id(public_key: &PublicKey, creation_block: u64) -> MikId {
        let mut hasher = Sha256::new();
        hasher.update(b"TSN_MIK_ID_v1");
        hasher.update(&public_key.as_bytes());
        hasher.update(&creation_block.to_le_bytes());
        hasher.finalize().into()
    }

    /// Check if this MIK is valid at the given block height.
    pub fn is_valid_at_block(&self, current_block: u64) -> Result<(), MikError> {
        // Check if revoked
        if let MikStatus::Revoked { .. } = self.status {
            return Err(MikError::Revoked {
                id: hex::encode(self.id),
            });
        }

        // Check if creation block is in the future
        if self.creation_block > current_block {
            return Err(MikError::FutureCreationBlock {
                creation_block: self.creation_block,
                current_block,
            });
        }

        // Check if expired
        if let Some(expiry_block) = self.expiry_block {
            if current_block >= expiry_block {
                return Err(MikError::Expired {
                    expiry_block,
                    current_block,
                });
            }
        }

        Ok(())
    }

    /// Revoke this MIK with a reason.
    pub fn revoke(&mut self, reason: String, revoked_at_block: u64) {
        self.status = MikStatus::Revoked {
            reason,
            revoked_at_block,
        };
    }

    /// Mark this MIK as expired.
    pub fn mark_expired(&mut self) {
        self.status = MikStatus::Expired;
    }

    /// Get the MIK ID as a hex string.
    pub fn id_hex(&self) -> String {
        hex::encode(self.id)
    }

    /// Check if this MIK is currently active.
    pub fn is_active(&self) -> bool {
        matches!(self.status, MikStatus::Active)
    }

    /// Get the remaining lifetime of this MIK in blocks.
    pub fn remaining_lifetime(&self, current_block: u64) -> Option<u64> {
        self.expiry_block.map(|expiry| {
            if expiry > current_block {
                expiry - current_block
            } else {
                0
            }
        })
    }
}

/// A MIK registration request that needs to be signed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MikRegistrationRequest {
    /// Public key to register.
    pub public_key: PublicKey,
    
    /// Block height at which this MIK should be created.
    pub creation_block: u64,
    
    /// Optional expiry block.
    pub expiry_block: Option<u64>,
    
    /// Optional metadata.
    pub metadata: Option<MikMetadata>,
    
    /// Signature over the registration data.
    pub signature: Signature,
}

impl MikRegistrationRequest {
    /// Create a new registration request.
    pub fn new(
        public_key: PublicKey,
        creation_block: u64,
        expiry_block: Option<u64>,
        metadata: Option<MikMetadata>,
        signature: Signature,
    ) -> Self {
        Self {
            public_key,
            creation_block,
            expiry_block,
            metadata,
            signature,
        }
    }

    /// Get the data that should be signed for this registration.
    pub fn signing_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"TSN_MIK_REGISTRATION_v1");
        data.extend_from_slice(&self.public_key.as_bytes());
        data.extend_from_slice(&self.creation_block.to_le_bytes());
        
        if let Some(expiry) = self.expiry_block {
            data.extend_from_slice(&expiry.to_le_bytes());
        } else {
            data.extend_from_slice(&[0u8; 8]); // No expiry
        }
        
        // Include metadata hash if present
        if let Some(ref metadata) = self.metadata {
            let metadata_bytes = bincode::serialize(metadata).unwrap_or_default();
            let mut hasher = Sha256::new();
            hasher.update(&metadata_bytes);
            data.extend_from_slice(&hasher.finalize());
        } else {
            data.extend_from_slice(&[0u8; 32]); // No metadata
        }
        
        data
    }

    /// Verify the signature on this registration request.
    pub fn verify_signature(&self) -> Result<(), MikError> {
        let signing_data = self.signing_data();
        
        if self.public_key.verify(&signing_data, &self.signature) {
            Ok(())
        } else {
            Err(MikError::InvalidSignature)
        }
    }

    /// Convert this request into a MIK if valid.
    pub fn into_mik(self) -> Result<MiningIdentityKey, MikError> {
        // Verify signature first
        self.verify_signature()?;
        
        // Create the MIK
        MiningIdentityKey::new(
            self.public_key,
            self.creation_block,
            self.expiry_block,
            self.metadata,
        )
    }
}

/// A MIK revocation request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MikRevocationRequest {
    /// ID of the MIK to revoke.
    pub mik_id: MikId,
    
    /// Reason for revocation.
    pub reason: String,
    
    /// Block at which the revocation takes effect.
    pub revoked_at_block: u64,
    
    /// Signature from the MIK owner or an authorized entity.
    pub signature: Signature,
    
    /// Public key of the signer.
    pub signer_public_key: PublicKey,
}

impl MikRevocationRequest {
    /// Get the data that should be signed for this revocation.
    pub fn signing_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"TSN_MIK_REVOCATION_v1");
        data.extend_from_slice(&self.mik_id);
        data.extend_from_slice(self.reason.as_bytes());
        data.extend_from_slice(&self.revoked_at_block.to_le_bytes());
        data
    }

    /// Verify the signature on this revocation request.
    pub fn verify_signature(&self) -> Result<(), MikError> {
        let signing_data = self.signing_data();
        
        if self.signer_public_key.verify(&signing_data, &self.signature) {
            Ok(())
        } else {
            Err(MikError::InvalidSignature)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyPair;

    #[test]
    fn test_mik_creation() {
        let keypair = KeyPair::generate();
        let creation_block = 100;
        let expiry_block = Some(1000);
        
        let mik = MiningIdentityKey::new(
            keypair.public_key(),
            creation_block,
            expiry_block,
            None,
        ).unwrap();
        
        assert_eq!(mik.creation_block, creation_block);
        assert_eq!(mik.expiry_block, expiry_block);
        assert!(mik.is_active());
        assert_eq!(mik.id, MiningIdentityKey::compute_id(&keypair.public_key(), creation_block));
    }

    #[test]
    fn test_mik_validation() {
        let keypair = KeyPair::generate();
        let mut mik = MiningIdentityKey::new(
            keypair.public_key(),
            100,
            Some(200),
            None,
        ).unwrap();
        
        // Valid at creation block
        assert!(mik.is_valid_at_block(100).is_ok());
        
        // Valid before expiry
        assert!(mik.is_valid_at_block(150).is_ok());
        
        // Invalid after expiry
        assert!(mik.is_valid_at_block(200).is_err());
        
        // Invalid if revoked
        mik.revoke("Test revocation".to_string(), 150);
        assert!(mik.is_valid_at_block(160).is_err());
    }

    #[test]
    fn test_mik_registration_request() {
        let keypair = KeyPair::generate();
        let creation_block = 100;
        let expiry_block = Some(1000);
        
        let mut request = MikRegistrationRequest {
            public_key: keypair.public_key(),
            creation_block,
            expiry_block,
            metadata: None,
            signature: Signature::default(), // Will be replaced
        };
        
        // Sign the request
        let signing_data = request.signing_data();
        request.signature = keypair.sign(&signing_data);
        
        // Verify signature
        assert!(request.verify_signature().is_ok());
        
        // Convert to MIK
        let mik = request.into_mik().unwrap();
        assert_eq!(mik.creation_block, creation_block);
        assert_eq!(mik.expiry_block, expiry_block);
    }

    #[test]
    fn test_invalid_expiry_block() {
        let keypair = KeyPair::generate();
        
        // Expiry block before creation block should fail
        let result = MiningIdentityKey::new(
            keypair.public_key(),
            100,
            Some(50), // Invalid: before creation block
            None,
        );
        
        assert!(matches!(result, Err(MikError::InvalidExpiryBlock { .. })));
    }

    #[test]
    fn test_mik_id_computation() {
        let keypair = KeyPair::generate();
        let creation_block = 42;
        
        let id1 = MiningIdentityKey::compute_id(&keypair.public_key(), creation_block);
        let id2 = MiningIdentityKey::compute_id(&keypair.public_key(), creation_block);
        
        // Same inputs should produce same ID
        assert_eq!(id1, id2);
        
        // Different creation block should produce different ID
        let id3 = MiningIdentityKey::compute_id(&keypair.public_key(), creation_block + 1);
        assert_ne!(id1, id3);
    }
}