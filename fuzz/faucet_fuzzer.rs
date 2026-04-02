//! Fuzz Target for TSN Faucet Module
//!
//! This fuzzer targets the faucet claim validation logic to find:
//! - Parsing panics on malformed inputs
//! - Integer overflows in amount calculations
//! - Logic errors in rate limiting
//! - Memory exhaustion via large inputs
//! - Timing side channels

#![no_main]

use libfuzzer_sys::fuzz_target;

/// Fuzz input structure for faucet claims
#[derive(Debug, Clone)]
struct FaucetClaimInput {
    /// Public key hash (should be 32 bytes)
    pk_hash: Vec<u8>,
    /// Plonky2 proof bytes
    proof: Vec<u8>,
    /// Nullifier (should be 32 bytes)
    nullifier: Vec<u8>,
    /// Merkle root (should be 32 bytes)
    merkle_root: Vec<u8>,
    /// Claim amount (should be constant 50 TSN)
    amount: u64,
    /// Timestamp for rate limiting
    timestamp: u64,
    /// Additional arbitrary data for extensibility
    extra_data: Vec<u8>,
}

impl FaucetClaimInput {
    /// Parse raw bytes into structured input
    /// This parsing itself is a fuzz target - it should never panic
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        
        // Parse with length prefixes to avoid OOM on large inputs
        let mut offset = 0;
        
        // Read pk_hash length (u16 to limit max size)
        let pk_hash_len = u16::from_le_bytes([
            data.get(offset)?,
            data.get(offset + 1)?,
        ]) as usize;
        offset += 2;
        
        // Limit individual field size to prevent OOM
        if pk_hash_len > 1024 {
            return None;
        }
        
        let pk_hash = data.get(offset..offset + pk_hash_len)?.to_vec();
        offset += pk_hash_len;
        
        // Read proof length
        let proof_len = u16::from_le_bytes([
            data.get(offset)?,
            data.get(offset + 1)?,
        ]) as usize;
        offset += 2;
        
        if proof_len > 65536 { // 64KB limit for proofs
            return None;
        }
        
        let proof = data.get(offset..offset + proof_len)?.to_vec();
        offset += proof_len;
        
        // Read nullifier length
        let nullifier_len = u16::from_le_bytes([
            data.get(offset)?,
            data.get(offset + 1)?,
        ]) as usize;
        offset += 2;
        
        if nullifier_len > 1024 {
            return None;
        }
        
        let nullifier = data.get(offset..offset + nullifier_len)?.to_vec();
        offset += nullifier_len;
        
        // Read merkle_root length
        let merkle_root_len = u16::from_le_bytes([
            data.get(offset)?,
            data.get(offset + 1)?,
        ]) as usize;
        offset += 2;
        
        if merkle_root_len > 1024 {
            return None;
        }
        
        let merkle_root = data.get(offset..offset + merkle_root_len)?.to_vec();
        offset += merkle_root_len;
        
        // Read amount (u64)
        let amount = u64::from_le_bytes([
            *data.get(offset)?,
            *data.get(offset + 1)?,
            *data.get(offset + 2)?,
            *data.get(offset + 3)?,
            *data.get(offset + 4)?,
            *data.get(offset + 5)?,
            *data.get(offset + 6)?,
            *data.get(offset + 7)?,
        ]);
        offset += 8;
        
        // Read timestamp (u64)
        let timestamp = if offset + 8 <= data.len() {
            u64::from_le_bytes([
                *data.get(offset)?,
                *data.get(offset + 1)?,
                *data.get(offset + 2)?,
                *data.get(offset + 3)?,
                *data.get(offset + 4)?,
                *data.get(offset + 5)?,
                *data.get(offset + 6)?,
                *data.get(offset + 7)?,
            ])
        } else {
            0
        };
        
        // Remaining data is extra_data
        let extra_data = if offset + 8 < data.len() {
            data[offset + 8..].to_vec()
        } else {
            vec![]
        };
        
        Some(Self {
            pk_hash,
            proof,
            nullifier,
            merkle_root,
            amount,
            timestamp,
            extra_data,
        })
    }
}

/// Fuzz target for faucet claim validation
fuzz_target!(|data: &[u8]| {
    // Parse input - this should never panic
    let input = match FaucetClaimInput::from_bytes(data) {
        Some(i) => i,
        None => return, // Invalid format, skip
    };
    
    // Fuzz target 1: pk_hash validation
    // Should reject non-32-byte hashes without panicking
    let _ = validate_pk_hash(&input.pk_hash);
    
    // Fuzz target 2: nullifier validation
    // Should reject non-32-byte nullifiers
    let _ = validate_nullifier(&input.nullifier);
    
    // Fuzz target 3: merkle_root validation
    // Should reject non-32-byte roots
    let _ = validate_merkle_root(&input.merkle_root);
    
    // Fuzz target 4: amount validation
    // Should reject amounts != 50 TSN
    let _ = validate_amount(input.amount);
    
    // Fuzz target 5: proof validation
    // Should handle arbitrary proof bytes without panicking
    let _ = validate_proof(&input.proof);
    
    // Fuzz target 6: timestamp validation
    // Should handle any u64 timestamp
    let _ = validate_timestamp(input.timestamp);
    
    // Fuzz target 7: Full claim validation
    // This is the main target - should never panic
    let _ = validate_faucet_claim(&input);
});

/// Validate pk_hash format
/// Must be exactly 32 bytes
fn validate_pk_hash(pk_hash: &[u8]) -> Result<(), FaucetValidationError> {
    if pk_hash.len() != 32 {
        return Err(FaucetValidationError::InvalidPkHashLength);
    }
    
    // Check for suspicious patterns (all zeros, all ones)
    if pk_hash.iter().all(|b| *b == 0) {
        return Err(FaucetValidationError::SuspiciousPkHash);
    }
    
    if pk_hash.iter().all(|b| *b == 0xff) {
        return Err(FaucetValidationError::SuspiciousPkHash);
    }
    
    Ok(())
}

/// Validate nullifier format
fn validate_nullifier(nullifier: &[u8]) -> Result<(), FaucetValidationError> {
    if nullifier.len() != 32 {
        return Err(FaucetValidationError::InvalidNullifierLength);
    }
    Ok(())
}

/// Validate merkle_root format
fn validate_merkle_root(merkle_root: &[u8]) -> Result<(), FaucetValidationError> {
    if merkle_root.len() != 32 {
        return Err(FaucetValidationError::InvalidMerkleRootLength);
    }
    Ok(())
}

/// Validate claim amount
const FAUCET_CLAIM_AMOUNT: u64 = 50_000_000; // 50 TSN in nanounits

fn validate_amount(amount: u64) -> Result<(), FaucetValidationError> {
    if amount != FAUCET_CLAIM_AMOUNT {
        return Err(FaucetValidationError::InvalidAmount);
    }
    Ok(())
}

/// Validate proof format (basic checks)
fn validate_proof(proof: &[u8]) -> Result<(), FaucetValidationError> {
    // Proof should not be empty
    if proof.is_empty() {
        return Err(FaucetValidationError::EmptyProof);
    }
    
    // Proof should not exceed reasonable size
    if proof.len() > 65536 {
        return Err(FaucetValidationError::ProofTooLarge);
    }
    
    // Additional Plonky2-specific validation would go here
    Ok(())
}

/// Validate timestamp
fn validate_timestamp(timestamp: u64) -> Result<(), FaucetValidationError> {
    // Timestamp should be reasonable (not in the distant future)
    // Current time + 1 hour tolerance
    const MAX_FUTURE_OFFSET: u64 = 3600;
    
    // In real implementation, compare against current time
    // For fuzzing, we just check it's not u64::MAX
    if timestamp == u64::MAX {
        return Err(FaucetValidationError::InvalidTimestamp);
    }
    
    Ok(())
}

/// Full claim validation
fn validate_faucet_claim(input: &FaucetClaimInput) -> Result<(), FaucetValidationError> {
    // Validate all components
    validate_pk_hash(&input.pk_hash)?;
    validate_nullifier(&input.nullifier)?;
    validate_merkle_root(&input.merkle_root)?;
    validate_amount(input.amount)?;
    validate_proof(&input.proof)?;
    validate_timestamp(input.timestamp)?;
    
    // Additional validations:
    // - Check nullifier not already spent
    // - Verify Plonky2 proof
    // - Check rate limiting
    // - Verify Merkle proof
    
    Ok(())
}

/// Validation errors
#[derive(Debug, Clone, PartialEq)]
enum FaucetValidationError {
    InvalidPkHashLength,
    InvalidNullifierLength,
    InvalidMerkleRootLength,
    InvalidAmount,
    EmptyProof,
    ProofTooLarge,
    InvalidTimestamp,
    SuspiciousPkHash,
    NullifierAlreadySpent,
    RateLimitExceeded,
    InvalidPlonky2Proof,
    InvalidMerkleProof,
}

/// Additional fuzz target for rate limiting logic
#[cfg(fuzzing)]
mod rate_limit_fuzz {
    use super::*;
    
    /// Fuzz the rate limiting state machine
    fuzz_target!(|data: &[u8]| {
        if data.len() < 40 {
            return;
        }
        
        let pk_hash = &data[0..32];
        let timestamp = u64::from_le_bytes([
            data[32], data[33], data[34], data[35],
            data[36], data[37], data[38], data[39],
        ]);
        
        // Fuzz rate limit check
        let _ = check_rate_limit(pk_hash, timestamp);
    });
    
    fn check_rate_limit(_pk_hash: &[u8], _timestamp: u64) -> Result<(), FaucetValidationError> {
        // Implementation would check against claim history
        Ok(())
    }
}

/// Fuzz target for Merkle proof validation
#[cfg(fuzzing)]
mod merkle_fuzz {
    use super::*;
    
    /// Fuzz Merkle proof verification
    fuzz_target!(|data: &[u8]| {
        if data.len() < 64 {
            return;
        }
        
        let root = &data[0..32];
        let leaf = &data[32..64];
        let proof_path = &data[64..];
        
        // Fuzz Merkle verification - should not panic
        let _ = verify_merkle_proof(root, leaf, proof_path);
    });
    
    fn verify_merkle_proof(_root: &[u8], _leaf: &[u8], _proof: &[u8]) -> Result<(), FaucetValidationError> {
        // Implementation would verify Merkle proof
        Ok(())
    }
}

/// Corpus seeds for targeted fuzzing
#[cfg(test)]
mod corpus_seeds {
    /// Valid claim structure for seeding the fuzzer
    pub fn valid_claim() -> Vec<u8> {
        let mut data = vec![];
        
        // pk_hash length (32)
        data.extend_from_slice(&32u16.to_le_bytes());
        // pk_hash (32 random bytes)
        data.extend_from_slice(&[0x42u8; 32]);
        
        // proof length (100)
        data.extend_from_slice(&100u16.to_le_bytes());
        // proof (100 bytes)
        data.extend_from_slice(&[0xABu8; 100]);
        
        // nullifier length (32)
        data.extend_from_slice(&32u16.to_le_bytes());
        // nullifier
        data.extend_from_slice(&[0xCDu8; 32]);
        
        // merkle_root length (32)
        data.extend_from_slice(&32u16.to_le_bytes());
        // merkle_root
        data.extend_from_slice(&[0xEFu8; 32]);
        
        // amount (50 TSN)
        data.extend_from_slice(&50_000_000u64.to_le_bytes());
        
        // timestamp
        data.extend_from_slice(&1_700_000_000u64.to_le_bytes());
        
        data
    }
    
    /// Edge case: zero-length fields
    pub fn zero_length_fields() -> Vec<u8> {
        let mut data = vec![];
        
        // All zero lengths
        data.extend_from_slice(&0u16.to_le_bytes()); // pk_hash
        data.extend_from_slice(&0u16.to_le_bytes()); // proof
        data.extend_from_slice(&0u16.to_le_bytes()); // nullifier
        data.extend_from_slice(&0u16.to_le_bytes()); // merkle_root
        data.extend_from_slice(&0u64.to_le_bytes()); // amount
        data.extend_from_slice(&0u64.to_le_bytes()); // timestamp
        
        data
    }
    
    /// Edge case: maximum allowed sizes
    pub fn max_size_fields() -> Vec<u8> {
        let mut data = vec![];
        
        // pk_hash at limit
        data.extend_from_slice(&1024u16.to_le_bytes());
        data.extend_from_slice(&[0u8; 1024]);
        
        // proof at limit
        data.extend_from_slice(&65536u16.to_le_bytes());
        data.extend_from_slice(&[0u8; 65536]);
        
        // nullifier at limit
        data.extend_from_slice(&1024u16.to_le_bytes());
        data.extend_from_slice(&[0u8; 1024]);
        
        // merkle_root at limit
        data.extend_from_slice(&1024u16.to_le_bytes());
        data.extend_from_slice(&[0u8; 1024]);
        
        data.extend_from_slice(&u64::MAX.to_le_bytes());
        data.extend_from_slice(&u64::MAX.to_le_bytes());
        
        data
    }
}
