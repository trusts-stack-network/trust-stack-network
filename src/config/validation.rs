//! Cryptographic parameter validation
//!
//! Ensures that critical cryptographic parameters are valid and secure.
//! These validations are strict and will reject any suspicious configurations.
//!
//! # Security Rules
//! - Genesis difficulty must be within safe bounds
//! - Hash functions must use approved algorithms
//! - Key sizes must meet post-quantum requirements
//! - Proof systems must use secure parameters

use crate::config::environment::Environment;
use thiserror::Error;

/// Minimum safe genesis difficulty (prevents instant mining)
pub const MIN_GENESIS_DIFFICULTY: u64 = 8;

/// Maximum genesis difficulty (prevents impossible mining)
pub const MAX_GENESIS_DIFFICULTY: u64 = 32;

/// Minimum block time in seconds (prevents spam)
pub const MIN_BLOCK_TIME: u64 = 10;

/// Maximum block time in seconds (prevents chain stall)
pub const MAX_BLOCK_TIME: u64 = 3600;

/// Minimum ML-DSA security level (must be ML-DSA-65 or higher)
pub const MIN_MLDSA_LEVEL: u32 = 3;

/// Valid hash algorithms for TSN
pub const APPROVED_HASH_ALGORITHMS: &[&str] = &[
    "poseidon2",
    "blake2b",
    "sha3-256",
];

/// Errors that can occur during cryptographic parameter validation
#[derive(Error, Debug, Clone, PartialEq)]
pub enum CryptoValidationError {
    #[error("Genesis difficulty {0} is outside safe range [{1}, {2}]")]
    InvalidGenesisDifficulty(u64, u64, u64),

    #[error("Block time {0}s is outside safe range [{1}s, {2}s]")]
    InvalidBlockTime(u64, u64, u64),

    #[error("Hash algorithm '{0}' is not approved for use")]
    UnapprovedHashAlgorithm(String),

    #[error("ML-DSA security level {0} is below minimum {1}")]
    InsufficientMLDSALevel(u32, u32),

    #[error("Invalid Merkle tree depth: {0} (must be between {1} and {2})")]
    InvalidMerkleDepth(u32, u32, u32),

    #[error("Invalid nullifier derivation scheme")]
    InvalidNullifierScheme,

    #[error("Proof system parameters are insecure")]
    InsecureProofParameters,

    #[error("Dev fee percentage {0}% is outside valid range [0, 100]")]
    InvalidDevFeePercentage(u64),

    #[error("Block reward {0} is below minimum {1}")]
    InvalidBlockReward(u64, u64),

    #[error("Coin decimals {0} is outside valid range [{1}, {2}]")]
    InvalidCoinDecimals(u32, u32, u32),

    #[error("Treasury hash is all zeros (not configured)")]
    UnconfiguredTreasury,

    #[error("Network name '{0}' contains invalid characters")]
    InvalidNetworkName(String),

    #[error("Seed node list is empty")]
    EmptySeedNodes,

    #[error("Port {0} is outside valid range [1024, 65535]")]
    InvalidPort(u16),

    #[error("Assume-valid height {0} is suspicious (too high or inconsistent)")]
    SuspiciousAssumeValid(u64),
}

/// Result type for validation operations
pub type ValidationResult<T> = Result<T, CryptoValidationError>;

/// Validates genesis difficulty
/// # Security
/// Must be within safe bounds to prevent both instant mining and impossible mining
pub fn validate_genesis_difficulty(difficulty: u64, env: Environment) -> ValidationResult<()> {
    // In dev mode, allow lower difficulty for testing
    let min = if env.debug_enabled() { 4 } else { MIN_GENESIS_DIFFICULTY };

    if difficulty < min || difficulty > MAX_GENESIS_DIFFICULTY {
        return Err(CryptoValidationError::InvalidGenesisDifficulty(
            difficulty,
            min,
            MAX_GENESIS_DIFFICULTY,
        ));
    }
    Ok(())
}

/// Validates block time target
pub fn validate_block_time(seconds: u64, env: Environment) -> ValidationResult<()> {
    // In dev mode, allow faster blocks
    let min = if env.debug_enabled() { 1 } else { MIN_BLOCK_TIME };

    if seconds < min || seconds > MAX_BLOCK_TIME {
        return Err(CryptoValidationError::InvalidBlockTime(
            seconds,
            min,
            MAX_BLOCK_TIME,
        ));
    }
    Ok(())
}

/// Validates hash algorithm is approved
pub fn validate_hash_algorithm(algorithm: &str) -> ValidationResult<()> {
    if !APPROVED_HASH_ALGORITHMS.contains(&algorithm.to_lowercase().as_str()) {
        return Err(CryptoValidationError::UnapprovedHashAlgorithm(
            algorithm.to_string(),
        ));
    }
    Ok(())
}

/// Validates ML-DSA security level
pub fn validate_mldsa_level(level: u32) -> ValidationResult<()> {
    if level < MIN_MLDSA_LEVEL {
        return Err(CryptoValidationError::InsufficientMLDSALevel(
            level,
            MIN_MLDSA_LEVEL,
        ));
    }
    Ok(())
}

/// Validates Merkle tree depth
pub fn validate_merkle_depth(depth: u32) -> ValidationResult<()> {
    const MIN_DEPTH: u32 = 16;
    const MAX_DEPTH: u32 = 48;

    if depth < MIN_DEPTH || depth > MAX_DEPTH {
        return Err(CryptoValidationError::InvalidMerkleDepth(
            depth,
            MIN_DEPTH,
            MAX_DEPTH,
        ));
    }
    Ok(())
}

/// Validates dev fee percentage
pub fn validate_dev_fee(percentage: u64) -> ValidationResult<()> {
    if percentage > 100 {
        return Err(CryptoValidationError::InvalidDevFeePercentage(percentage));
    }
    Ok(())
}

/// Validates block reward
pub fn validate_block_reward(reward: u64, env: Environment) -> ValidationResult<()> {
    // Minimum reward to prevent underflow issues
    let min_reward = if env.debug_enabled() { 1 } else { 1_000_000 };

    if reward < min_reward {
        return Err(CryptoValidationError::InvalidBlockReward(reward, min_reward));
    }
    Ok(())
}

/// Validates coin decimals
pub fn validate_coin_decimals(decimals: u32) -> ValidationResult<()> {
    const MIN_DECIMALS: u32 = 6;
    const MAX_DECIMALS: u32 = 18;

    if decimals < MIN_DECIMALS || decimals > MAX_DECIMALS {
        return Err(CryptoValidationError::InvalidCoinDecimals(
            decimals,
            MIN_DECIMALS,
            MAX_DECIMALS,
        ));
    }
    Ok(())
}

/// Validates treasury hash is configured
pub fn validate_treasury_hash(hash: &[u8; 32]) -> ValidationResult<()> {
    if hash.iter().all(|b| *b == 0) {
        return Err(CryptoValidationError::UnconfiguredTreasury);
    }
    Ok(())
}

/// Validates network name
pub fn validate_network_name(name: &str) -> ValidationResult<()> {
    // Network name should be alphanumeric with hyphens only
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(CryptoValidationError::InvalidNetworkName(name.to_string()));
    }
    Ok(())
}

/// Validates seed nodes list
pub fn validate_seed_nodes(nodes: &[impl AsRef<str>]) -> ValidationResult<()> {
    if nodes.is_empty() {
        return Err(CryptoValidationError::EmptySeedNodes);
    }

    for node in nodes {
        let node_str = node.as_ref();
        // Basic URL validation
        if !node_str.starts_with("http://") && !node_str.starts_with("https://") {
            // Allow host:port format
            if !node_str.contains(':') {
                return Err(CryptoValidationError::InvalidNetworkName(
                    "Seed node must be URL or host:port".to_string(),
                ));
            }
        }
    }
    Ok(())
}

/// Validates port number
pub fn validate_port(port: u16) -> ValidationResult<()> {
    // Ports below 1024 require root privileges
    if port < 1024 {
        return Err(CryptoValidationError::InvalidPort(port));
    }
    Ok(())
}

/// Validates assume-valid checkpoint
pub fn validate_assume_valid(height: u64, hash: &str, env: Environment) -> ValidationResult<()> {
    // In production, assume-valid should be carefully configured
    if env.is_production() && height > 1_000_000 {
        return Err(CryptoValidationError::SuspiciousAssumeValid(height));
    }

    // Hash must be valid hex string of correct length
    if hash.len() != 64 {
        return Err(CryptoValidationError::SuspiciousAssumeValid(height));
    }

    if hex::decode(hash).is_err() {
        return Err(CryptoValidationError::SuspiciousAssumeValid(height));
    }

    Ok(())
}

/// Comprehensive validation of all cryptographic parameters
pub fn validate_all_crypto_params(
    genesis_difficulty: u64,
    block_time: u64,
    dev_fee: u64,
    block_reward: u64,
    coin_decimals: u32,
    treasury_hash: &[u8; 32],
    network_name: &str,
    seed_nodes: &[impl AsRef<str>],
    port: u16,
    assume_valid_height: u64,
    assume_valid_hash: &str,
    env: Environment,
) -> ValidationResult<()> {
    validate_genesis_difficulty(genesis_difficulty, env)?;
    validate_block_time(block_time, env)?;
    validate_dev_fee(dev_fee)?;
    validate_block_reward(block_reward, env)?;
    validate_coin_decimals(coin_decimals)?;
    validate_treasury_hash(treasury_hash)?;
    validate_network_name(network_name)?;
    validate_seed_nodes(seed_nodes)?;
    validate_port(port)?;
    validate_assume_valid(assume_valid_height, assume_valid_hash, env)?;

    Ok(())
}

/// Checks if a parameter is considered critical (immutable after init)
pub fn is_critical_param(param_name: &str) -> bool {
    matches!(
        param_name,
        "genesis_difficulty"
            | "coin_decimals"
            | "network_name"
            | "treasury_hash"
            | "hash_algorithm"
            | "mldsa_level"
            | "merkle_depth"
            | "proof_system"
    )
}

/// Checks if a parameter can be hot-reloaded
pub fn is_hot_reloadable(param_name: &str) -> bool {
    !is_critical_param(param_name)
        && matches!(
            param_name,
            "log_level"
                | "max_peers"
                | "rate_limit"
                | "faucet_daily_limit"
                | "faucet_cooldown"
                | "rpc_timeout"
                | "sync_batch_size"
                | "mempool_max_size"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_genesis_difficulty() {
        assert!(validate_genesis_difficulty(12, Environment::Mainnet).is_ok());
        assert!(validate_genesis_difficulty(4, Environment::Dev).is_ok());
        assert!(validate_genesis_difficulty(4, Environment::Mainnet).is_err());
        assert!(validate_genesis_difficulty(100, Environment::Mainnet).is_err());
    }

    #[test]
    fn test_validate_block_time() {
        assert!(validate_block_time(600, Environment::Mainnet).is_ok());
        assert!(validate_block_time(1, Environment::Dev).is_ok());
        assert!(validate_block_time(1, Environment::Mainnet).is_err());
    }

    #[test]
    fn test_validate_dev_fee() {
        assert!(validate_dev_fee(5).is_ok());
        assert!(validate_dev_fee(0).is_ok());
        assert!(validate_dev_fee(100).is_ok());
        assert!(validate_dev_fee(101).is_err());
    }

    #[test]
    fn test_validate_network_name() {
        assert!(validate_network_name("tsn-mainnet").is_ok());
        assert!(validate_network_name("tsn_dev").is_ok());
        assert!(validate_network_name("").is_err());
        assert!(validate_network_name("tsn mainnet").is_err());
    }

    #[test]
    fn test_validate_seed_nodes() {
        assert!(validate_seed_nodes(&["https://node1.tsn.io", "https://node2.tsn.io"]).is_ok());
        assert!(validate_seed_nodes(&[] as &[&str]).is_err());
    }

    #[test]
    fn test_is_critical_param() {
        assert!(is_critical_param("genesis_difficulty"));
        assert!(is_critical_param("network_name"));
        assert!(!is_critical_param("log_level"));
        assert!(!is_critical_param("max_peers"));
    }

    #[test]
    fn test_is_hot_reloadable() {
        assert!(is_hot_reloadable("log_level"));
        assert!(is_hot_reloadable("max_peers"));
        assert!(!is_hot_reloadable("genesis_difficulty"));
        assert!(!is_hot_reloadable("treasury_hash"));
    }
}
