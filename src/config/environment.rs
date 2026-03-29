//! Environment types and configuration profiles
//!
//! Defines the different deployment environments for TSN:
//! - Dev: Local development, debugging enabled, relaxed security
//! - Staging: Pre-production testing, mirrors mainnet config
//! - Mainnet: Production, strict security, no debug features

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Deployment environment types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    /// Development environment - local testing, debug features enabled
    Dev,
    /// Staging environment - pre-production, mirrors mainnet
    Staging,
    /// Mainnet production environment - strict security
    Mainnet,
}

impl Environment {
    /// Returns true if this is a production environment (mainnet)
    pub const fn is_production(&self) -> bool {
        matches!(self, Environment::Mainnet)
    }

    /// Returns true if debug features should be enabled
    pub const fn debug_enabled(&self) -> bool {
        matches!(self, Environment::Dev)
    }

    /// Returns true if detailed logging should be enabled
    pub const fn verbose_logging(&self) -> bool {
        matches!(self, Environment::Dev | Environment::Staging)
    }

    /// Returns the default configuration file name for this environment
    pub const fn config_file(&self) -> &'static str {
        match self {
            Environment::Dev => "dev.yaml",
            Environment::Staging => "staging.yaml",
            Environment::Mainnet => "mainnet.yaml",
        }
    }

    /// Returns the network name for this environment
    pub const fn network_name(&self) -> &'static str {
        match self {
            Environment::Dev => "tsn-devnet",
            Environment::Staging => "tsn-staging",
            Environment::Mainnet => "tsn-mainnet",
        }
    }

    /// Minimum number of confirmations required for transactions
    pub const fn min_confirmations(&self) -> u32 {
        match self {
            Environment::Dev => 1,
            Environment::Staging => 6,
            Environment::Mainnet => 12,
        }
    }

    /// Block time target in seconds
    pub const fn block_time_target(&self) -> u64 {
        match self {
            Environment::Dev => 30,      // 30 seconds for fast testing
            Environment::Staging => 120, // 2 minutes
            Environment::Mainnet => 600, // 10 minutes
        }
    }

    /// Maximum peers to connect to
    pub const fn max_peers(&self) -> usize {
        match self {
            Environment::Dev => 8,
            Environment::Staging => 50,
            Environment::Mainnet => 125,
        }
    }

    /// Rate limit: requests per minute per IP
    pub const fn rate_limit_per_minute(&self) -> u32 {
        match self {
            Environment::Dev => 1000,    // Relaxed for testing
            Environment::Staging => 300, // Moderate
            Environment::Mainnet => 120, // Strict
        }
    }

    /// Returns true if hot-reload is allowed
    pub const fn hot_reload_allowed(&self) -> bool {
        !self.is_production()
    }

    /// Returns true if cryptographic parameters can be modified at runtime
    pub const fn crypto_params_mutable(&self) -> bool {
        matches!(self, Environment::Dev)
    }
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Environment::Dev => write!(f, "dev"),
            Environment::Staging => write!(f, "staging"),
            Environment::Mainnet => write!(f, "mainnet"),
        }
    }
}

impl FromStr for Environment {
    type Err = EnvironmentError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "dev" | "development" | "local" => Ok(Environment::Dev),
            "staging" | "test" | "preprod" => Ok(Environment::Staging),
            "mainnet" | "prod" | "production" => Ok(Environment::Mainnet),
            _ => Err(EnvironmentError::InvalidEnvironment(s.to_string())),
        }
    }
}

impl Default for Environment {
    fn default() -> Self {
        Environment::Dev
    }
}

/// Errors related to environment handling
#[derive(Debug, Clone, PartialEq)]
pub enum EnvironmentError {
    InvalidEnvironment(String),
    UnsupportedEnvironment(String),
}

impl fmt::Display for EnvironmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvironmentError::InvalidEnvironment(s) => {
                write!(f, "Invalid environment: '{}'. Use: dev, staging, mainnet", s)
            }
            EnvironmentError::UnsupportedEnvironment(s) => {
                write!(f, "Environment '{}' is not supported in this build", s)
            }
        }
    }
}

impl std::error::Error for EnvironmentError {}

/// Detect environment from environment variables
/// Priority: TSN_ENV > RUST_ENV > default (dev)
pub fn detect_environment() -> Environment {
    std::env::var("TSN_ENV")
        .or_else(|_| std::env::var("RUST_ENV"))
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_default()
}

/// Get environment from string or panic with helpful message
pub fn require_environment() -> Environment {
    let env = detect_environment();
    tracing::info!("Running in {} environment", env);
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment_parsing() {
        assert_eq!("dev".parse::<Environment>().unwrap(), Environment::Dev);
        assert_eq!("staging".parse::<Environment>().unwrap(), Environment::Staging);
        assert_eq!("mainnet".parse::<Environment>().unwrap(), Environment::Mainnet);
        assert!("invalid".parse::<Environment>().is_err());
    }

    #[test]
    fn test_environment_properties() {
        assert!(!Environment::Dev.is_production());
        assert!(!Environment::Staging.is_production());
        assert!(Environment::Mainnet.is_production());

        assert!(Environment::Dev.debug_enabled());
        assert!(!Environment::Staging.debug_enabled());
        assert!(!Environment::Mainnet.debug_enabled());
    }

    #[test]
    fn test_environment_display() {
        assert_eq!(Environment::Dev.to_string(), "dev");
        assert_eq!(Environment::Staging.to_string(), "staging");
        assert_eq!(Environment::Mainnet.to_string(), "mainnet");
    }
}
