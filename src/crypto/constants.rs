//! Cryptographic constants for TSN blockchain
//!
//! This module contains all domain separators and cryptographic constants
//! used throughout the TSN protocol. Centralizing these prevents
//! divergence and ensures consistent security properties.

// ============================================================================
// Domain Separators for Key Derivation
// ============================================================================

/// Domain separator for treasury key derivation.
/// Derived from "TSN_TREASURY" in ASCII.
/// Used to deterministically derive treasury keys from node entropy.
pub const DOMAIN_TREASURY: &[u8] = b"TSN_TREASURY";

/// Domain separator for API authentication keys.
/// Derived from "TSN_API_AUTH" in ASCII.
/// Used for JWT signing key derivation.
pub const DOMAIN_API_AUTH: &[u8] = b"TSN_API_AUTH";

/// Domain separator for rate limiting bucket keys.
/// Derived from "TSN_RATE_LIMIT" in ASCII.
pub const DOMAIN_RATE_LIMIT: &[u8] = b"TSN_RATE_LIMIT";

/// Domain separator for audit log integrity.
/// Derived from "TSN_AUDIT_LOG" in ASCII.
pub const DOMAIN_AUDIT_LOG: &[u8] = b"TSN_AUDIT_LOG";

// ============================================================================
// JWT Configuration Constants
// ============================================================================

/// Default JWT expiration time in seconds (1 hour).
pub const JWT_DEFAULT_EXPIRATION_SECONDS: u64 = 3600;

/// Maximum JWT expiration time in seconds (24 hours).
pub const JWT_MAX_EXPIRATION_SECONDS: u64 = 86400;

/// Minimum JWT expiration time in seconds (5 minutes).
pub const JWT_MIN_EXPIRATION_SECONDS: u64 = 300;

/// JWT issuer claim value.
pub const JWT_ISSUER: &str = "tsn-node";

/// JWT audience claim value for API access.
pub const JWT_AUDIENCE_API: &str = "tsn-api";

/// JWT audience claim value for explorer access.
pub const JWT_AUDIENCE_EXPLORER: &str = "tsn-explorer";

// ============================================================================
// Rate Limiting Constants
// ============================================================================

/// Default requests per minute for authenticated users.
pub const RATE_LIMIT_AUTHENTICATED_RPM: u32 = 120;

/// Default requests per minute for unauthenticated users.
pub const RATE_LIMIT_UNAUTHENTICATED_RPM: u32 = 30;

/// Burst allowance for rate limiting (additional requests allowed temporarily).
pub const RATE_LIMIT_BURST: u32 = 10;

/// Rate limit window size in seconds.
pub const RATE_LIMIT_WINDOW_SECONDS: u64 = 60;

/// Cooldown period after rate limit exceeded (in seconds).
pub const RATE_LIMIT_COOLDOWN_SECONDS: u64 = 300;

// ============================================================================
// API Security Constants
// ============================================================================

/// Maximum API request body size in bytes (1 MB).
pub const API_MAX_BODY_SIZE: usize = 1_048_576;

/// Maximum API header size in bytes (16 KB).
pub const API_MAX_HEADER_SIZE: usize = 16_384;

/// API key length in bytes (32 bytes = 256 bits).
pub const API_KEY_LENGTH: usize = 32;

/// Maximum failed authentication attempts before temporary lockout.
pub const API_MAX_FAILED_AUTH_ATTEMPTS: u32 = 5;

/// Lockout duration after max failed attempts (in seconds).
pub const API_LOCKOUT_DURATION_SECONDS: u64 = 900;

// ============================================================================
// Audit Constants
// ============================================================================

/// Maximum audit log entry size in bytes.
pub const AUDIT_MAX_ENTRY_SIZE: usize = 4096;

/// Audit log retention period in days.
pub const AUDIT_RETENTION_DAYS: u32 = 90;

/// Audit log batch size for writing.
pub const AUDIT_BATCH_SIZE: usize = 100;
