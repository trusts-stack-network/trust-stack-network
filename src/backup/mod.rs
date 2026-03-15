//! Backup and restore system for TSN critical data.
//!
//! Provides automated backup of Sled databases with:
//! - Compression using zstd
//! - Encryption using ChaCha20Poly1305 (quantum-safe AEAD)
//! - Integrity verification via SHA-256 checksums
//! - Incremental and full backup strategies

use std::path::{Path, PathBuf};
use std::fs;
use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, AeadCore, KeyInit},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn, error, debug};

pub mod manager;
pub mod crypto;
pub mod integrity;
pub mod scheduler;

pub use manager::BackupManager;
pub use crypto::{BackupEncryption, EncryptionConfig};
pub use integrity::{IntegrityChecker, ChecksumAlgorithm};
pub use scheduler::{BackupScheduler, BackupSchedule};

/// Errors that can occur during backup/restore operations.
#[derive(Error, Debug)]
pub enum BackupError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Encryption error: {0}")]
    Encryption(String),
    
    #[error("Integrity check failed: {0}")]
    IntegrityCheckFailed(String),
    
    #[error("Backup not found: {0}")]
    BackupNotFound(PathBuf),
    
    #[error("Invalid backup format: {0}")]
    InvalidFormat(String),
    
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("Compression error: {0}")]
    Compression(String),
    
    #[error("Schedule error: {0}")]
    Schedule(String),
}

/// Type of backup operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupType {
    /// Full backup of all data.
    Full,
    /// Incremental backup (only changed data since last backup).
    Incremental,
    /// Differential backup (changes since last full backup).
    Differential,
}

impl Default for BackupType {
    fn default() -> Self {
        BackupType::Full
    }
}

impl std::fmt::Display for BackupType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackupType::Full => write!(f, "full"),
            BackupType::Incremental => write!(f, "incremental"),
            BackupType::Differential => write!(f, "differential"),
        }
    }
}

/// Metadata for a backup archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    /// Unique identifier for this backup.
    pub id: String,
    /// Type of backup.
    pub backup_type: BackupType,
    /// Timestamp when backup was created.
    pub created_at: u64,
    /// Block height at time of backup (if available).
    pub block_height: Option<u64>,
    /// Network name (e.g., "tsn-mainnet").
    pub network: String,
    /// Version of the backup format.
    pub format_version: u32,
    /// List of backed up components.
    pub components: Vec<ComponentInfo>,
    /// Size of uncompressed data in bytes.
    pub uncompressed_size: u64,
    /// Size of compressed data in bytes.
    pub compressed_size: u64,
    /// Encryption algorithm used.
    pub encryption: Option<String>,
    /// Compression algorithm used.
    pub compression: String,
    /// Parent backup ID (for incremental/differential).
    pub parent_backup: Option<String>,
}

impl BackupMetadata {
    /// Create new backup metadata.
    pub fn new(backup_type: BackupType, network: impl Into<String>) -> Self {
        let id = format!("{}_{}", 
            backup_type,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );
        
        Self {
            id,
            backup_type,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            block_height: None,
            network: network.into(),
            format_version: 1,
            components: Vec::new(),
            uncompressed_size: 0,
            compressed_size: 0,
            encryption: None,
            compression: "zstd".to_string(),
            parent_backup: None,
        }
    }
    
    /// Calculate compression ratio.
    pub fn compression_ratio(&self) -> f64 {
        if self.uncompressed_size == 0 {
            1.0
        } else {
            self.compressed_size as f64 / self.uncompressed_size as f64
        }
    }
    
    /// Get human-readable size.
    pub fn size_human(&self) -> String {
        format_size(self.compressed_size)
    }
}

/// Information about a backed up component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentInfo {
    /// Name of the component (e.g., "blocks", "accounts").
    pub name: String,
    /// Path relative to backup root.
    pub path: PathBuf,
    /// SHA-256 checksum of original data.
    pub checksum: String,
    /// Size in bytes.
    pub size: u64,
    /// Number of entries (if applicable).
    pub entry_count: Option<u64>,
}

/// Configuration for backup operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Directory where backups are stored.
    pub backup_dir: PathBuf,
    /// Directory containing Sled databases.
    pub data_dir: PathBuf,
    /// Maximum number of backups to keep (rotation).
    pub max_backups: usize,
    /// Minimum free space required (in bytes).
    pub min_free_space: u64,
    /// Whether to compress backups.
    pub compression_enabled: bool,
    /// Compression level (1-22 for zstd).
    pub compression_level: i32,
    /// Whether to encrypt backups.
    pub encryption_enabled: bool,
    /// Encryption key file path (if not using environment).
    pub encryption_key_file: Option<PathBuf>,
    /// Components to backup.
    pub components: Vec<String>,
    /// Verify backup after creation.
    pub verify_after_backup: bool,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            backup_dir: PathBuf::from("./backups"),
            data_dir: PathBuf::from("./data"),
            max_backups: 10,
            min_free_space: 1024 * 1024 * 1024, // 1 GB
            compression_enabled: true,
            compression_level: 3,
            encryption_enabled: true,
            encryption_key_file: None,
            components: vec![
                "blocks".to_string(),
                "accounts".to_string(),
                "mik".to_string(),
                "merkle_trees".to_string(),
            ],
            verify_after_backup: true,
        }
    }
}

impl BackupConfig {
    /// Load configuration from file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, BackupError> {
        let content = fs::read_to_string(path)?;
        let config: Self = serde_json::from_str(&content)?;
        Ok(config)
    }
    
    /// Save configuration to file.
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), BackupError> {
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }
    
    /// Validate configuration.
    pub fn validate(&self) -> Result<(), BackupError> {
        if !self.data_dir.exists() {
            return Err(BackupError::InvalidFormat(
                format!("Data directory does not exist: {:?}", self.data_dir)
            ));
        }
        
        if self.max_backups == 0 {
            return Err(BackupError::InvalidFormat(
                "max_backups must be greater than 0".to_string()
            ));
        }
        
        if self.compression_level < 1 || self.compression_level > 22 {
            return Err(BackupError::InvalidFormat(
                "compression_level must be between 1 and 22".to_string()
            ));
        }
        
        Ok(())
    }
}

/// Result of a backup operation.
#[derive(Debug, Clone)]
pub struct BackupResult {
    /// Path to the created backup.
    pub backup_path: PathBuf,
    /// Metadata of the backup.
    pub metadata: BackupMetadata,
    /// Duration of the operation in seconds.
    pub duration_secs: u64,
}

/// Result of a restore operation.
#[derive(Debug, Clone)]
pub struct RestoreResult {
    /// Path where data was restored.
    pub restored_to: PathBuf,
    /// Metadata of the restored backup.
    pub metadata: BackupMetadata,
    /// Duration of the operation in seconds.
    pub duration_secs: u64,
    /// Components that were restored.
    pub restored_components: Vec<String>,
}

/// Format a size in bytes to human-readable string.
pub fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }
    
    format!("{:.2} {}", size, UNITS[unit_index])
}

/// Ensure directory exists, creating it if necessary.
pub fn ensure_dir<P: AsRef<Path>>(path: P) -> Result<(), BackupError> {
    let path = path.as_ref();
    if !path.exists() {
        fs::create_dir_all(path)?;
        debug!("Created directory: {:?}", path);
    }
    Ok(())
}

/// Get available disk space at path.
pub fn available_space<P: AsRef<Path>>(path: P) -> Result<u64, BackupError> {
    // This is a simplified version - in production would use sysinfo or similar
    // For now, return a large value
    Ok(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_backup_type_display() {
        assert_eq!(BackupType::Full.to_string(), "full");
        assert_eq!(BackupType::Incremental.to_string(), "incremental");
        assert_eq!(BackupType::Differential.to_string(), "differential");
    }
    
    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0.00 B");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1024 * 1024), "1.00 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.00 GB");
    }
    
    #[test]
    fn test_backup_metadata_compression_ratio() {
        let mut metadata = BackupMetadata::new(BackupType::Full, "tsn-test");
        metadata.uncompressed_size = 1000;
        metadata.compressed_size = 500;
        assert_eq!(metadata.compression_ratio(), 0.5);
        
        metadata.uncompressed_size = 0;
        assert_eq!(metadata.compression_ratio(), 1.0);
    }
}
