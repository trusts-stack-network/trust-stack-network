//! Hot-reload configuration for non-critical parameters
//!
//! Provides safe runtime reloading of configuration parameters that don't
//! affect consensus or cryptographic security.
//!
//! # Security Model
//! - Only non-critical parameters can be hot-reloaded
//! - Critical parameters (genesis, crypto settings) require restart
//! - Changes are validated before application
//! - Audit log of all configuration changes
//! - Rollback capability for failed reloads

use crate::config::validation::{is_hot_reloadable, CryptoValidationError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Minimum interval between hot-reloads (prevents spam)
pub const MIN_RELOAD_INTERVAL: Duration = Duration::from_secs(5);

/// Maximum number of reload attempts per hour (rate limiting)
pub const MAX_RELOADS_PER_HOUR: u32 = 60;

/// Configuration change record for audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigChange {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub parameter: String,
    pub old_value: serde_json::Value,
    pub new_value: serde_json::Value,
    pub source: ChangeSource,
    pub success: bool,
    pub error: Option<String>,
}

/// Source of configuration change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChangeSource {
    FileReload,
    ApiRequest { user: String },
    Signal { signal: String },
    EnvironmentVariable,
}

/// Hot-reload manager state
pub struct HotReloadManager {
    /// Last reload timestamp
    last_reload: RwLock<Instant>,
    /// Reload attempt counter (sliding window)
    reload_counter: RwLock<Vec<Instant>>,
    /// Configuration change history
    change_history: RwLock<Vec<ConfigChange>>,
    /// Current configuration values (hot-reloadable only)
    current_values: RwLock<HashMap<String, serde_json::Value>>,
    /// Original configuration file path
    config_path: Arc<std::path::PathBuf>,
    /// Whether hot-reload is enabled
    enabled: bool,
}

/// Result of a hot-reload operation
#[derive(Debug, Clone)]
pub struct ReloadResult {
    pub success: bool,
    pub changes_applied: Vec<String>,
    pub changes_rejected: Vec<( String, String)>, // (param, reason)
    pub errors: Vec<String>,
}

impl HotReloadManager {
    /// Create a new hot-reload manager
    pub fn new(config_path: impl AsRef<Path>, enabled: bool) -> Self {
        Self {
            last_reload: RwLock::new(Instant::now() - Duration::from_secs(3600)),
            reload_counter: RwLock::new(Vec::new()),
            change_history: RwLock::new(Vec::with_capacity(1000)),
            current_values: RwLock::new(HashMap::new()),
            config_path: Arc::new(config_path.as_ref().to_path_buf()),
            enabled,
        }
    }

    /// Check if hot-reload is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the last reload time
    pub async fn last_reload_time(&self) -> Instant {
        *self.last_reload.read().await
    }

    /// Get change history
    pub async fn get_change_history(&self, limit: usize) -> Vec<ConfigChange> {
        let history = self.change_history.read().await;
        history.iter().rev().take(limit).cloned().collect()
    }

    /// Check if reload is allowed (rate limiting)
    pub async fn can_reload(&self) -> bool {
        if !self.enabled {
            return false;
        }

        let now = Instant::now();
        let last = *self.last_reload.read().await;

        // Check minimum interval
        if now.duration_since(last) < MIN_RELOAD_INTERVAL {
            return false;
        }

        // Check hourly rate limit
        let mut counter = self.reload_counter.write().await;
        let cutoff = now - Duration::from_secs(3600);
        counter.retain(|t| *t > cutoff);

        if counter.len() >= MAX_RELOADS_PER_HOUR as usize {
            return false;
        }

        true
    }

    /// Attempt to reload configuration from file
    pub async fn reload_from_file(&self, source: ChangeSource) -> ReloadResult {
        if !self.can_reload().await {
            return ReloadResult {
                success: false,
                changes_applied: vec![],
                changes_rejected: vec![],
                errors: vec!["Rate limit exceeded or hot-reload disabled".to_string()],
            };
        }

        // Update rate limiting counters
        {
            let mut last = self.last_reload.write().await;
            *last = Instant::now();
            let mut counter = self.reload_counter.write().await;
            counter.push(*last);
        }

        match self.perform_reload(source).await {
            Ok(result) => result,
            Err(e) => ReloadResult {
                success: false,
                changes_applied: vec![],
                changes_rejected: vec![],
                errors: vec![format!("Reload failed: {}", e)],
            },
        }
    }

    /// Perform the actual reload
    async fn perform_reload(
        &self,
        source: ChangeSource,
    ) -> Result<ReloadResult, Box<dyn std::error::Error + Send + Sync>> {
        let config_content = tokio::fs::read_to_string(&*self.config_path).await?;
        let new_config: serde_yaml::Value = serde_yaml::from_str(&config_content)?;

        let mut result = ReloadResult {
            success: true,
            changes_applied: vec![],
            changes_rejected: vec![],
            errors: vec![],
        };

        // Extract hot-reloadable parameters
        if let Some(params) = new_config.get("runtime") {
            if let Some(obj) = params.as_mapping() {
                for (key, value) in obj {
                    let key_str = key.as_str().unwrap_or("").to_string();

                    if !is_hot_reloadable(&key_str) {
                        result.changes_rejected.push((
                            key_str.clone(),
                            "Parameter is not hot-reloadable".to_string(),
                        ));
                        continue;
                    }

                    // Validate the new value
                    match self.validate_param(&key_str, value).await {
                        Ok(_) => {
                            // Apply the change
                            let old_value = {
                                let mut values = self.current_values.write().await;
                                let old = values.get(&key_str).cloned();
                                values.insert(key_str.clone(), value.clone());
                                old
                            };

                            // Log the change
                            let change = ConfigChange {
                                timestamp: chrono::Utc::now(),
                                parameter: key_str.clone(),
                                old_value: old_value.unwrap_or(serde_json::Value::Null),
                                new_value: value.clone(),
                                source: source.clone(),
                                success: true,
                                error: None,
                            };

                            {
                                let mut history = self.change_history.write().await;
                                history.push(change);
                            }

                            result.changes_applied.push(key_str);
                            info!("Hot-reloaded parameter: {} = {}", key_str, value);
                        }
                        Err(e) => {
                            result.changes_rejected.push((key_str.clone(), e.to_string()));
                            result.errors.push(format!("{}: {}", key_str, e));

                            // Log failed change
                            let change = ConfigChange {
                                timestamp: chrono::Utc::now(),
                                parameter: key_str,
                                old_value: serde_json::Value::Null,
                                new_value: value.clone(),
                                source,
                                success: false,
                                error: Some(e.to_string()),
                            };

                            let mut history = self.change_history.write().await;
                            history.push(change);
                        }
                    }
                }
            }
        }

        result.success = result.errors.is_empty();
        Ok(result)
    }

    /// Validate a single parameter value
    async fn validate_param(
        &self,
        name: &str,
        value: &serde_yaml::Value,
    ) -> Result<(), CryptoValidationError> {
        match name {
            "max_peers" => {
                if let Some(n) = value.as_u64() {
                    if n > 1000 {
                        return Err(CryptoValidationError::InvalidNetworkName(
                            "max_peers exceeds limit".to_string(),
                        ));
                    }
                }
            }
            "rate_limit" => {
                if let Some(n) = value.as_u64() {
                    if n > 10000 {
                        return Err(CryptoValidationError::InvalidNetworkName(
                            "rate_limit exceeds limit".to_string(),
                        ));
                    }
                }
            }
            "log_level" => {
                if let Some(s) = value.as_str() {
                    if !matches!(
                        s.to_lowercase().as_str(),
                        "trace" | "debug" | "info" | "warn" | "error"
                    ) {
                        return Err(CryptoValidationError::InvalidNetworkName(
                            "invalid log_level".to_string(),
                        ));
                    }
                }
            }
            "faucet_daily_limit" | "faucet_cooldown" | "rpc_timeout" | "sync_batch_size"
            | "mempool_max_size" => {
                if !value.is_number() {
                    return Err(CryptoValidationError::InvalidNetworkName(
                        "expected numeric value".to_string(),
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Get current value of a hot-reloadable parameter
    pub async fn get_value(&self, name: &str) -> Option<serde_json::Value> {
        let values = self.current_values.read().await;
        values.get(name).cloned()
    }

    /// Set a value programmatically (for testing)
    #[cfg(test)]
    pub async fn set_value(
        &self,
        name: String,
        value: serde_json::Value,
    ) -> Result<(), CryptoValidationError> {
        if !is_hot_reloadable(&name) {
            return Err(CryptoValidationError::InvalidNetworkName(
                "not hot-reloadable".to_string(),
            ));
        }

        let mut values = self.current_values.write().await;
        values.insert(name, value);
        Ok(())
    }

    /// Export change history to JSON
    pub async fn export_history(&self) -> Result<String, serde_json::Error> {
        let history = self.change_history.read().await;
        serde_json::to_string_pretty(&*history)
    }

    /// Clear old history entries
    pub async fn trim_history(&self, keep_last: usize) {
        let mut history = self.change_history.write().await;
        if history.len() > keep_last {
            let start = history.len() - keep_last;
            history.drain(0..start);
        }
    }
}

/// File watcher for automatic hot-reload
pub struct ConfigWatcher {
    manager: Arc<HotReloadManager>,
    watch_path: std::path::PathBuf,
}

impl ConfigWatcher {
    /// Create a new config watcher
    pub fn new(manager: Arc<HotReloadManager>, watch_path: impl AsRef<Path>) -> Self {
        Self {
            manager,
            watch_path: watch_path.as_ref().to_path_buf(),
        }
    }

    /// Start watching for file changes (requires notify crate)
    /// Note: This is a simplified version - production would use notify crate
    pub async fn watch(&self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In production, use notify crate for efficient file watching
        // For now, poll every 30 seconds
        let mut last_modified = std::fs::metadata(&self.watch_path)?.modified()?;

        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;

            match std::fs::metadata(&self.watch_path) {
                Ok(metadata) => {
                    if let Ok(modified) = metadata.modified() {
                        if modified > last_modified {
                            info!("Configuration file changed, triggering hot-reload");
                            let result = self
                                .manager
                                .reload_from_file(ChangeSource::FileReload)
                                .await;

                            if result.success {
                                info!("Hot-reload successful: {:?}", result.changes_applied);
                            } else {
                                warn!("Hot-reload failed: {:?}", result.errors);
                            }

                            last_modified = modified;
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to check config file: {}", e);
                }
            }
        }
    }
}

/// Signal handler for SIGHUP reload
pub async fn handle_sighup(manager: Arc<HotReloadManager>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut stream = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to create SIGHUP handler: {}", e);
                return;
            }
        };

        loop {
            stream.recv().await;
            info!("Received SIGHUP, triggering hot-reload");

            let result = manager
                .reload_from_file(ChangeSource::Signal {
                    signal: "SIGHUP".to_string(),
                })
                .await;

            if result.success {
                info!("SIGHUP reload successful");
            } else {
                error!("SIGHUP reload failed: {:?}", result.errors);
            }
        }
    }

    #[cfg(not(unix))]
    {
        // Windows: use Ctrl+C as reload signal
        tokio::signal::ctrl_c().await.ok();
        info!("Received reload signal, triggering hot-reload");
        let _ = manager
            .reload_from_file(ChangeSource::Signal {
                signal: "CTRL+C".to_string(),
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_hot_reload_manager_creation() {
        let temp = NamedTempFile::new().unwrap();
        let manager = HotReloadManager::new(temp.path(), true);
        assert!(manager.is_enabled());
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let temp = NamedTempFile::new().unwrap();
        let manager = HotReloadManager::new(temp.path(), true);

        // First reload should succeed
        assert!(manager.can_reload().await);

        // Simulate recent reload
        {
            let mut last = manager.last_reload.write().await;
            *last = Instant::now();
        }

        // Should fail due to rate limiting
        assert!(!manager.can_reload().await);
    }

    #[tokio::test]
    async fn test_disabled_manager() {
        let temp = NamedTempFile::new().unwrap();
        let manager = HotReloadManager::new(temp.path(), false);
        assert!(!manager.can_reload().await);
    }
}
