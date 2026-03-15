//! Configuration management for TSN network monitoring
//!
//! Provides configuration structures and loading mechanisms for the monitoring system.

use std::path::Path;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Complete monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Dashboard configuration
    pub dashboard: DashboardConfig,
    /// Metrics collection configuration
    pub metrics: MetricsConfig,
    /// Alerting configuration
    pub alerts: AlertConfig,
    /// Performance thresholds
    pub thresholds: ThresholdConfig,
}

/// Dashboard-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    /// Enable/disable dashboard
    pub enabled: bool,
    /// Port for dashboard HTTP server
    pub port: u16,
    /// Bind address for dashboard server
    pub bind_address: String,
    /// Update interval for real-time data (seconds)
    pub update_interval_seconds: u32,
    /// Maximum number of data points to keep in memory for charts
    pub max_chart_data_points: usize,
    /// Enable WebSocket for real-time updates
    pub websocket_enabled: bool,
}

/// Metrics collection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable/disable metrics collection
    pub enabled: bool,
    /// Metrics collection interval (seconds)
    pub collection_interval_seconds: u32,
    /// How long to retain metrics in memory (hours)
    pub retention_hours: u32,
    /// Enable Prometheus metrics export
    pub prometheus_enabled: bool,
    /// Prometheus metrics port
    pub prometheus_port: u16,
    /// Enable detailed peer metrics
    pub detailed_peer_metrics: bool,
    /// Enable system resource monitoring
    pub system_metrics_enabled: bool,
}

/// Alerting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Enable/disable alerting
    pub enabled: bool,
    /// Webhook URL for alerts (optional)
    pub webhook_url: Option<String>,
    /// Email configuration for alerts (optional)
    pub email: Option<EmailConfig>,
    /// Alert cooldown period (seconds)
    pub cooldown_seconds: u32,
    /// Maximum alerts per hour
    pub max_alerts_per_hour: u32,
}

/// Email configuration for alerts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    pub smtp_server: String,
    pub smtp_port: u16,
    pub username: String,
    pub password: String,
    pub from_address: String,
    pub to_addresses: Vec<String>,
    pub use_tls: bool,
}

/// Performance and health thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Network performance thresholds
    pub network: NetworkThresholds,
    /// Blockchain sync thresholds
    pub blockchain: BlockchainThresholds,
    /// System resource thresholds
    pub system: SystemThresholds,
    /// Peer connection thresholds
    pub peers: PeerThresholds,
}

/// Network performance thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkThresholds {
    /// Warning threshold for average latency (ms)
    pub latency_warning_ms: f64,
    /// Critical threshold for average latency (ms)
    pub latency_critical_ms: f64,
    /// Warning threshold for message rate (msgs/sec)
    pub message_rate_warning: f64,
    /// Critical threshold for message rate (msgs/sec)
    pub message_rate_critical: f64,
    /// Warning threshold for throughput (bytes/sec)
    pub throughput_warning_bps: u64,
    /// Critical threshold for throughput (bytes/sec)
    pub throughput_critical_bps: u64,
}

/// Blockchain sync thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainThresholds {
    /// Warning threshold for sync lag (blocks)
    pub sync_lag_warning_blocks: u64,
    /// Critical threshold for sync lag (blocks)
    pub sync_lag_critical_blocks: u64,
    /// Warning threshold for mempool size
    pub mempool_size_warning: u32,
    /// Critical threshold for mempool size
    pub mempool_size_critical: u32,
    /// Warning threshold for block time variance (seconds)
    pub block_time_variance_warning_seconds: u64,
}

/// System resource thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemThresholds {
    /// Warning threshold for memory usage (percentage)
    pub memory_usage_warning_percent: f64,
    /// Critical threshold for memory usage (percentage)
    pub memory_usage_critical_percent: f64,
    /// Warning threshold for CPU usage (percentage)
    pub cpu_usage_warning_percent: f64,
    /// Critical threshold for CPU usage (percentage)
    pub cpu_usage_critical_percent: f64,
    /// Warning threshold for disk usage (percentage)
    pub disk_usage_warning_percent: f64,
    /// Critical threshold for disk usage (percentage)
    pub disk_usage_critical_percent: f64,
}

/// Peer connection thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerThresholds {
    /// Minimum number of peers (warning)
    pub min_peers_warning: u32,
    /// Minimum number of peers (critical)
    pub min_peers_critical: u32,
    /// Maximum connection failures before warning
    pub max_connection_failures_warning: u32,
    /// Maximum connection failures before critical
    pub max_connection_failures_critical: u32,
    /// Peer timeout threshold (seconds)
    pub peer_timeout_warning_seconds: u64,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            dashboard: DashboardConfig::default(),
            metrics: MetricsConfig::default(),
            alerts: AlertConfig::default(),
            thresholds: ThresholdConfig::default(),
        }
    }
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 8081,
            bind_address: "0.0.0.0".to_string(),
            update_interval_seconds: 1,
            max_chart_data_points: 300, // 5 minutes at 1s intervals
            websocket_enabled: true,
        }
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            collection_interval_seconds: 1,
            retention_hours: 24,
            prometheus_enabled: true,
            prometheus_port: 9090,
            detailed_peer_metrics: true,
            system_metrics_enabled: true,
        }
    }
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default
            webhook_url: None,
            email: None,
            cooldown_seconds: 300, // 5 minutes
            max_alerts_per_hour: 10,
        }
    }
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            network: NetworkThresholds::default(),
            blockchain: BlockchainThresholds::default(),
            system: SystemThresholds::default(),
            peers: PeerThresholds::default(),
        }
    }
}

impl Default for NetworkThresholds {
    fn default() -> Self {
        Self {
            latency_warning_ms: 100.0,
            latency_critical_ms: 500.0,
            message_rate_warning: 1000.0,
            message_rate_critical: 5000.0,
            throughput_warning_bps: 1_000_000, // 1 MB/s
            throughput_critical_bps: 10_000_000, // 10 MB/s
        }
    }
}

impl Default for BlockchainThresholds {
    fn default() -> Self {
        Self {
            sync_lag_warning_blocks: 3,
            sync_lag_critical_blocks: 10,
            mempool_size_warning: 1000,
            mempool_size_critical: 5000,
            block_time_variance_warning_seconds: 30,
        }
    }
}

impl Default for SystemThresholds {
    fn default() -> Self {
        Self {
            memory_usage_warning_percent: 80.0,
            memory_usage_critical_percent: 95.0,
            cpu_usage_warning_percent: 80.0,
            cpu_usage_critical_percent: 95.0,
            disk_usage_warning_percent: 85.0,
            disk_usage_critical_percent: 95.0,
        }
    }
}

impl Default for PeerThresholds {
    fn default() -> Self {
        Self {
            min_peers_warning: 3,
            min_peers_critical: 1,
            max_connection_failures_warning: 10,
            max_connection_failures_critical: 50,
            peer_timeout_warning_seconds: 30,
        }
    }
}

impl MonitoringConfig {
    /// Load configuration from a TOML file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        
        if !path.exists() {
            warn!("Monitoring config file not found at {:?}, using defaults", path);
            return Ok(Self::default());
        }
        
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::IoError(format!("Failed to read config file: {}", e)))?;
        
        let config: Self = toml::from_str(&content)
            .map_err(|e| ConfigError::ParseError(format!("Failed to parse config: {}", e)))?;
        
        info!("Loaded monitoring configuration from {:?}", path);
        config.validate()?;
        
        Ok(config)
    }
    
    /// Save configuration to a TOML file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), ConfigError> {
        let path = path.as_ref();
        
        let content = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::SerializeError(format!("Failed to serialize config: {}", e)))?;
        
        std::fs::write(path, content)
            .map_err(|e| ConfigError::IoError(format!("Failed to write config file: {}", e)))?;
        
        info!("Saved monitoring configuration to {:?}", path);
        Ok(())
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate dashboard config
        if self.dashboard.enabled {
            if self.dashboard.port == 0 {
                return Err(ConfigError::ValidationError("Dashboard port cannot be 0".to_string()));
            }
            
            if self.dashboard.update_interval_seconds == 0 {
                return Err(ConfigError::ValidationError("Update interval cannot be 0".to_string()));
            }
            
            if self.dashboard.max_chart_data_points == 0 {
                return Err(ConfigError::ValidationError("Max chart data points cannot be 0".to_string()));
            }
        }
        
        // Validate metrics config
        if self.metrics.enabled {
            if self.metrics.collection_interval_seconds == 0 {
                return Err(ConfigError::ValidationError("Collection interval cannot be 0".to_string()));
            }
            
            if self.metrics.retention_hours == 0 {
                return Err(ConfigError::ValidationError("Retention hours cannot be 0".to_string()));
            }
            
            if self.metrics.prometheus_enabled && self.metrics.prometheus_port == 0 {
                return Err(ConfigError::ValidationError("Prometheus port cannot be 0 when enabled".to_string()));
            }
        }
        
        // Validate alert config
        if self.alerts.enabled {
            if self.alerts.webhook_url.is_none() && self.alerts.email.is_none() {
                return Err(ConfigError::ValidationError(
                    "At least one alert method (webhook or email) must be configured when alerts are enabled".to_string()
                ));
            }
            
            if self.alerts.cooldown_seconds == 0 {
                return Err(ConfigError::ValidationError("Alert cooldown cannot be 0".to_string()));
            }
            
            if self.alerts.max_alerts_per_hour == 0 {
                return Err(ConfigError::ValidationError("Max alerts per hour cannot be 0".to_string()));
            }
        }
        
        // Validate thresholds
        self.validate_thresholds()?;
        
        Ok(())
    }
    
    /// Validate threshold configuration
    fn validate_thresholds(&self) -> Result<(), ConfigError> {
        let net = &self.thresholds.network;
        if net.latency_warning_ms >= net.latency_critical_ms {
            return Err(ConfigError::ValidationError(
                "Latency warning threshold must be less than critical threshold".to_string()
            ));
        }
        
        let blockchain = &self.thresholds.blockchain;
        if blockchain.sync_lag_warning_blocks >= blockchain.sync_lag_critical_blocks {
            return Err(ConfigError::ValidationError(
                "Sync lag warning threshold must be less than critical threshold".to_string()
            ));
        }
        
        if blockchain.mempool_size_warning >= blockchain.mempool_size_critical {
            return Err(ConfigError::ValidationError(
                "Mempool size warning threshold must be less than critical threshold".to_string()
            ));
        }
        
        let system = &self.thresholds.system;
        if system.memory_usage_warning_percent >= system.memory_usage_critical_percent {
            return Err(ConfigError::ValidationError(
                "Memory usage warning threshold must be less than critical threshold".to_string()
            ));
        }
        
        if system.cpu_usage_warning_percent >= system.cpu_usage_critical_percent {
            return Err(ConfigError::ValidationError(
                "CPU usage warning threshold must be less than critical threshold".to_string()
            ));
        }
        
        let peers = &self.thresholds.peers;
        if peers.min_peers_warning <= peers.min_peers_critical {
            return Err(ConfigError::ValidationError(
                "Min peers warning threshold must be greater than critical threshold".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Create a sample configuration file
    pub fn create_sample_config<P: AsRef<Path>>(path: P) -> Result<(), ConfigError> {
        let config = Self::default();
        config.save_to_file(path)
    }
}

/// Configuration error types
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    IoError(String),
    
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("Serialize error: {0}")]
    SerializeError(String),
    
    #[error("Validation error: {0}")]
    ValidationError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    
    #[test]
    fn test_default_config_validation() {
        let config = MonitoringConfig::default();
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_config_serialization() {
        let config = MonitoringConfig::default();
        let toml_str = toml::to_string(&config).unwrap();
        
        // Should be able to deserialize back
        let parsed: MonitoringConfig = toml::from_str(&toml_str).unwrap();
        assert!(parsed.validate().is_ok());
    }
    
    #[test]
    fn test_config_file_operations() {
        let temp_file = NamedTempFile::new().unwrap();
        let config = MonitoringConfig::default();
        
        // Save config
        assert!(config.save_to_file(temp_file.path()).is_ok());
        
        // Load config
        let loaded_config = MonitoringConfig::load_from_file(temp_file.path()).unwrap();
        assert!(loaded_config.validate().is_ok());
    }
    
    #[test]
    fn test_invalid_threshold_validation() {
        let mut config = MonitoringConfig::default();
        
        // Make latency thresholds invalid
        config.thresholds.network.latency_warning_ms = 500.0;
        config.thresholds.network.latency_critical_ms = 100.0;
        
        assert!(config.validate().is_err());
    }
    
    #[test]
    fn test_missing_alert_config_validation() {
        let mut config = MonitoringConfig::default();
        
        // Enable alerts but don't configure any methods
        config.alerts.enabled = true;
        config.alerts.webhook_url = None;
        config.alerts.email = None;
        
        assert!(config.validate().is_err());
    }
}