//! Network alerting system for TSN monitoring
//!
//! Provides real-time alerting based on network metrics and thresholds.
//! Supports webhook and email notifications with rate limiting and cooldowns.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error, debug};

use super::monitoring_config::{AlertConfig, ThresholdConfig, EmailConfig};
use super::metrics::NetworkMetrics;

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
    Emergency,
}

/// Alert categories
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertCategory {
    Network,
    Blockchain,
    System,
    Peers,
    Security,
}

/// Alert information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub category: AlertCategory,
    pub severity: AlertSeverity,
    pub title: String,
    pub description: String,
    pub timestamp: u64,
    pub metrics: HashMap<String, f64>,
    pub resolved: bool,
    pub resolved_at: Option<u64>,
}

/// Alert manager for handling network alerts
pub struct AlertManager {
    config: AlertConfig,
    thresholds: ThresholdConfig,
    active_alerts: Arc<RwLock<HashMap<String, Alert>>>,
    alert_history: Arc<RwLock<Vec<Alert>>>,
    last_alert_times: Arc<RwLock<HashMap<String, Instant>>>,
    _alert_counts: Arc<RwLock<HashMap<String, u32>>>,
    webhook_client: Option<reqwest::Client>,
}

impl AlertManager {
    /// Create a new alert manager
    pub fn new(config: AlertConfig, thresholds: ThresholdConfig) -> Self {
        let webhook_client = if config.webhook_url.is_some() {
            Some(reqwest::Client::new())
        } else {
            None
        };
        
        Self {
            config,
            thresholds,
            active_alerts: Arc::new(RwLock::new(HashMap::new())),
            alert_history: Arc::new(RwLock::new(Vec::new())),
            last_alert_times: Arc::new(RwLock::new(HashMap::new())),
            _alert_counts: Arc::new(RwLock::new(HashMap::new())),
            webhook_client,
        }
    }
    
    /// Check network metrics and trigger alerts if necessary
    pub async fn check_network_metrics(&self, metrics: &NetworkMetrics) {
        if !self.config.enabled {
            return;
        }
        
        // Check latency
        let avg_latency = self.calculate_average_latency(metrics).await;
        if avg_latency > self.thresholds.network.latency_critical_ms {
            self.trigger_alert(
                "network_latency_critical",
                AlertCategory::Network,
                AlertSeverity::Critical,
                "Critical Network Latency",
                &format!("Average network latency is {:.2}ms (threshold: {:.2}ms)", 
                    avg_latency, self.thresholds.network.latency_critical_ms),
                [("latency_ms".to_string(), avg_latency)].into(),
            ).await;
        } else if avg_latency > self.thresholds.network.latency_warning_ms {
            self.trigger_alert(
                "network_latency_warning",
                AlertCategory::Network,
                AlertSeverity::Warning,
                "High Network Latency",
                &format!("Average network latency is {:.2}ms (threshold: {:.2}ms)", 
                    avg_latency, self.thresholds.network.latency_warning_ms),
                [("latency_ms".to_string(), avg_latency)].into(),
            ).await;
        } else {
            self.resolve_alert("network_latency_critical").await;
            self.resolve_alert("network_latency_warning").await;
        }
        
        // Check peer count
        let peer_count = metrics.connected_peers.load(std::sync::atomic::Ordering::Relaxed);
        if peer_count <= self.thresholds.peers.min_peers_critical as usize {
            self.trigger_alert(
                "peers_critical",
                AlertCategory::Peers,
                AlertSeverity::Critical,
                "Critical Peer Count",
                &format!("Only {} peers connected (minimum: {})", 
                    peer_count, self.thresholds.peers.min_peers_critical),
                [("peer_count".to_string(), peer_count as f64)].into(),
            ).await;
        } else if peer_count <= self.thresholds.peers.min_peers_warning as usize {
            self.trigger_alert(
                "peers_warning",
                AlertCategory::Peers,
                AlertSeverity::Warning,
                "Low Peer Count",
                &format!("Only {} peers connected (minimum: {})", 
                    peer_count, self.thresholds.peers.min_peers_warning),
                [("peer_count".to_string(), peer_count as f64)].into(),
            ).await;
        } else {
            self.resolve_alert("peers_critical").await;
            self.resolve_alert("peers_warning").await;
        }
        
        // Check mempool size
        let mempool_size = metrics.mempool_size.load(std::sync::atomic::Ordering::Relaxed);
        if mempool_size >= self.thresholds.blockchain.mempool_size_critical as usize {
            self.trigger_alert(
                "mempool_critical",
                AlertCategory::Blockchain,
                AlertSeverity::Critical,
                "Critical Mempool Size",
                &format!("Mempool has {} transactions (threshold: {})", 
                    mempool_size, self.thresholds.blockchain.mempool_size_critical),
                [("mempool_size".to_string(), mempool_size as f64)].into(),
            ).await;
        } else if mempool_size >= self.thresholds.blockchain.mempool_size_warning as usize {
            self.trigger_alert(
                "mempool_warning",
                AlertCategory::Blockchain,
                AlertSeverity::Warning,
                "Large Mempool Size",
                &format!("Mempool has {} transactions (threshold: {})", 
                    mempool_size, self.thresholds.blockchain.mempool_size_warning),
                [("mempool_size".to_string(), mempool_size as f64)].into(),
            ).await;
        } else {
            self.resolve_alert("mempool_critical").await;
            self.resolve_alert("mempool_warning").await;
        }
        
        // Check sync status
        let sync_lag = self.calculate_sync_lag(metrics).await;
        if sync_lag >= self.thresholds.blockchain.sync_lag_critical_blocks {
            self.trigger_alert(
                "sync_critical",
                AlertCategory::Blockchain,
                AlertSeverity::Critical,
                "Critical Sync Lag",
                &format!("Blockchain is {} blocks behind (threshold: {})", 
                    sync_lag, self.thresholds.blockchain.sync_lag_critical_blocks),
                [("sync_lag_blocks".to_string(), sync_lag as f64)].into(),
            ).await;
        } else if sync_lag >= self.thresholds.blockchain.sync_lag_warning_blocks {
            self.trigger_alert(
                "sync_warning",
                AlertCategory::Blockchain,
                AlertSeverity::Warning,
                "Sync Lag Detected",
                &format!("Blockchain is {} blocks behind (threshold: {})", 
                    sync_lag, self.thresholds.blockchain.sync_lag_warning_blocks),
                [("sync_lag_blocks".to_string(), sync_lag as f64)].into(),
            ).await;
        } else {
            self.resolve_alert("sync_critical").await;
            self.resolve_alert("sync_warning").await;
        }
    }
    
    /// Trigger a new alert
    async fn trigger_alert(
        &self,
        alert_id: &str,
        category: AlertCategory,
        severity: AlertSeverity,
        title: &str,
        description: &str,
        metrics: HashMap<String, f64>,
    ) {
        // Check if we're in cooldown period
        if !self.can_send_alert(alert_id).await {
            debug!("Alert {} is in cooldown period, skipping", alert_id);
            return;
        }
        
        // Check rate limiting
        if !self.check_rate_limit().await {
            warn!("Alert rate limit exceeded, skipping alert {}", alert_id);
            return;
        }
        
        let alert = Alert {
            id: alert_id.to_string(),
            category,
            severity,
            title: title.to_string(),
            description: description.to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            metrics,
            resolved: false,
            resolved_at: None,
        };
        
        // Store alert
        {
            let mut active_alerts = self.active_alerts.write().await;
            active_alerts.insert(alert_id.to_string(), alert.clone());
        }
        
        {
            let mut history = self.alert_history.write().await;
            history.push(alert.clone());
            
            // Keep only last 1000 alerts in history
            if history.len() > 1000 {
                history.remove(0);
            }
        }
        
        // Update alert timing
        {
            let mut last_times = self.last_alert_times.write().await;
            last_times.insert(alert_id.to_string(), Instant::now());
        }
        
        // Send notifications
        self.send_alert_notifications(&alert).await;
        
        info!("Alert triggered: {} - {}", alert.title, alert.description);
    }
    
    /// Resolve an active alert
    async fn resolve_alert(&self, alert_id: &str) {
        let mut active_alerts = self.active_alerts.write().await;
        
        if let Some(mut alert) = active_alerts.remove(alert_id) {
            alert.resolved = true;
            alert.resolved_at = Some(chrono::Utc::now().timestamp() as u64);
            
            // Add to history
            let mut history = self.alert_history.write().await;
            history.push(alert.clone());
            
            info!("Alert resolved: {}", alert.title);
        }
    }
    
    /// Send alert notifications via configured channels
    async fn send_alert_notifications(&self, alert: &Alert) {
        // Send webhook notification
        if let Some(webhook_url) = &self.config.webhook_url {
            if let Some(client) = &self.webhook_client {
                self.send_webhook_notification(client, webhook_url, alert).await;
            }
        }
        
        // Send email notification
        if let Some(email_config) = &self.config.email {
            self.send_email_notification(email_config, alert).await;
        }
    }
    
    /// Send webhook notification
    async fn send_webhook_notification(&self, client: &reqwest::Client, webhook_url: &str, alert: &Alert) {
        let payload = serde_json::json!({
            "alert_id": alert.id,
            "category": alert.category,
            "severity": alert.severity,
            "title": alert.title,
            "description": alert.description,
            "timestamp": alert.timestamp,
            "metrics": alert.metrics,
            "node_id": "tsn-node", // Could be configurable
        });
        
        match client.post(webhook_url)
            .json(&payload)
            .timeout(Duration::from_secs(10))
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    debug!("Webhook notification sent successfully for alert {}", alert.id);
                } else {
                    warn!("Webhook notification failed with status: {} for alert {}", 
                        response.status(), alert.id);
                }
            }
            Err(e) => {
                error!("Failed to send webhook notification for alert {}: {}", alert.id, e);
            }
        }
    }
    
    /// Send email notification (placeholder implementation)
    async fn send_email_notification(&self, _email_config: &EmailConfig, alert: &Alert) {
        // This would require an SMTP client implementation
        // For now, just log that we would send an email
        info!("Would send email notification for alert: {} - {}", alert.title, alert.description);
        
        // TODO: Implement actual email sending using lettre or similar crate
        // let email = Message::builder()
        //     .from(email_config.from_address.parse().unwrap())
        //     .to(email_config.to_addresses[0].parse().unwrap())
        //     .subject(&alert.title)
        //     .body(format!("{}\n\nMetrics: {:?}", alert.description, alert.metrics))
        //     .unwrap();
    }
    
    /// Check if we can send an alert (cooldown check)
    async fn can_send_alert(&self, alert_id: &str) -> bool {
        let last_times = self.last_alert_times.read().await;
        
        if let Some(last_time) = last_times.get(alert_id) {
            let elapsed = last_time.elapsed();
            elapsed >= Duration::from_secs(self.config.cooldown_seconds as u64)
        } else {
            true
        }
    }
    
    /// Check rate limiting
    async fn check_rate_limit(&self) -> bool {
        let now = Instant::now();
        let hour_ago = now - Duration::from_secs(3600);
        
        // Count alerts in the last hour
        let history = self.alert_history.read().await;
        let recent_alerts = history.iter()
            .filter(|alert| {
                let alert_time = std::time::UNIX_EPOCH + Duration::from_secs(alert.timestamp);
                alert_time >= std::time::UNIX_EPOCH + hour_ago.elapsed()
            })
            .count();
        
        recent_alerts < self.config.max_alerts_per_hour as usize
    }
    
    /// Get active alerts
    pub async fn get_active_alerts(&self) -> Vec<Alert> {
        let active_alerts = self.active_alerts.read().await;
        active_alerts.values().cloned().collect()
    }
    
    /// Get alert history
    pub async fn get_alert_history(&self, limit: Option<usize>) -> Vec<Alert> {
        let history = self.alert_history.read().await;
        let limit = limit.unwrap_or(100);
        
        history.iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }
    
    /// Calculate average latency from metrics
    async fn calculate_average_latency(&self, _metrics: &NetworkMetrics) -> f64 {
        // Placeholder implementation
        // In a real implementation, this would calculate from actual latency measurements
        50.0
    }
    
    /// Calculate sync lag from metrics
    async fn calculate_sync_lag(&self, _metrics: &NetworkMetrics) -> u64 {
        // Placeholder implementation
        // In a real implementation, this would compare local height with network height
        0
    }
    
    /// Trigger a test alert
    pub async fn trigger_test_alert(&self) {
        self.trigger_alert(
            "test_alert",
            AlertCategory::System,
            AlertSeverity::Info,
            "Test Alert",
            "This is a test alert to verify the alerting system is working",
            [("test_value".to_string(), 42.0)].into(),
        ).await;
    }
}

/// Alert statistics
#[derive(Debug, Serialize, Deserialize)]
pub struct AlertStats {
    pub total_alerts: u32,
    pub active_alerts: u32,
    pub alerts_by_severity: HashMap<AlertSeverity, u32>,
    pub alerts_by_category: HashMap<AlertCategory, u32>,
    pub last_alert_time: Option<u64>,
    pub avg_resolution_time_seconds: f64,
}

impl AlertManager {
    /// Get alert statistics
    pub async fn get_alert_stats(&self) -> AlertStats {
        let active_alerts = self.active_alerts.read().await;
        let history = self.alert_history.read().await;
        
        let mut alerts_by_severity = HashMap::new();
        let mut alerts_by_category = HashMap::new();
        let mut total_resolution_time = 0u64;
        let mut resolved_count = 0u32;
        let mut last_alert_time = None;
        
        for alert in history.iter() {
            // Count by severity
            *alerts_by_severity.entry(alert.severity).or_insert(0) += 1;
            
            // Count by category
            *alerts_by_category.entry(alert.category.clone()).or_insert(0) += 1;
            
            // Track resolution times
            if let Some(resolved_at) = alert.resolved_at {
                total_resolution_time += resolved_at - alert.timestamp;
                resolved_count += 1;
            }
            
            // Track last alert time
            if last_alert_time.is_none() || alert.timestamp > last_alert_time.unwrap() {
                last_alert_time = Some(alert.timestamp);
            }
        }
        
        let avg_resolution_time = if resolved_count > 0 {
            total_resolution_time as f64 / resolved_count as f64
        } else {
            0.0
        };
        
        AlertStats {
            total_alerts: history.len() as u32,
            active_alerts: active_alerts.len() as u32,
            alerts_by_severity,
            alerts_by_category,
            last_alert_time,
            avg_resolution_time_seconds: avg_resolution_time,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::monitoring_config::{AlertConfig, ThresholdConfig};
    
    #[tokio::test]
    async fn test_alert_manager_creation() {
        let config = AlertConfig::default();
        let thresholds = ThresholdConfig::default();
        let manager = AlertManager::new(config, thresholds);
        
        let active_alerts = manager.get_active_alerts().await;
        assert!(active_alerts.is_empty());
    }
    
    #[tokio::test]
    async fn test_alert_triggering() {
        let mut config = AlertConfig::default();
        config.enabled = true;
        config.cooldown_seconds = 0; // No cooldown for testing
        
        let thresholds = ThresholdConfig::default();
        let manager = AlertManager::new(config, thresholds);
        
        manager.trigger_test_alert().await;
        
        let active_alerts = manager.get_active_alerts().await;
        assert_eq!(active_alerts.len(), 1);
        assert_eq!(active_alerts[0].id, "test_alert");
    }
    
    #[tokio::test]
    async fn test_alert_resolution() {
        let mut config = AlertConfig::default();
        config.enabled = true;
        config.cooldown_seconds = 0;
        
        let thresholds = ThresholdConfig::default();
        let manager = AlertManager::new(config, thresholds);
        
        manager.trigger_test_alert().await;
        assert_eq!(manager.get_active_alerts().await.len(), 1);
        
        manager.resolve_alert("test_alert").await;
        assert_eq!(manager.get_active_alerts().await.len(), 0);
    }
    
    #[tokio::test]
    async fn test_alert_cooldown() {
        let mut config = AlertConfig::default();
        config.enabled = true;
        config.cooldown_seconds = 1;
        
        let thresholds = ThresholdConfig::default();
        let manager = AlertManager::new(config, thresholds);
        
        manager.trigger_test_alert().await;
        assert_eq!(manager.get_active_alerts().await.len(), 1);
        
        // Try to trigger the same alert immediately - should be blocked by cooldown
        manager.trigger_test_alert().await;
        assert_eq!(manager.get_active_alerts().await.len(), 1); // Still only one
    }
}