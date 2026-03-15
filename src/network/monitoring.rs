//! Integrated network monitoring system for TSN
//!
//! Combines metrics collection, alerting, and dashboard functionality
//! into a unified monitoring solution with real-time updates.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn, error};

use super::monitoring_config::{MonitoringConfig, DashboardConfig, AlertConfig, ThresholdConfig};
use super::metrics::{NetworkMetrics, MetricsCollector};
use super::metrics_server::MetricsServer;
use super::alerts::AlertManager;
use super::dashboard::{DashboardServer, DashboardUpdate};

/// Comprehensive network monitoring system
pub struct NetworkMonitoringSystem {
    config: MonitoringConfig,
    metrics: Arc<NetworkMetrics>,
    metrics_collector: Arc<MetricsCollector>,
    metrics_server: Option<MetricsServer>,
    alert_manager: Arc<AlertManager>,
    dashboard_server: Option<DashboardServer>,
    is_running: Arc<RwLock<bool>>,
}

impl NetworkMonitoringSystem {
    /// Create a new monitoring system
    pub fn new(config: MonitoringConfig) -> Self {
        let metrics = Arc::new(NetworkMetrics::new());
        let metrics_collector = Arc::new(MetricsCollector::new(metrics.clone()));
        
        // Create metrics server if enabled
        let metrics_server = if config.prometheus.enabled {
            Some(MetricsServer::new(
                config.prometheus.clone(),
                metrics.clone(),
            ))
        } else {
            None
        };
        
        // Create alert manager
        let alert_manager = Arc::new(AlertManager::new(
            config.alerts.clone(),
            config.thresholds.clone(),
        ));
        
        // Create dashboard server if enabled
        let dashboard_server = if config.dashboard.enabled {
            Some(DashboardServer::new(
                config.dashboard.clone(),
                metrics.clone(),
                alert_manager.clone(),
            ))
        } else {
            None
        };
        
        Self {
            config,
            metrics,
            metrics_collector,
            metrics_server,
            alert_manager,
            dashboard_server,
            is_running: Arc::new(RwLock::new(false)),
        }
    }
    
    /// Start the monitoring system
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut is_running = self.is_running.write().await;
        if *is_running {
            warn!("Monitoring system is already running");
            return Ok(());
        }
        
        info!("Starting TSN Network Monitoring System");
        
        // Start metrics collection
        self.start_metrics_collection().await?;
        
        // Start Prometheus metrics server
        if let Some(metrics_server) = &self.metrics_server {
            self.start_metrics_server(metrics_server).await?;
        }
        
        // Start alert monitoring
        self.start_alert_monitoring().await?;
        
        // Start dashboard server
        if let Some(dashboard_server) = &self.dashboard_server {
            self.start_dashboard_server(dashboard_server).await?;
        }
        
        // Start background monitoring tasks
        self.start_background_tasks().await;
        
        *is_running = true;
        info!("Network monitoring system started successfully");
        
        Ok(())
    }
    
    /// Stop the monitoring system
    pub async fn stop(&self) {
        let mut is_running = self.is_running.write().await;
        if !*is_running {
            return;
        }
        
        info!("Stopping TSN Network Monitoring System");
        *is_running = false;
        
        // Cleanup would go here if needed
        info!("Network monitoring system stopped");
    }
    
    /// Check if the monitoring system is running
    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }
    
    /// Get metrics reference
    pub fn get_metrics(&self) -> Arc<NetworkMetrics> {
        self.metrics.clone()
    }
    
    /// Get alert manager reference
    pub fn get_alert_manager(&self) -> Arc<AlertManager> {
        self.alert_manager.clone()
    }
    
    /// Get dashboard WebSocket sender if available
    pub fn get_dashboard_websocket_sender(&self) -> Option<tokio::sync::broadcast::Sender<DashboardUpdate>> {
        self.dashboard_server.as_ref().map(|server| server.get_websocket_sender())
    }
    
    /// Record a network event
    pub async fn record_network_event(&self, event: NetworkEvent) {
        match event {
            NetworkEvent::PeerConnected { peer_id, address } => {
                self.metrics.increment_peer_connections();
                info!("Peer connected: {} at {}", peer_id, address);
                
                // Send dashboard update if available
                if let Some(sender) = self.get_dashboard_websocket_sender() {
                    let update = DashboardUpdate::SystemStatus {
                        status: self.get_system_status().await,
                    };
                    let _ = sender.send(update);
                }
            }
            
            NetworkEvent::PeerDisconnected { peer_id, reason } => {
                self.metrics.decrement_peer_connections();
                info!("Peer disconnected: {} (reason: {})", peer_id, reason);
                
                // Send dashboard update if available
                if let Some(sender) = self.get_dashboard_websocket_sender() {
                    let update = DashboardUpdate::SystemStatus {
                        status: self.get_system_status().await,
                    };
                    let _ = sender.send(update);
                }
            }
            
            NetworkEvent::MessageReceived { message_type, size, latency } => {
                self.metrics.record_message_received(message_type, size);
                if let Some(latency) = latency {
                    self.metrics.record_latency(latency);
                }
            }
            
            NetworkEvent::MessageSent { message_type, size } => {
                self.metrics.record_message_sent(message_type, size);
            }
            
            NetworkEvent::BlockReceived { height, hash, size } => {
                self.metrics.update_block_height(height);
                self.metrics.record_block_received(size);
                info!("Block received: {} at height {}", hash, height);
            }
            
            NetworkEvent::TransactionReceived { tx_hash, size } => {
                self.metrics.record_transaction_received(size);
                self.metrics.increment_mempool_size();
                info!("Transaction received: {}", tx_hash);
            }
            
            NetworkEvent::SyncProgress { current_height, target_height } => {
                self.metrics.update_block_height(current_height);
                self.metrics.update_sync_progress(current_height, target_height);
            }
            
            NetworkEvent::Error { error_type, description } => {
                self.metrics.record_network_error(&error_type);
                warn!("Network error: {} - {}", error_type, description);
            }
        }
    }
    
    /// Start metrics collection
    async fn start_metrics_collection(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting metrics collection");
        // The metrics collector is passive and collects data as events are recorded
        Ok(())
    }
    
    /// Start Prometheus metrics server
    async fn start_metrics_server(&self, metrics_server: &MetricsServer) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting Prometheus metrics server on {}:{}", 
            self.config.prometheus.bind_address, 
            self.config.prometheus.port
        );
        
        let server = metrics_server.clone();
        tokio::spawn(async move {
            if let Err(e) = server.start().await {
                error!("Metrics server error: {}", e);
            }
        });
        
        Ok(())
    }
    
    /// Start alert monitoring
    async fn start_alert_monitoring(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.alerts.enabled {
            info!("Alert monitoring is disabled");
            return Ok(());
        }
        
        info!("Starting alert monitoring");
        
        let alert_manager = self.alert_manager.clone();
        let metrics = self.metrics.clone();
        let check_interval = Duration::from_secs(self.config.alerts.check_interval_seconds as u64);
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(check_interval);
            
            loop {
                interval.tick().await;
                alert_manager.check_network_metrics(&*metrics).await;
            }
        });
        
        Ok(())
    }
    
    /// Start dashboard server
    async fn start_dashboard_server(&self, dashboard_server: &DashboardServer) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting dashboard server on {}:{}", 
            self.config.dashboard.bind_address, 
            self.config.dashboard.port
        );
        
        let server = dashboard_server.clone();
        tokio::spawn(async move {
            if let Err(e) = server.start().await {
                error!("Dashboard server error: {}", e);
            }
        });
        
        Ok(())
    }
    
    /// Start background monitoring tasks
    async fn start_background_tasks(&self) {
        // System health monitoring
        self.start_system_health_monitoring().await;
        
        // Periodic cleanup
        self.start_periodic_cleanup().await;
        
        // Performance monitoring
        self.start_performance_monitoring().await;
    }
    
    /// Start system health monitoring
    async fn start_system_health_monitoring(&self) {
        let metrics = self.metrics.clone();
        let alert_manager = self.alert_manager.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                // Check system resources
                if let Ok(system_info) = get_system_info().await {
                    metrics.update_system_metrics(system_info);
                }
                
                // Check for system-level alerts
                // This would include CPU, memory, disk usage, etc.
            }
        });
    }
    
    /// Start periodic cleanup
    async fn start_periodic_cleanup(&self) {
        let metrics = self.metrics.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Every hour
            
            loop {
                interval.tick().await;
                
                // Cleanup old metrics data
                metrics.cleanup_old_data().await;
                
                info!("Performed periodic cleanup of monitoring data");
            }
        });
    }
    
    /// Start performance monitoring
    async fn start_performance_monitoring(&self) {
        let metrics = self.metrics.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                // Calculate and update performance metrics
                metrics.calculate_performance_metrics().await;
            }
        });
    }
    
    /// Get current system status
    async fn get_system_status(&self) -> super::dashboard::SystemStatus {
        use super::dashboard::{SystemStatus, SyncStatus, PeerInfo, BlockchainInfo};
        
        let current_height = self.metrics.current_block_height.load(std::sync::atomic::Ordering::Relaxed);
        let peer_count = self.metrics.connected_peers.load(std::sync::atomic::Ordering::Relaxed);
        let mempool_size = self.metrics.mempool_size.load(std::sync::atomic::Ordering::Relaxed);
        let total_transactions = self.metrics.total_transactions.load(std::sync::atomic::Ordering::Relaxed);
        
        SystemStatus {
            uptime_seconds: 3600, // Placeholder - would calculate actual uptime
            node_version: "1.0.0".to_string(),
            network_id: "tsn-mainnet".to_string(),
            sync_status: SyncStatus {
                is_syncing: false, // Placeholder
                current_block: current_height,
                target_block: current_height,
                sync_progress: 100.0,
                estimated_time_remaining: None,
            },
            peer_info: PeerInfo {
                connected_peers: peer_count,
                max_peers: 50,
                inbound_peers: peer_count / 2, // Placeholder
                outbound_peers: peer_count / 2, // Placeholder
                peer_list: Vec::new(), // Would be populated from actual peer manager
            },
            blockchain_info: BlockchainInfo {
                current_height,
                best_block_hash: "0x1234...".to_string(), // Placeholder
                difficulty: 1000.0, // Placeholder
                total_transactions,
                mempool_size,
                average_block_time: 10.0, // Placeholder
            },
        }
    }
}

/// Network events that can be recorded by the monitoring system
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    PeerConnected {
        peer_id: String,
        address: String,
    },
    PeerDisconnected {
        peer_id: String,
        reason: String,
    },
    MessageReceived {
        message_type: String,
        size: usize,
        latency: Option<Duration>,
    },
    MessageSent {
        message_type: String,
        size: usize,
    },
    BlockReceived {
        height: u64,
        hash: String,
        size: usize,
    },
    TransactionReceived {
        tx_hash: String,
        size: usize,
    },
    SyncProgress {
        current_height: u64,
        target_height: u64,
    },
    Error {
        error_type: String,
        description: String,
    },
}

/// System information for health monitoring
#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub cpu_usage_percent: f64,
    pub memory_usage_percent: f64,
    pub disk_usage_percent: f64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
}

/// Get current system information
async fn get_system_info() -> Result<SystemInfo, Box<dyn std::error::Error + Send + Sync>> {
    // Placeholder implementation
    // In a real implementation, this would use system monitoring libraries
    // like sysinfo or procfs to get actual system metrics
    
    Ok(SystemInfo {
        cpu_usage_percent: 25.0,
        memory_usage_percent: 60.0,
        disk_usage_percent: 45.0,
        network_rx_bytes: 1024 * 1024 * 100, // 100 MB
        network_tx_bytes: 1024 * 1024 * 80,  // 80 MB
    })
}

impl NetworkMetrics {
    /// Update system metrics
    pub fn update_system_metrics(&self, system_info: SystemInfo) {
        // Store system metrics
        // This would require additional atomic fields in NetworkMetrics
        // For now, this is a placeholder
    }
    
    /// Calculate performance metrics
    pub async fn calculate_performance_metrics(&self) {
        // Calculate derived metrics like:
        // - Average latency over time windows
        // - Throughput rates
        // - Error rates
        // - Connection stability
        
        // This is a placeholder implementation
    }
    
    /// Cleanup old data
    pub async fn cleanup_old_data(&self) {
        // Remove old historical data to prevent memory leaks
        // This would clean up time-series data older than a certain threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_monitoring_system_creation() {
        let config = MonitoringConfig::default();
        let monitoring = NetworkMonitoringSystem::new(config);
        
        assert!(!monitoring.is_running().await);
    }
    
    #[tokio::test]
    async fn test_network_event_recording() {
        let config = MonitoringConfig::default();
        let monitoring = NetworkMonitoringSystem::new(config);
        
        let event = NetworkEvent::PeerConnected {
            peer_id: "test-peer".to_string(),
            address: "127.0.0.1:8080".to_string(),
        };
        
        monitoring.record_network_event(event).await;
        
        let metrics = monitoring.get_metrics();
        assert_eq!(metrics.connected_peers.load(std::sync::atomic::Ordering::Relaxed), 1);
    }
    
    #[tokio::test]
    async fn test_system_status() {
        let config = MonitoringConfig::default();
        let monitoring = NetworkMonitoringSystem::new(config);
        
        let status = monitoring.get_system_status().await;
        assert_eq!(status.node_version, "1.0.0");
        assert_eq!(status.network_id, "tsn-mainnet");
    }
}