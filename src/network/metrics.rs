//! Prometheus metrics for TSN network monitoring
//!
//! Provides comprehensive metrics for network performance, peer management,
//! transaction throughput, and system health monitoring.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use tokio::sync::RwLock;
use serde_json::{json, Value};

/// Network performance metrics
#[derive(Debug, Default)]
pub struct NetworkMetrics {
    // Peer metrics
    pub connected_peers: AtomicUsize,
    pub total_peer_connections: AtomicU64,
    pub failed_peer_connections: AtomicU64,
    pub banned_peers: AtomicUsize,
    
    // Transaction metrics
    pub transactions_received: AtomicU64,
    pub transactions_sent: AtomicU64,
    pub transactions_per_second: AtomicU64,
    pub mempool_size: AtomicUsize,
    pub mempool_v1_size: AtomicUsize,
    pub mempool_v2_size: AtomicUsize,
    
    // Block metrics
    pub blocks_received: AtomicU64,
    pub blocks_sent: AtomicU64,
    pub block_sync_height: AtomicU64,
    pub block_sync_lag: AtomicU64,
    
    // Network latency metrics (in milliseconds)
    pub avg_peer_latency_ms: AtomicU64,
    pub max_peer_latency_ms: AtomicU64,
    pub min_peer_latency_ms: AtomicU64,
    
    // Bandwidth metrics (bytes)
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    
    // Error metrics
    pub network_errors: AtomicU64,
    pub timeout_errors: AtomicU64,
    pub protocol_errors: AtomicU64,
    
    // System metrics
    pub memory_usage_bytes: AtomicU64,
    pub cpu_usage_percent: AtomicU64,
    pub uptime_seconds: AtomicU64,
    
    // Mining metrics (for PoW)
    pub current_hashrate: AtomicU64,
    pub total_hashes: AtomicU64,
    pub blocks_mined: AtomicU64,
    pub current_difficulty: AtomicU64,
}

/// Per-peer latency tracking
#[derive(Debug)]
pub struct PeerLatency {
    pub addr: String,
    pub last_ping: Instant,
    pub avg_latency_ms: u64,
    pub samples: Vec<u64>,
    pub max_samples: usize,
}

impl PeerLatency {
    pub fn new(addr: String) -> Self {
        Self {
            addr,
            last_ping: Instant::now(),
            avg_latency_ms: 0,
            samples: Vec::new(),
            max_samples: 100, // Keep last 100 samples
        }
    }
    
    pub fn add_sample(&mut self, latency_ms: u64) {
        self.samples.push(latency_ms);
        if self.samples.len() > self.max_samples {
            self.samples.remove(0);
        }
        self.avg_latency_ms = self.samples.iter().sum::<u64>() / self.samples.len() as u64;
    }
}

/// Comprehensive metrics collector for TSN network
#[derive(Debug)]
pub struct MetricsCollector {
    pub metrics: Arc<NetworkMetrics>,
    peer_latencies: Arc<RwLock<HashMap<String, PeerLatency>>>,
    start_time: Instant,
    last_tx_count: AtomicU64,
    last_tx_time: Arc<RwLock<Instant>>,
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(NetworkMetrics::default()),
            peer_latencies: Arc::new(RwLock::new(HashMap::new())),
            start_time: Instant::now(),
            last_tx_count: AtomicU64::new(0),
            last_tx_time: Arc::new(RwLock::new(Instant::now())),
        }
    }
    
    /// Record a new peer connection
    pub fn peer_connected(&self, peer_addr: &str) {
        self.metrics.connected_peers.fetch_add(1, Ordering::Relaxed);
        self.metrics.total_peer_connections.fetch_add(1, Ordering::Relaxed);
        
        tracing::info!(
            peer = peer_addr,
            total_peers = self.metrics.connected_peers.load(Ordering::Relaxed),
            "Peer connected"
        );
    }
    
    /// Record a peer disconnection
    pub fn peer_disconnected(&self, peer_addr: &str) {
        self.metrics.connected_peers.fetch_sub(1, Ordering::Relaxed);
        
        tracing::info!(
            peer = peer_addr,
            total_peers = self.metrics.connected_peers.load(Ordering::Relaxed),
            "Peer disconnected"
        );
    }
    
    /// Record a failed peer connection
    pub fn peer_connection_failed(&self, peer_addr: &str, error: &str) {
        self.metrics.failed_peer_connections.fetch_add(1, Ordering::Relaxed);
        
        tracing::warn!(
            peer = peer_addr,
            error = error,
            "Peer connection failed"
        );
    }
    
    /// Record a peer ban
    pub fn peer_banned(&self, peer_addr: &str, reason: &str) {
        self.metrics.banned_peers.fetch_add(1, Ordering::Relaxed);
        
        tracing::warn!(
            peer = peer_addr,
            reason = reason,
            "Peer banned"
        );
    }
    
    /// Record transaction received
    pub async fn transaction_received(&self, tx_size: usize) {
        self.metrics.transactions_received.fetch_add(1, Ordering::Relaxed);
        self.metrics.bytes_received.fetch_add(tx_size as u64, Ordering::Relaxed);
        
        // Update TPS calculation
        self.update_tps().await;
    }
    
    /// Record transaction sent
    pub async fn transaction_sent(&self, tx_size: usize) {
        self.metrics.transactions_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics.bytes_sent.fetch_add(tx_size as u64, Ordering::Relaxed);
        
        // Update TPS calculation
        self.update_tps().await;
    }
    
    /// Update transactions per second calculation
    async fn update_tps(&self) {
        let now = Instant::now();
        let mut last_time = self.last_tx_time.write().await;
        let elapsed = now.duration_since(*last_time);
        
        if elapsed >= Duration::from_secs(1) {
            let current_tx_count = self.metrics.transactions_received.load(Ordering::Relaxed) 
                                 + self.metrics.transactions_sent.load(Ordering::Relaxed);
            let last_count = self.last_tx_count.load(Ordering::Relaxed);
            
            let tps = (current_tx_count - last_count) * 1000 / elapsed.as_millis() as u64;
            self.metrics.transactions_per_second.store(tps, Ordering::Relaxed);
            
            self.last_tx_count.store(current_tx_count, Ordering::Relaxed);
            *last_time = now;
        }
    }
    
    /// Update mempool metrics
    pub fn update_mempool_metrics(&self, v1_size: usize, v2_size: usize) {
        self.metrics.mempool_v1_size.store(v1_size, Ordering::Relaxed);
        self.metrics.mempool_v2_size.store(v2_size, Ordering::Relaxed);
        self.metrics.mempool_size.store(v1_size + v2_size, Ordering::Relaxed);
    }
    
    /// Record block received
    pub fn block_received(&self, block_size: usize) {
        self.metrics.blocks_received.fetch_add(1, Ordering::Relaxed);
        self.metrics.bytes_received.fetch_add(block_size as u64, Ordering::Relaxed);
    }
    
    /// Record block sent
    pub fn block_sent(&self, block_size: usize) {
        self.metrics.blocks_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics.bytes_sent.fetch_add(block_size as u64, Ordering::Relaxed);
    }
    
    /// Update block sync metrics
    pub fn update_block_sync(&self, current_height: u64, network_height: u64) {
        self.metrics.block_sync_height.store(current_height, Ordering::Relaxed);
        let lag = if network_height > current_height {
            network_height - current_height
        } else {
            0
        };
        self.metrics.block_sync_lag.store(lag, Ordering::Relaxed);
    }
    
    /// Record peer latency
    pub async fn record_peer_latency(&self, peer_addr: &str, latency_ms: u64) {
        let mut latencies = self.peer_latencies.write().await;
        let peer_latency = latencies.entry(peer_addr.to_string())
            .or_insert_with(|| PeerLatency::new(peer_addr.to_string()));
        
        peer_latency.add_sample(latency_ms);
        
        // Update global latency metrics
        self.update_global_latency_metrics(&latencies).await;
    }
    
    /// Update global latency metrics from all peers
    async fn update_global_latency_metrics(&self, latencies: &HashMap<String, PeerLatency>) {
        if latencies.is_empty() {
            return;
        }
        
        let mut total_latency = 0u64;
        let mut max_latency = 0u64;
        let mut min_latency = u64::MAX;
        let mut count = 0;
        
        for peer_latency in latencies.values() {
            if !peer_latency.samples.is_empty() {
                total_latency += peer_latency.avg_latency_ms;
                max_latency = max_latency.max(peer_latency.avg_latency_ms);
                min_latency = min_latency.min(peer_latency.avg_latency_ms);
                count += 1;
            }
        }
        
        if count > 0 {
            let avg_latency = total_latency / count;
            self.metrics.avg_peer_latency_ms.store(avg_latency, Ordering::Relaxed);
            self.metrics.max_peer_latency_ms.store(max_latency, Ordering::Relaxed);
            self.metrics.min_peer_latency_ms.store(min_latency, Ordering::Relaxed);
        }
    }
    
    /// Record network error
    pub fn network_error(&self, error_type: &str, error_msg: &str) {
        self.metrics.network_errors.fetch_add(1, Ordering::Relaxed);
        
        match error_type {
            "timeout" => { self.metrics.timeout_errors.fetch_add(1, Ordering::Relaxed); },
            "protocol" => { self.metrics.protocol_errors.fetch_add(1, Ordering::Relaxed); },
            _ => {}
        };
        
        tracing::error!(
            error_type = error_type,
            error = error_msg,
            "Network error recorded"
        );
    }
    
    /// Update mining metrics
    pub fn update_mining_metrics(&self, hashrate: u64, difficulty: u64) {
        self.metrics.current_hashrate.store(hashrate, Ordering::Relaxed);
        self.metrics.current_difficulty.store(difficulty, Ordering::Relaxed);
    }
    
    /// Record a mined block
    pub fn block_mined(&self, hashes_computed: u64) {
        self.metrics.blocks_mined.fetch_add(1, Ordering::Relaxed);
        self.metrics.total_hashes.fetch_add(hashes_computed, Ordering::Relaxed);
    }
    
    /// Update system metrics (memory, CPU, uptime)
    pub fn update_system_metrics(&self, memory_bytes: u64, cpu_percent: u64) {
        self.metrics.memory_usage_bytes.store(memory_bytes, Ordering::Relaxed);
        self.metrics.cpu_usage_percent.store(cpu_percent, Ordering::Relaxed);
        
        let uptime = self.start_time.elapsed().as_secs();
        self.metrics.uptime_seconds.store(uptime, Ordering::Relaxed);
    }
    
    /// Get all metrics as Prometheus format
    pub async fn get_prometheus_metrics(&self) -> String {
        let mut output = String::new();
        
        // Helper macro to add metric
        macro_rules! add_metric {
            ($name:expr, $type:expr, $help:expr, $value:expr) => {
                output.push_str(&format!("# HELP {} {}\n", $name, $help));
                output.push_str(&format!("# TYPE {} {}\n", $name, $type));
                output.push_str(&format!("{} {}\n", $name, $value));
            };
        }
        
        // Peer metrics
        add_metric!("tsn_connected_peers", "gauge", "Number of connected peers", 
                   self.metrics.connected_peers.load(Ordering::Relaxed));
        add_metric!("tsn_total_peer_connections", "counter", "Total peer connections attempted", 
                   self.metrics.total_peer_connections.load(Ordering::Relaxed));
        add_metric!("tsn_failed_peer_connections", "counter", "Failed peer connections", 
                   self.metrics.failed_peer_connections.load(Ordering::Relaxed));
        add_metric!("tsn_banned_peers", "gauge", "Number of banned peers", 
                   self.metrics.banned_peers.load(Ordering::Relaxed));
        
        // Transaction metrics
        add_metric!("tsn_transactions_received", "counter", "Total transactions received", 
                   self.metrics.transactions_received.load(Ordering::Relaxed));
        add_metric!("tsn_transactions_sent", "counter", "Total transactions sent", 
                   self.metrics.transactions_sent.load(Ordering::Relaxed));
        add_metric!("tsn_transactions_per_second", "gauge", "Current transactions per second", 
                   self.metrics.transactions_per_second.load(Ordering::Relaxed));
        add_metric!("tsn_mempool_size", "gauge", "Total mempool size", 
                   self.metrics.mempool_size.load(Ordering::Relaxed));
        add_metric!("tsn_mempool_v1_size", "gauge", "V1 mempool size", 
                   self.metrics.mempool_v1_size.load(Ordering::Relaxed));
        add_metric!("tsn_mempool_v2_size", "gauge", "V2 mempool size", 
                   self.metrics.mempool_v2_size.load(Ordering::Relaxed));
        
        // Block metrics
        add_metric!("tsn_blocks_received", "counter", "Total blocks received", 
                   self.metrics.blocks_received.load(Ordering::Relaxed));
        add_metric!("tsn_blocks_sent", "counter", "Total blocks sent", 
                   self.metrics.blocks_sent.load(Ordering::Relaxed));
        add_metric!("tsn_block_sync_height", "gauge", "Current block sync height", 
                   self.metrics.block_sync_height.load(Ordering::Relaxed));
        add_metric!("tsn_block_sync_lag", "gauge", "Block sync lag behind network", 
                   self.metrics.block_sync_lag.load(Ordering::Relaxed));
        
        // Latency metrics
        add_metric!("tsn_avg_peer_latency_ms", "gauge", "Average peer latency in milliseconds", 
                   self.metrics.avg_peer_latency_ms.load(Ordering::Relaxed));
        add_metric!("tsn_max_peer_latency_ms", "gauge", "Maximum peer latency in milliseconds", 
                   self.metrics.max_peer_latency_ms.load(Ordering::Relaxed));
        add_metric!("tsn_min_peer_latency_ms", "gauge", "Minimum peer latency in milliseconds", 
                   self.metrics.min_peer_latency_ms.load(Ordering::Relaxed));
        
        // Bandwidth metrics
        add_metric!("tsn_bytes_sent", "counter", "Total bytes sent", 
                   self.metrics.bytes_sent.load(Ordering::Relaxed));
        add_metric!("tsn_bytes_received", "counter", "Total bytes received", 
                   self.metrics.bytes_received.load(Ordering::Relaxed));
        
        // Error metrics
        add_metric!("tsn_network_errors", "counter", "Total network errors", 
                   self.metrics.network_errors.load(Ordering::Relaxed));
        add_metric!("tsn_timeout_errors", "counter", "Network timeout errors", 
                   self.metrics.timeout_errors.load(Ordering::Relaxed));
        add_metric!("tsn_protocol_errors", "counter", "Protocol errors", 
                   self.metrics.protocol_errors.load(Ordering::Relaxed));
        
        // System metrics
        add_metric!("tsn_memory_usage_bytes", "gauge", "Memory usage in bytes", 
                   self.metrics.memory_usage_bytes.load(Ordering::Relaxed));
        add_metric!("tsn_cpu_usage_percent", "gauge", "CPU usage percentage", 
                   self.metrics.cpu_usage_percent.load(Ordering::Relaxed));
        add_metric!("tsn_uptime_seconds", "gauge", "Node uptime in seconds", 
                   self.metrics.uptime_seconds.load(Ordering::Relaxed));
        
        // Mining metrics
        add_metric!("tsn_current_hashrate", "gauge", "Current mining hashrate", 
                   self.metrics.current_hashrate.load(Ordering::Relaxed));
        add_metric!("tsn_total_hashes", "counter", "Total hashes computed", 
                   self.metrics.total_hashes.load(Ordering::Relaxed));
        add_metric!("tsn_blocks_mined", "counter", "Total blocks mined", 
                   self.metrics.blocks_mined.load(Ordering::Relaxed));
        add_metric!("tsn_current_difficulty", "gauge", "Current mining difficulty", 
                   self.metrics.current_difficulty.load(Ordering::Relaxed));
        
        output
    }
    
    /// Get metrics as JSON for REST API
    pub async fn get_json_metrics(&self) -> Value {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        json!({
            "timestamp": timestamp,
            "peers": {
                "connected": self.metrics.connected_peers.load(Ordering::Relaxed),
                "total_connections": self.metrics.total_peer_connections.load(Ordering::Relaxed),
                "failed_connections": self.metrics.failed_peer_connections.load(Ordering::Relaxed),
                "banned": self.metrics.banned_peers.load(Ordering::Relaxed)
            },
            "transactions": {
                "received": self.metrics.transactions_received.load(Ordering::Relaxed),
                "sent": self.metrics.transactions_sent.load(Ordering::Relaxed),
                "per_second": self.metrics.transactions_per_second.load(Ordering::Relaxed),
                "mempool_total": self.metrics.mempool_size.load(Ordering::Relaxed),
                "mempool_v1": self.metrics.mempool_v1_size.load(Ordering::Relaxed),
                "mempool_v2": self.metrics.mempool_v2_size.load(Ordering::Relaxed)
            },
            "blocks": {
                "received": self.metrics.blocks_received.load(Ordering::Relaxed),
                "sent": self.metrics.blocks_sent.load(Ordering::Relaxed),
                "sync_height": self.metrics.block_sync_height.load(Ordering::Relaxed),
                "sync_lag": self.metrics.block_sync_lag.load(Ordering::Relaxed)
            },
            "latency": {
                "avg_ms": self.metrics.avg_peer_latency_ms.load(Ordering::Relaxed),
                "max_ms": self.metrics.max_peer_latency_ms.load(Ordering::Relaxed),
                "min_ms": self.metrics.min_peer_latency_ms.load(Ordering::Relaxed)
            },
            "bandwidth": {
                "bytes_sent": self.metrics.bytes_sent.load(Ordering::Relaxed),
                "bytes_received": self.metrics.bytes_received.load(Ordering::Relaxed)
            },
            "errors": {
                "network_total": self.metrics.network_errors.load(Ordering::Relaxed),
                "timeouts": self.metrics.timeout_errors.load(Ordering::Relaxed),
                "protocol": self.metrics.protocol_errors.load(Ordering::Relaxed)
            },
            "system": {
                "memory_bytes": self.metrics.memory_usage_bytes.load(Ordering::Relaxed),
                "cpu_percent": self.metrics.cpu_usage_percent.load(Ordering::Relaxed),
                "uptime_seconds": self.metrics.uptime_seconds.load(Ordering::Relaxed)
            },
            "mining": {
                "hashrate": self.metrics.current_hashrate.load(Ordering::Relaxed),
                "total_hashes": self.metrics.total_hashes.load(Ordering::Relaxed),
                "blocks_mined": self.metrics.blocks_mined.load(Ordering::Relaxed),
                "difficulty": self.metrics.current_difficulty.load(Ordering::Relaxed)
            }
        })
    }
    
    /// Start background task to collect system metrics
    pub fn start_system_metrics_collector(collector: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            
            loop {
                interval.tick().await;
                
                // Collect system metrics (simplified - in production use proper system monitoring)
                let memory_usage = get_memory_usage();
                let cpu_usage = get_cpu_usage();
                
                collector.update_system_metrics(memory_usage, cpu_usage);
            }
        });
    }
}

/// Get current memory usage (simplified implementation)
fn get_memory_usage() -> u64 {
    // In production, use proper system monitoring like sysinfo crate
    // For now, return a placeholder
    0
}

/// Get current CPU usage (simplified implementation)
fn get_cpu_usage() -> u64 {
    // In production, use proper system monitoring like sysinfo crate
    // For now, return a placeholder
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};
    
    #[tokio::test]
    async fn test_metrics_collector() {
        let collector = MetricsCollector::new();
        
        // Test peer metrics
        collector.peer_connected("127.0.0.1:8333");
        assert_eq!(collector.metrics.connected_peers.load(Ordering::Relaxed), 1);
        
        collector.peer_disconnected("127.0.0.1:8333");
        assert_eq!(collector.metrics.connected_peers.load(Ordering::Relaxed), 0);
        
        // Test transaction metrics
        collector.transaction_received(1024).await;
        assert_eq!(collector.metrics.transactions_received.load(Ordering::Relaxed), 1);
        assert_eq!(collector.metrics.bytes_received.load(Ordering::Relaxed), 1024);
        
        // Test latency recording
        collector.record_peer_latency("127.0.0.1:8333", 50).await;
        assert!(collector.metrics.avg_peer_latency_ms.load(Ordering::Relaxed) > 0);
        
        // Test Prometheus format
        let prometheus_output = collector.get_prometheus_metrics().await;
        assert!(prometheus_output.contains("tsn_connected_peers"));
        assert!(prometheus_output.contains("tsn_transactions_received"));
        
        // Test JSON format
        let json_output = collector.get_json_metrics().await;
        assert!(json_output["peers"]["connected"].is_number());
        assert!(json_output["transactions"]["received"].is_number());
    }
    
    #[tokio::test]
    async fn test_tps_calculation() {
        let collector = MetricsCollector::new();
        
        // Send multiple transactions
        for _ in 0..10 {
            collector.transaction_received(100).await;
            sleep(Duration::from_millis(10)).await;
        }
        
        // TPS should be calculated
        let tps = collector.metrics.transactions_per_second.load(Ordering::Relaxed);
        assert!(tps > 0);
    }
    
    #[tokio::test]
    async fn test_peer_latency_tracking() {
        let collector = MetricsCollector::new();
        
        // Record multiple latency samples
        collector.record_peer_latency("peer1", 100).await;
        collector.record_peer_latency("peer1", 200).await;
        collector.record_peer_latency("peer1", 150).await;
        
        let latencies = collector.peer_latencies.read().await;
        let peer_latency = latencies.get("peer1").unwrap();
        assert_eq!(peer_latency.avg_latency_ms, 150); // (100 + 200 + 150) / 3
        assert_eq!(peer_latency.samples.len(), 3);
    }
}