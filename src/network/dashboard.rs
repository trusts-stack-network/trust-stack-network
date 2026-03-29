//! Real-time network monitoring dashboard for TSN
//!
//! Provides a web-based dashboard with real-time metrics, charts, and network status.
//! Includes WebSocket support for live updates and interactive debugging tools.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, RwLock};
use axum::{
    extract::{ws::WebSocket, ws::WebSocketUpgrade, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::Query;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error, debug};
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;

use super::monitoring_config::DashboardConfig;
use super::metrics::{NetworkMetrics, MetricsSnapshot};
use super::alerts::{AlertManager, Alert, AlertStats};

/// Dashboard state shared across handlers
#[derive(Clone)]
pub struct DashboardState {
    pub config: DashboardConfig,
    pub metrics: Arc<NetworkMetrics>,
    pub alert_manager: Arc<AlertManager>,
    pub chart_data: Arc<RwLock<ChartDataStore>>,
    pub websocket_tx: broadcast::Sender<DashboardUpdate>,
}

/// Chart data storage for real-time updates
#[derive(Debug, Clone)]
pub struct ChartDataStore {
    pub latency_history: Vec<TimeSeriesPoint>,
    pub throughput_history: Vec<TimeSeriesPoint>,
    pub peer_count_history: Vec<TimeSeriesPoint>,
    pub mempool_size_history: Vec<TimeSeriesPoint>,
    pub block_height_history: Vec<TimeSeriesPoint>,
    pub cpu_usage_history: Vec<TimeSeriesPoint>,
    pub memory_usage_history: Vec<TimeSeriesPoint>,
    pub max_points: usize,
}

/// Time series data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    pub timestamp: u64,
    pub value: f64,
}

/// Dashboard update message for WebSocket
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DashboardUpdate {
    MetricsUpdate {
        timestamp: u64,
        metrics: MetricsSnapshot,
    },
    AlertUpdate {
        alert: Alert,
    },
    ChartDataUpdate {
        chart_type: String,
        data: Vec<TimeSeriesPoint>,
    },
    SystemStatus {
        status: SystemStatus,
    },
}

/// System status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub uptime_seconds: u64,
    pub node_version: String,
    pub network_id: String,
    pub sync_status: SyncStatus,
    pub peer_info: PeerInfo,
    pub blockchain_info: BlockchainInfo,
}

/// Synchronization status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    pub is_syncing: bool,
    pub current_block: u64,
    pub target_block: u64,
    pub sync_progress: f64,
    pub estimated_time_remaining: Option<u64>,
}

/// Peer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub connected_peers: u32,
    pub max_peers: u32,
    pub inbound_peers: u32,
    pub outbound_peers: u32,
    pub peer_list: Vec<PeerDetails>,
}

/// Individual peer details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerDetails {
    pub id: String,
    pub address: String,
    pub version: String,
    pub latency_ms: f64,
    pub last_seen: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_time: u64,
}

/// Blockchain information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainInfo {
    pub current_height: u64,
    pub best_block_hash: String,
    pub difficulty: f64,
    pub total_transactions: u64,
    pub mempool_size: u32,
    pub average_block_time: f64,
}

/// Query parameters for API endpoints
#[derive(Debug, Deserialize)]
pub struct TimeRangeQuery {
    pub start: Option<u64>,
    pub end: Option<u64>,
    pub limit: Option<usize>,
}

impl ChartDataStore {
    pub fn new(max_points: usize) -> Self {
        Self {
            latency_history: Vec::new(),
            throughput_history: Vec::new(),
            peer_count_history: Vec::new(),
            mempool_size_history: Vec::new(),
            block_height_history: Vec::new(),
            cpu_usage_history: Vec::new(),
            memory_usage_history: Vec::new(),
            max_points,
        }
    }
    
    pub fn add_data_point(&mut self, chart_type: &str, timestamp: u64, value: f64) {
        let point = TimeSeriesPoint { timestamp, value };
        
        let history = match chart_type {
            "latency" => &mut self.latency_history,
            "throughput" => &mut self.throughput_history,
            "peer_count" => &mut self.peer_count_history,
            "mempool_size" => &mut self.mempool_size_history,
            "block_height" => &mut self.block_height_history,
            "cpu_usage" => &mut self.cpu_usage_history,
            "memory_usage" => &mut self.memory_usage_history,
            _ => return,
        };
        
        history.push(point);
        
        // Keep only the last max_points
        if history.len() > self.max_points {
            history.remove(0);
        }
    }
    
    pub fn get_chart_data(&self, chart_type: &str) -> Vec<TimeSeriesPoint> {
        match chart_type {
            "latency" => self.latency_history.clone(),
            "throughput" => self.throughput_history.clone(),
            "peer_count" => self.peer_count_history.clone(),
            "mempool_size" => self.mempool_size_history.clone(),
            "block_height" => self.block_height_history.clone(),
            "cpu_usage" => self.cpu_usage_history.clone(),
            "memory_usage" => self.memory_usage_history.clone(),
            _ => Vec::new(),
        }
    }
}

/// Dashboard server implementation
pub struct DashboardServer {
    state: DashboardState,
}

impl DashboardServer {
    pub fn new(
        config: DashboardConfig,
        metrics: Arc<NetworkMetrics>,
        alert_manager: Arc<AlertManager>,
    ) -> Self {
        let (websocket_tx, _) = broadcast::channel(1000);
        let chart_data = Arc::new(RwLock::new(ChartDataStore::new(config.max_chart_data_points)));
        
        let state = DashboardState {
            config,
            metrics,
            alert_manager,
            chart_data,
            websocket_tx,
        };
        
        Self { state }
    }
    
    /// Start the dashboard server
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let app = self.create_router();
        
        let addr = format!("{}:{}", self.state.config.bind_address, self.state.config.port);
        info!("Starting dashboard server on {}", addr);
        
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        
        // Start background tasks
        self.start_background_tasks().await;
        
        axum::serve(listener, app).await?;
        
        Ok(())
    }
    
    /// Create the Axum router with all routes
    fn create_router(&self) -> Router {
        Router::new()
            // Static files and main dashboard
            .route("/", get(dashboard_index))
            .route("/dashboard", get(dashboard_index))
            
            // API endpoints
            .route("/api/status", get(get_system_status))
            .route("/api/metrics", get(get_current_metrics))
            .route("/api/metrics/history", get(get_metrics_history))
            .route("/api/alerts", get(get_alerts))
            .route("/api/alerts/stats", get(get_alert_stats))
            .route("/api/alerts/test", post(trigger_test_alert))
            .route("/api/peers", get(get_peer_info))
            .route("/api/blockchain", get(get_blockchain_info))
            .route("/api/charts/:chart_type", get(get_chart_data))
            
            // WebSocket endpoint
            .route("/ws", get(websocket_handler))
            
            // Static assets (if needed)
            .nest_service("/static", ServeDir::new("static"))
            
            .layer(CorsLayer::permissive())
            .with_state(self.state.clone())
    }
    
    /// Start background tasks for data collection and WebSocket updates
    async fn start_background_tasks(&self) {
        let state = self.state.clone();
        
        // Data collection task
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                Duration::from_secs(state.config.update_interval_seconds as u64)
            );
            
            loop {
                interval.tick().await;
                
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                
                // Collect current metrics
                let metrics_snapshot = state.metrics.get_snapshot().await;
                
                // Update chart data
                {
                    let mut chart_data = state.chart_data.write().await;
                    
                    // Add data points for various metrics
                    chart_data.add_data_point("peer_count", timestamp, 
                        state.metrics.connected_peers.load(std::sync::atomic::Ordering::Relaxed) as f64);
                    
                    chart_data.add_data_point("mempool_size", timestamp,
                        state.metrics.mempool_size.load(std::sync::atomic::Ordering::Relaxed) as f64);
                    
                    chart_data.add_data_point("block_height", timestamp,
                        state.metrics.current_block_height.load(std::sync::atomic::Ordering::Relaxed) as f64);
                    
                    // Add more metrics as needed
                    chart_data.add_data_point("latency", timestamp, 50.0); // Placeholder
                    chart_data.add_data_point("throughput", timestamp, 1000.0); // Placeholder
                }
                
                // Send WebSocket update
                let update = DashboardUpdate::MetricsUpdate {
                    timestamp,
                    metrics: metrics_snapshot,
                };
                
                if let Err(e) = state.websocket_tx.send(update) {
                    debug!("No WebSocket subscribers: {}", e);
                }
            }
        });
    }
    
    /// Get the WebSocket sender for external updates
    pub fn get_websocket_sender(&self) -> broadcast::Sender<DashboardUpdate> {
        self.state.websocket_tx.clone()
    }
}

// HTTP Handlers

async fn dashboard_index() -> impl IntoResponse {
    Html(include_str!("dashboard.html"))
}

async fn get_system_status(State(state): State<DashboardState>) -> impl IntoResponse {
    let status = SystemStatus {
        uptime_seconds: 3600, // Placeholder
        node_version: "1.0.0".to_string(),
        network_id: "tsn-mainnet".to_string(),
        sync_status: SyncStatus {
            is_syncing: false,
            current_block: state.metrics.current_block_height.load(std::sync::atomic::Ordering::Relaxed),
            target_block: state.metrics.current_block_height.load(std::sync::atomic::Ordering::Relaxed),
            sync_progress: 100.0,
            estimated_time_remaining: None,
        },
        peer_info: PeerInfo {
            connected_peers: state.metrics.connected_peers.load(std::sync::atomic::Ordering::Relaxed),
            max_peers: 50,
            inbound_peers: 10,
            outbound_peers: 15,
            peer_list: Vec::new(), // Would be populated from actual peer manager
        },
        blockchain_info: BlockchainInfo {
            current_height: state.metrics.current_block_height.load(std::sync::atomic::Ordering::Relaxed),
            best_block_hash: "0x1234...".to_string(),
            difficulty: 1000.0,
            total_transactions: state.metrics.total_transactions.load(std::sync::atomic::Ordering::Relaxed),
            mempool_size: state.metrics.mempool_size.load(std::sync::atomic::Ordering::Relaxed),
            average_block_time: 10.0,
        },
    };
    
    Json(status)
}

async fn get_current_metrics(State(state): State<DashboardState>) -> impl IntoResponse {
    let metrics = state.metrics.get_snapshot().await;
    Json(metrics)
}

async fn get_metrics_history(
    State(state): State<DashboardState>,
    Query(params): Query<TimeRangeQuery>,
) -> impl IntoResponse {
    // This would return historical metrics from storage
    // For now, return current metrics
    let metrics = state.metrics.get_snapshot().await;
    Json(vec![metrics])
}

async fn get_alerts(State(state): State<DashboardState>) -> impl IntoResponse {
    let alerts = state.alert_manager.get_active_alerts().await;
    Json(alerts)
}

async fn get_alert_stats(State(state): State<DashboardState>) -> impl IntoResponse {
    let stats = state.alert_manager.get_alert_stats().await;
    Json(stats)
}

async fn trigger_test_alert(State(state): State<DashboardState>) -> impl IntoResponse {
    state.alert_manager.trigger_test_alert().await;
    Json(serde_json::json!({"status": "ok", "message": "Test alert triggered"}))
}

async fn get_peer_info(State(state): State<DashboardState>) -> impl IntoResponse {
    let peer_info = PeerInfo {
        connected_peers: state.metrics.connected_peers.load(std::sync::atomic::Ordering::Relaxed),
        max_peers: 50,
        inbound_peers: 10,
        outbound_peers: 15,
        peer_list: Vec::new(), // Would be populated from actual peer manager
    };
    
    Json(peer_info)
}

async fn get_blockchain_info(State(state): State<DashboardState>) -> impl IntoResponse {
    let blockchain_info = BlockchainInfo {
        current_height: state.metrics.current_block_height.load(std::sync::atomic::Ordering::Relaxed),
        best_block_hash: "0x1234...".to_string(),
        difficulty: 1000.0,
        total_transactions: state.metrics.total_transactions.load(std::sync::atomic::Ordering::Relaxed),
        mempool_size: state.metrics.mempool_size.load(std::sync::atomic::Ordering::Relaxed),
        average_block_time: 10.0,
    };
    
    Json(blockchain_info)
}

async fn get_chart_data(
    State(state): State<DashboardState>,
    axum::extract::Path(chart_type): axum::extract::Path<String>,
) -> impl IntoResponse {
    let chart_data = state.chart_data.read().await;
    let data = chart_data.get_chart_data(&chart_type);
    Json(data)
}

async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<DashboardState>,
) -> Response {
    ws.on_upgrade(|socket| handle_websocket(socket, state))
}

async fn handle_websocket(socket: WebSocket, state: DashboardState) {
    let mut rx = state.websocket_tx.subscribe();
    let (mut sender, mut receiver) = socket.split();
    
    // Send initial data
    let initial_metrics = state.metrics.get_snapshot().await;
    let initial_update = DashboardUpdate::MetricsUpdate {
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        metrics: initial_metrics,
    };
    
    if let Ok(msg) = serde_json::to_string(&initial_update) {
        if sender.send(axum::extract::ws::Message::Text(msg)).await.is_err() {
            return;
        }
    }
    
    // Handle incoming messages and send updates
    loop {
        tokio::select! {
            // Receive updates from broadcast channel
            update = rx.recv() => {
                match update {
                    Ok(update) => {
                        if let Ok(msg) = serde_json::to_string(&update) {
                            if sender.send(axum::extract::ws::Message::Text(msg)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            
            // Handle incoming WebSocket messages
            msg = receiver.recv() => {
                match msg {
                    Some(Ok(axum::extract::ws::Message::Text(_text))) => {
                        // Handle client requests if needed
                    }
                    Some(Ok(axum::extract::ws::Message::Close(_))) => break,
                    Some(Err(_)) => break,
                    None => break,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::monitoring_config::{DashboardConfig, AlertConfig, ThresholdConfig};
    
    #[test]
    fn test_chart_data_store() {
        let mut store = ChartDataStore::new(5);
        
        // Add some data points
        store.add_data_point("latency", 1000, 50.0);
        store.add_data_point("latency", 1001, 60.0);
        store.add_data_point("latency", 1002, 55.0);
        
        let data = store.get_chart_data("latency");
        assert_eq!(data.len(), 3);
        assert_eq!(data[0].value, 50.0);
        assert_eq!(data[1].value, 60.0);
        assert_eq!(data[2].value, 55.0);
    }
    
    #[test]
    fn test_chart_data_store_max_points() {
        let mut store = ChartDataStore::new(2);
        
        // Add more points than max
        store.add_data_point("latency", 1000, 50.0);
        store.add_data_point("latency", 1001, 60.0);
        store.add_data_point("latency", 1002, 55.0);
        
        let data = store.get_chart_data("latency");
        assert_eq!(data.len(), 2);
        assert_eq!(data[0].value, 60.0); // First point was removed
        assert_eq!(data[1].value, 55.0);
    }
    
    #[tokio::test]
    async fn test_dashboard_server_creation() {
        let config = DashboardConfig::default();
        let metrics = Arc::new(NetworkMetrics::new());
        let alert_manager = Arc::new(AlertManager::new(
            AlertConfig::default(),
            ThresholdConfig::default(),
        ));
        
        let server = DashboardServer::new(config, metrics, alert_manager);
        
        // Test that we can get the WebSocket sender
        let _sender = server.get_websocket_sender();
    }
}