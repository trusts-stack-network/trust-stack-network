//! HTTP server for exposing Prometheus metrics and health endpoints
//!
//! Provides /metrics endpoint for Prometheus scraping and /health for monitoring.

use std::sync::Arc;
use std::net::SocketAddr;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::Value;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing::{info, error};

use super::metrics::MetricsCollector;

/// Metrics server state
#[derive(Clone)]
pub struct MetricsServerState {
    pub collector: Arc<MetricsCollector>,
}

/// Start the metrics HTTP server
pub async fn start_metrics_server(
    collector: Arc<MetricsCollector>,
    bind_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = MetricsServerState { collector };
    
    let app = Router::new()
        .route("/metrics", get(prometheus_metrics))
        .route("/metrics/json", get(json_metrics))
        .route("/health", get(health_check))
        .route("/health/ready", get(readiness_check))
        .route("/health/live", get(liveness_check))
        .layer(CorsLayer::permissive())
        .with_state(state);
    
    let listener = TcpListener::bind(bind_addr).await?;
    info!("Metrics server listening on {}", bind_addr);
    
    axum::serve(listener, app).await?;
    
    Ok(())
}

/// Prometheus metrics endpoint
async fn prometheus_metrics(
    State(state): State<MetricsServerState>,
) -> Result<Response, StatusCode> {
    match get_prometheus_metrics_internal(&state.collector).await {
        Ok(metrics) => Ok((
            StatusCode::OK,
            [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
            metrics,
        ).into_response()),
        Err(e) => {
            error!("Failed to generate Prometheus metrics: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// JSON metrics endpoint
async fn json_metrics(
    State(state): State<MetricsServerState>,
) -> Result<Json<Value>, StatusCode> {
    match get_json_metrics_internal(&state.collector).await {
        Ok(metrics) => Ok(Json(metrics)),
        Err(e) => {
            error!("Failed to generate JSON metrics: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Health check endpoint
async fn health_check(
    State(state): State<MetricsServerState>,
) -> impl IntoResponse {
    let health_status = check_node_health(&state.collector).await;
    
    let status_code = if health_status["healthy"].as_bool().unwrap_or(false) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    
    (status_code, Json(health_status))
}

/// Readiness check endpoint (for Kubernetes)
async fn readiness_check(
    State(state): State<MetricsServerState>,
) -> impl IntoResponse {
    let ready = check_node_readiness(&state.collector).await;
    
    let response = serde_json::json!({
        "ready": ready,
        "timestamp": chrono::Utc::now().timestamp()
    });
    
    let status_code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    
    (status_code, Json(response))
}

/// Liveness check endpoint (for Kubernetes)
async fn liveness_check(
    State(state): State<MetricsServerState>,
) -> impl IntoResponse {
    let alive = check_node_liveness(&state.collector).await;
    
    let response = serde_json::json!({
        "alive": alive,
        "timestamp": chrono::Utc::now().timestamp()
    });
    
    let status_code = if alive {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    
    (status_code, Json(response))
}

/// Internal function to get Prometheus metrics
async fn get_prometheus_metrics_internal(
    collector: &MetricsCollector,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let metrics = collector.get_prometheus_metrics().await;
    Ok(metrics)
}

/// Internal function to get JSON metrics
async fn get_json_metrics_internal(
    collector: &MetricsCollector,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let metrics = collector.get_json_metrics().await;
    Ok(metrics)
}

/// Check overall node health
async fn check_node_health(collector: &MetricsCollector) -> Value {
    let metrics = &collector.metrics;
    
    // Health criteria
    let connected_peers = metrics.connected_peers.load(std::sync::atomic::Ordering::Relaxed);
    let network_errors = metrics.network_errors.load(std::sync::atomic::Ordering::Relaxed);
    let uptime = metrics.uptime_seconds.load(std::sync::atomic::Ordering::Relaxed);
    let sync_lag = metrics.block_sync_lag.load(std::sync::atomic::Ordering::Relaxed);
    let memory_usage = metrics.memory_usage_bytes.load(std::sync::atomic::Ordering::Relaxed);
    
    // Health checks
    let has_peers = connected_peers > 0;
    let low_error_rate = network_errors < 100; // Arbitrary threshold
    let running_long_enough = uptime > 60; // At least 1 minute
    let sync_ok = sync_lag < 10; // Less than 10 blocks behind
    let memory_ok = memory_usage < 8_000_000_000; // Less than 8GB (arbitrary)
    
    let healthy = has_peers && low_error_rate && running_long_enough && sync_ok && memory_ok;
    
    let mut issues = Vec::new();
    if !has_peers {
        issues.push("No connected peers");
    }
    if !low_error_rate {
        issues.push("High network error rate");
    }
    if !running_long_enough {
        issues.push("Node just started");
    }
    if !sync_ok {
        issues.push("Block sync lagging");
    }
    if !memory_ok {
        issues.push("High memory usage");
    }
    
    serde_json::json!({
        "healthy": healthy,
        "timestamp": chrono::Utc::now().timestamp(),
        "checks": {
            "peers_connected": has_peers,
            "low_error_rate": low_error_rate,
            "uptime_sufficient": running_long_enough,
            "sync_current": sync_ok,
            "memory_usage_ok": memory_ok
        },
        "issues": issues,
        "metrics": {
            "connected_peers": connected_peers,
            "network_errors": network_errors,
            "uptime_seconds": uptime,
            "sync_lag_blocks": sync_lag,
            "memory_usage_bytes": memory_usage
        }
    })
}

/// Check if node is ready to serve traffic
async fn check_node_readiness(collector: &MetricsCollector) -> bool {
    let metrics = &collector.metrics;
    
    // Readiness criteria (more strict than health)
    let connected_peers = metrics.connected_peers.load(std::sync::atomic::Ordering::Relaxed);
    let sync_lag = metrics.block_sync_lag.load(std::sync::atomic::Ordering::Relaxed);
    let uptime = metrics.uptime_seconds.load(std::sync::atomic::Ordering::Relaxed);
    
    // Node is ready if:
    // - Has at least 2 peers
    // - Sync lag is less than 3 blocks
    // - Running for at least 2 minutes
    connected_peers >= 2 && sync_lag < 3 && uptime > 120
}

/// Check if node is alive (basic liveness)
async fn check_node_liveness(collector: &MetricsCollector) -> bool {
    let metrics = &collector.metrics;
    
    // Very basic liveness check
    let uptime = metrics.uptime_seconds.load(std::sync::atomic::Ordering::Relaxed);
    let memory_usage = metrics.memory_usage_bytes.load(std::sync::atomic::Ordering::Relaxed);
    
    // Node is alive if:
    // - Has been running for at least 10 seconds
    // - Memory usage is not excessive (less than 16GB)
    uptime > 10 && memory_usage < 16_000_000_000
}

/// Configuration for metrics server
#[derive(Debug, Clone)]
pub struct MetricsServerConfig {
    pub bind_addr: SocketAddr,
    pub enable_cors: bool,
    pub enable_health_checks: bool,
}

impl Default for MetricsServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:9090".parse().unwrap(),
            bind_addr: "0.0.0.0:9090".parse().unwrap(),
            enable_cors: true,
            enable_health_checks: true,
        }
    }
}

/// Start metrics server with custom configuration
pub async fn start_metrics_server_with_config(
    collector: Arc<MetricsCollector>,
    config: MetricsServerConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = MetricsServerState { collector };
    
    let mut app = Router::new()
        .route("/metrics", get(prometheus_metrics))
        .route("/metrics/json", get(json_metrics));
    
    if config.enable_health_checks {
        app = app
            .route("/health", get(health_check))
            .route("/health/ready", get(readiness_check))
            .route("/health/live", get(liveness_check));
    }
    
    if config.enable_cors {
        app = app.layer(CorsLayer::permissive());
    }
    
    app = app.with_state(state);
    
    let listener = TcpListener::bind(config.bind_addr).await?;
    info!("Metrics server listening on {} with config: {:?}", config.bind_addr, config);
    
    axum::serve(listener, app).await?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;
    
    #[tokio::test]
    async fn test_metrics_server_startup() {
        let collector = Arc::new(MetricsCollector::new());
        let addr = "127.0.0.1:0".parse().unwrap(); // Use random port
        
        // Start server in background
        let server_handle = tokio::spawn(async move {
            start_metrics_server(collector, addr).await
        });
        
        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Server should be running (we can't easily test HTTP requests without more setup)
        assert!(!server_handle.is_finished());
        
        // Cancel the server
        server_handle.abort();
    }
    
    #[tokio::test]
    async fn test_health_check_logic() {
        let collector = Arc::new(MetricsCollector::new());
        
        // Initially unhealthy (no peers, just started)
        let health = check_node_health(&collector).await;
        assert_eq!(health["healthy"].as_bool().unwrap(), false);
        
        // Simulate some uptime and peers
        collector.metrics.uptime_seconds.store(120, std::sync::atomic::Ordering::Relaxed);
        collector.peer_connected("127.0.0.1:8333");
        
        let health = check_node_health(&collector).await;
        // Should be healthier now, but might still fail other checks
        assert!(health["checks"]["uptime_sufficient"].as_bool().unwrap());
        assert!(health["checks"]["peers_connected"].as_bool().unwrap());
    }
    
    #[tokio::test]
    async fn test_readiness_and_liveness() {
        let collector = Arc::new(MetricsCollector::new());
        
        // Initially not ready or alive
        assert!(!check_node_readiness(&collector).await);
        assert!(!check_node_liveness(&collector).await);
        
        // Simulate minimal liveness
        collector.metrics.uptime_seconds.store(30, std::sync::atomic::Ordering::Relaxed);
        assert!(check_node_liveness(&collector).await);
        assert!(!check_node_readiness(&collector).await); // Still not ready
        
        // Simulate full readiness
        collector.metrics.uptime_seconds.store(180, std::sync::atomic::Ordering::Relaxed);
        collector.peer_connected("peer1");
        collector.peer_connected("peer2");
        collector.metrics.block_sync_lag.store(1, std::sync::atomic::Ordering::Relaxed);
        
        assert!(check_node_liveness(&collector).await);
        assert!(check_node_readiness(&collector).await);
    }
}