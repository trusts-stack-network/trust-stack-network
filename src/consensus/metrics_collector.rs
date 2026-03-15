/// Metrics collection service for consensus monitoring.
///
/// This module provides a background service that continuously collects
/// consensus metrics and exposes them via HTTP endpoints for monitoring.

use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::interval;
use serde_json::json;
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};

use crate::consensus::metrics::{
    ConsensusMetrics, ConsensusMetricsCalculator, BlockData
};
use crate::core::blockchain::Blockchain;
use crate::network::api::ApiError;

/// Metrics collection interval in seconds.
const METRICS_COLLECTION_INTERVAL_SECS: u64 = 30;

/// HTTP endpoint port for metrics.
const METRICS_PORT: u16 = 8081;

/// Shared metrics state.
pub type MetricsState = Arc<RwLock<ConsensusMetrics>>;

/// Metrics collector service.
pub struct MetricsCollector {
    /// Metrics calculator
    calculator: ConsensusMetricsCalculator,
    
    /// Shared metrics state for HTTP endpoints
    metrics_state: MetricsState,
    
    /// Reference to blockchain for data access
    blockchain: Arc<RwLock<Blockchain>>,
}

impl MetricsCollector {
    /// Create a new metrics collector.
    pub fn new(blockchain: Arc<RwLock<Blockchain>>) -> Self {
        let calculator = ConsensusMetricsCalculator::new();
        let initial_metrics = calculator.calculate_metrics();
        let metrics_state = Arc::new(RwLock::new(initial_metrics));

        Self {
            calculator,
            metrics_state,
            blockchain,
        }
    }

    /// Start the metrics collection service.
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Start background collection task
        let metrics_state = Arc::clone(&self.metrics_state);
        let blockchain = Arc::clone(&self.blockchain);
        let mut calculator = ConsensusMetricsCalculator::new();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(METRICS_COLLECTION_INTERVAL_SECS));
            
            loop {
                interval.tick().await;
                
                // Collect latest blockchain data
                if let Ok(blockchain_guard) = blockchain.read() {
                    // Update calculator with recent blocks
                    Self::update_calculator_with_blockchain_data(&mut calculator, &blockchain_guard);
                    
                    // Calculate new metrics
                    let new_metrics = calculator.calculate_metrics();
                    
                    // Update shared state
                    if let Ok(mut metrics_guard) = metrics_state.write() {
                        *metrics_guard = new_metrics;
                    }
                }
            }
        });

        // Start HTTP metrics server
        self.start_metrics_server().await
    }

    /// Start the HTTP metrics server.
    async fn start_metrics_server(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let app = self.create_metrics_router();
        
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", METRICS_PORT)).await?;
        
        println!("Metrics server starting on port {}", METRICS_PORT);
        axum::serve(listener, app).await?;
        
        Ok(())
    }

    /// Create the metrics HTTP router.
    fn create_metrics_router(&self) -> Router {
        Router::new()
            .route("/metrics", get(get_all_metrics))
            .route("/metrics/consensus", get(get_consensus_metrics))
            .route("/metrics/timing", get(get_timing_metrics))
            .route("/metrics/orphans", get(get_orphan_metrics))
            .route("/metrics/difficulty", get(get_difficulty_metrics))
            .route("/metrics/mining", get(get_mining_metrics))
            .route("/metrics/network", get(get_network_health_metrics))
            .route("/metrics/prometheus", get(get_prometheus_metrics))
            .route("/health", get(health_check))
            .with_state(Arc::clone(&self.metrics_state))
    }

    /// Update calculator with latest blockchain data.
    fn update_calculator_with_blockchain_data(
        calculator: &mut ConsensusMetricsCalculator,
        blockchain: &Blockchain,
    ) {
        // Get recent blocks from blockchain
        let current_height = blockchain.get_height();
        let start_height = current_height.saturating_sub(100); // Last 100 blocks

        for height in start_height..=current_height {
            if let Ok(Some(block)) = blockchain.get_block_by_height(height) {
                let block_data = BlockData {
                    height: block.header.height,
                    timestamp: block.header.timestamp,
                    difficulty: block.header.difficulty,
                    hash: block.hash().to_string(),
                    parent_hash: block.header.previous_hash.to_string(),
                    is_orphan: false, // Would need to check if block is in main chain
                    work: Self::calculate_block_work(block.header.difficulty),
                };

                calculator.add_block(block_data);
            }
        }

        // Check for orphan blocks (simplified - would need proper orphan detection)
        // This would require integration with the blockchain's orphan tracking
    }

    /// Calculate work for a given difficulty.
    fn calculate_block_work(difficulty: u64) -> f64 {
        2_f64.powi(difficulty as i32)
    }
}

/// HTTP handler for all metrics.
async fn get_all_metrics(
    State(metrics_state): State<MetricsState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let metrics = metrics_state
        .read()
        .map_err(|_| ApiError::Internal("Failed to read metrics".to_string()))?;

    Ok(Json(json!({
        "status": "success",
        "data": *metrics,
        "timestamp": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    })))
}

/// HTTP handler for consensus metrics.
async fn get_consensus_metrics(
    State(metrics_state): State<MetricsState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let metrics = metrics_state
        .read()
        .map_err(|_| ApiError::Internal("Failed to read metrics".to_string()))?;

    Ok(Json(json!({
        "height": metrics.height,
        "timing": metrics.timing,
        "orphans": metrics.orphans,
        "difficulty": metrics.difficulty,
        "last_updated": metrics.last_updated
    })))
}

/// HTTP handler for timing metrics.
async fn get_timing_metrics(
    State(metrics_state): State<MetricsState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let metrics = metrics_state
        .read()
        .map_err(|_| ApiError::Internal("Failed to read metrics".to_string()))?;

    Ok(Json(json!(metrics.timing)))
}

/// HTTP handler for orphan metrics.
async fn get_orphan_metrics(
    State(metrics_state): State<MetricsState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let metrics = metrics_state
        .read()
        .map_err(|_| ApiError::Internal("Failed to read metrics".to_string()))?;

    Ok(Json(json!(metrics.orphans)))
}

/// HTTP handler for difficulty metrics.
async fn get_difficulty_metrics(
    State(metrics_state): State<MetricsState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let metrics = metrics_state
        .read()
        .map_err(|_| ApiError::Internal("Failed to read metrics".to_string()))?;

    Ok(Json(json!(metrics.difficulty)))
}

/// HTTP handler for mining metrics.
async fn get_mining_metrics(
    State(metrics_state): State<MetricsState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let metrics = metrics_state
        .read()
        .map_err(|_| ApiError::Internal("Failed to read metrics".to_string()))?;

    Ok(Json(json!(metrics.mining)))
}

/// HTTP handler for network health metrics.
async fn get_network_health_metrics(
    State(metrics_state): State<MetricsState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let metrics = metrics_state
        .read()
        .map_err(|_| ApiError::Internal("Failed to read metrics".to_string()))?;

    Ok(Json(json!(metrics.network)))
}

/// HTTP handler for Prometheus-formatted metrics.
async fn get_prometheus_metrics(
    State(metrics_state): State<MetricsState>,
) -> Result<String, ApiError> {
    let metrics = metrics_state
        .read()
        .map_err(|_| ApiError::Internal("Failed to read metrics".to_string()))?;

    let prometheus_output = format_prometheus_metrics(&metrics);
    Ok(prometheus_output)
}

/// Format metrics in Prometheus format.
fn format_prometheus_metrics(metrics: &ConsensusMetrics) -> String {
    let mut output = String::new();

    // Blockchain height
    output.push_str(&format!("# HELP tsn_blockchain_height Current blockchain height\n"));
    output.push_str(&format!("# TYPE tsn_blockchain_height gauge\n"));
    output.push_str(&format!("tsn_blockchain_height {}\n\n", metrics.height));

    // Block timing metrics
    output.push_str(&format!("# HELP tsn_block_time_avg Average time between blocks in seconds\n"));
    output.push_str(&format!("# TYPE tsn_block_time_avg gauge\n"));
    output.push_str(&format!("tsn_block_time_avg {}\n\n", metrics.timing.avg_block_time));

    output.push_str(&format!("# HELP tsn_block_time_median Median time between blocks in seconds\n"));
    output.push_str(&format!("# TYPE tsn_block_time_median gauge\n"));
    output.push_str(&format!("tsn_block_time_median {}\n\n", metrics.timing.median_block_time));

    output.push_str(&format!("# HELP tsn_block_time_deviation Deviation from target block time percentage\n"));
    output.push_str(&format!("# TYPE tsn_block_time_deviation gauge\n"));
    output.push_str(&format!("tsn_block_time_deviation {}\n\n", metrics.timing.deviation_from_target));

    // Orphan metrics
    output.push_str(&format!("# HELP tsn_orphan_rate Orphan block rate percentage\n"));
    output.push_str(&format!("# TYPE tsn_orphan_rate gauge\n"));
    output.push_str(&format!("tsn_orphan_rate {}\n\n", metrics.orphans.orphan_rate));

    output.push_str(&format!("# HELP tsn_orphan_total Total number of orphan blocks\n"));
    output.push_str(&format!("# TYPE tsn_orphan_total counter\n"));
    output.push_str(&format!("tsn_orphan_total {}\n\n", metrics.orphans.total_orphans));

    // Difficulty metrics
    output.push_str(&format!("# HELP tsn_difficulty_current Current mining difficulty\n"));
    output.push_str(&format!("# TYPE tsn_difficulty_current gauge\n"));
    output.push_str(&format!("tsn_difficulty_current {}\n\n", metrics.difficulty.current_difficulty));

    output.push_str(&format!("# HELP tsn_difficulty_volatility Difficulty volatility (standard deviation)\n"));
    output.push_str(&format!("# TYPE tsn_difficulty_volatility gauge\n"));
    output.push_str(&format!("tsn_difficulty_volatility {}\n\n", metrics.difficulty.difficulty_volatility));

    // Mining metrics
    output.push_str(&format!("# HELP tsn_hashrate_estimated Estimated network hashrate\n"));
    output.push_str(&format!("# TYPE tsn_hashrate_estimated gauge\n"));
    output.push_str(&format!("tsn_hashrate_estimated {}\n\n", metrics.mining.estimated_hashrate));

    output.push_str(&format!("# HELP tsn_mining_efficiency Mining efficiency ratio\n"));
    output.push_str(&format!("# TYPE tsn_mining_efficiency gauge\n"));
    output.push_str(&format!("tsn_mining_efficiency {}\n\n", metrics.mining.mining_efficiency));

    output.push_str(&format!("# HELP tsn_hashrate_stability Hashrate stability coefficient\n"));
    output.push_str(&format!("# TYPE tsn_hashrate_stability gauge\n"));
    output.push_str(&format!("tsn_hashrate_stability {}\n\n", metrics.mining.hashrate_stability));

    // Network health metrics
    output.push_str(&format!("# HELP tsn_network_stability Network stability score (0-100)\n"));
    output.push_str(&format!("# TYPE tsn_network_stability gauge\n"));
    output.push_str(&format!("tsn_network_stability {}\n\n", metrics.network.stability_score));

    output.push_str(&format!("# HELP tsn_fork_frequency Fork frequency per 100 blocks\n"));
    output.push_str(&format!("# TYPE tsn_fork_frequency gauge\n"));
    output.push_str(&format!("tsn_fork_frequency {}\n\n", metrics.network.fork_frequency));

    output.push_str(&format!("# HELP tsn_consensus_participation Consensus participation rate percentage\n"));
    output.push_str(&format!("# TYPE tsn_consensus_participation gauge\n"));
    output.push_str(&format!("tsn_consensus_participation {}\n\n", metrics.network.consensus_participation));

    // Block time distribution histogram
    for (bucket, count) in &metrics.mining.block_time_distribution {
        output.push_str(&format!("# HELP tsn_block_time_distribution Block time distribution by bucket\n"));
        output.push_str(&format!("# TYPE tsn_block_time_distribution histogram\n"));
        output.push_str(&format!("tsn_block_time_distribution{{bucket=\"{}\"}} {}\n", bucket, count));
    }

    output.push('\n');

    // Metadata
    output.push_str(&format!("# HELP tsn_metrics_last_updated Timestamp of last metrics update\n"));
    output.push_str(&format!("# TYPE tsn_metrics_last_updated gauge\n"));
    output.push_str(&format!("tsn_metrics_last_updated {}\n", metrics.last_updated));

    output
}

/// Health check endpoint.
async fn health_check() -> Result<Json<serde_json::Value>, StatusCode> {
    Ok(Json(json!({
        "status": "healthy",
        "service": "tsn-consensus-metrics",
        "timestamp": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    })))
}

/// Metrics export utilities.
pub mod export {
    use super::*;
    use std::fs;
    use std::path::Path;

    /// Export metrics to JSON file.
    pub fn export_metrics_to_json(
        metrics: &ConsensusMetrics,
        file_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json_data = serde_json::to_string_pretty(metrics)?;
        fs::write(file_path, json_data)?;
        Ok(())
    }

    /// Export metrics to CSV format.
    pub fn export_metrics_to_csv(
        metrics: &ConsensusMetrics,
        file_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut csv_content = String::new();
        
        // CSV header
        csv_content.push_str("timestamp,height,avg_block_time,median_block_time,deviation_from_target,");
        csv_content.push_str("orphan_rate,current_difficulty,estimated_hashrate,mining_efficiency,");
        csv_content.push_str("stability_score,fork_frequency\n");

        // CSV data
        csv_content.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{}\n",
            metrics.last_updated,
            metrics.height,
            metrics.timing.avg_block_time,
            metrics.timing.median_block_time,
            metrics.timing.deviation_from_target,
            metrics.orphans.orphan_rate,
            metrics.difficulty.current_difficulty,
            metrics.mining.estimated_hashrate,
            metrics.mining.mining_efficiency,
            metrics.network.stability_score,
            metrics.network.fork_frequency
        ));

        fs::write(file_path, csv_content)?;
        Ok(())
    }

    /// Export Prometheus metrics to file.
    pub fn export_prometheus_metrics(
        metrics: &ConsensusMetrics,
        file_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let prometheus_data = format_prometheus_metrics(metrics);
        fs::write(file_path, prometheus_data)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::metrics::{BlockTimingMetrics, OrphanMetrics, DifficultyMetrics, MiningMetrics, NetworkHealthMetrics};
    use std::collections::HashMap;

    fn create_test_metrics() -> ConsensusMetrics {
        ConsensusMetrics {
            height: 1000,
            timing: BlockTimingMetrics {
                avg_block_time: 10.5,
                median_block_time: 10.0,
                block_time_stddev: 2.1,
                min_block_time: 5.0,
                max_block_time: 20.0,
                target_block_time: 10.0,
                deviation_from_target: 5.0,
                sample_size: 100,
            },
            orphans: OrphanMetrics {
                total_orphans: 5,
                orphan_rate: 0.5,
                recent_orphan_rate: 0.3,
                avg_orphan_depth: 1.2,
                max_orphan_depth: 3,
                time_since_last_orphan: 300,
            },
            difficulty: DifficultyMetrics {
                current_difficulty: 20,
                avg_difficulty: 19.5,
                difficulty_volatility: 1.2,
                adjustments_count: 10,
                avg_adjustment_magnitude: 0.8,
                max_difficulty_increase: 2.0,
                max_difficulty_decrease: 1.5,
                blocks_until_adjustment: 50,
            },
            mining: MiningMetrics {
                estimated_hashrate: 1000000.0,
                hashrate_stability: 0.1,
                mining_efficiency: 0.95,
                avg_work_per_block: 1048576.0,
                total_work: 1048576000.0,
                hashrate_trend: 0.05,
                block_time_distribution: {
                    let mut dist = HashMap::new();
                    dist.insert("6-10s".to_string(), 60);
                    dist.insert("11-20s".to_string(), 30);
                    dist.insert("0-5s".to_string(), 10);
                    dist
                },
            },
            network: NetworkHealthMetrics {
                stability_score: 95.0,
                fork_frequency: 0.1,
                avg_fork_resolution_time: 30.0,
                consensus_participation: 98.0,
                sync_health: 99.0,
                time_since_last_reorg: 3600,
            },
            last_updated: 1640995200,
        }
    }

    #[test]
    fn test_prometheus_format() {
        let metrics = create_test_metrics();
        let prometheus_output = format_prometheus_metrics(&metrics);
        
        assert!(prometheus_output.contains("tsn_blockchain_height 1000"));
        assert!(prometheus_output.contains("tsn_block_time_avg 10.5"));
        assert!(prometheus_output.contains("tsn_orphan_rate 0.5"));
        assert!(prometheus_output.contains("tsn_difficulty_current 20"));
        assert!(prometheus_output.contains("tsn_hashrate_estimated 1000000"));
        assert!(prometheus_output.contains("tsn_network_stability 95"));
    }

    #[test]
    fn test_json_export() {
        let metrics = create_test_metrics();
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join("test_metrics.json");
        
        export::export_metrics_to_json(&metrics, &file_path).unwrap();
        
        let content = std::fs::read_to_string(&file_path).unwrap();
        assert!(content.contains("\"height\": 1000"));
        assert!(content.contains("\"avg_block_time\": 10.5"));
        
        // Cleanup
        std::fs::remove_file(&file_path).ok();
    }

    #[test]
    fn test_csv_export() {
        let metrics = create_test_metrics();
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join("test_metrics.csv");
        
        export::export_metrics_to_csv(&metrics, &file_path).unwrap();
        
        let content = std::fs::read_to_string(&file_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        
        assert_eq!(lines.len(), 2); // Header + data
        assert!(lines[0].contains("timestamp,height,avg_block_time"));
        assert!(lines[1].contains("1640995200,1000,10.5"));
        
        // Cleanup
        std::fs::remove_file(&file_path).ok();
    }

    #[test]
    fn test_prometheus_export() {
        let metrics = create_test_metrics();
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join("test_metrics.prom");
        
        export::export_prometheus_metrics(&metrics, &file_path).unwrap();
        
        let content = std::fs::read_to_string(&file_path).unwrap();
        assert!(content.contains("# HELP tsn_blockchain_height"));
        assert!(content.contains("tsn_blockchain_height 1000"));
        
        // Cleanup
        std::fs::remove_file(&file_path).ok();
    }
}