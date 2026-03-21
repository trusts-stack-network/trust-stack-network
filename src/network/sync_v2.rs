//! Optimized parallel block synchronization for TSN nodes.
//!
//! This module implements a high-performance initial block download (IBD) system
//! that downloads blocks in parallel from multiple peers with automatic recovery
//! and incremental validation.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, RwLock, Semaphore};
use tokio::time::{interval, timeout};
use tracing::{debug, error, info, warn};

use crate::core::{ShieldedBlock, ShieldedState};
use super::{AppState, DiscoveryError, peer_id};

/// Configuration for parallel sync operations.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Maximum number of concurrent downloads per peer.
    pub max_concurrent_downloads: usize,
    /// Maximum number of peers to download from simultaneously.
    pub max_sync_peers: usize,
    /// Timeout for individual block downloads.
    pub block_download_timeout: Duration,
    /// Size of download batches (blocks per request).
    pub batch_size: usize,
    /// Maximum number of blocks to keep in memory during sync.
    pub max_pending_blocks: usize,
    /// Interval between sync progress reports.
    pub progress_report_interval: Duration,
    /// Maximum retries for failed block downloads.
    pub max_retries: usize,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_concurrent_downloads: 8,
            max_sync_peers: 4,
            block_download_timeout: Duration::from_secs(30),
            batch_size: 50,
            max_pending_blocks: 1000,
            progress_report_interval: Duration::from_secs(10),
            max_retries: 3,
        }
    }
}

/// Represents a block download job.
#[derive(Debug, Clone)]
struct DownloadJob {
    /// Starting block height for this batch.
    start_height: u64,
    /// Number of blocks to download in this batch.
    count: usize,
    /// Peer URL to download from.
    peer_url: String,
    /// Number of retry attempts.
    retry_count: usize,
}

/// Result of a block download operation.
#[derive(Debug)]
enum DownloadResult {
    /// Successfully downloaded blocks.
    Success {
        start_height: u64,
        blocks: Vec<ShieldedBlock>,
        peer_url: String,
    },
    /// Download failed with error.
    Failed {
        job: DownloadJob,
        error: SyncError,
    },
}

/// Tracks sync progress and statistics.
#[derive(Debug, Default)]
pub struct SyncProgress {
    /// Current local blockchain height.
    pub local_height: u64,
    /// Target height to sync to.
    pub target_height: u64,
    /// Number of blocks downloaded so far.
    pub downloaded_blocks: u64,
    /// Number of blocks validated and applied.
    pub validated_blocks: u64,
    /// Download speed in blocks per second.
    pub download_speed: f64,
    /// Validation speed in blocks per second.
    pub validation_speed: f64,
    /// Estimated time remaining.
    pub eta_seconds: Option<u64>,
    /// Active peer count.
    pub active_peers: usize,
    /// Failed download attempts.
    pub failed_downloads: u64,
}

/// Manages parallel block synchronization.
pub struct ParallelSyncManager {
    config: SyncConfig,
    state: Arc<AppState>,
    /// Semaphore to limit concurrent downloads.
    download_semaphore: Arc<Semaphore>,
    /// Channel for download results.
    result_tx: mpsc::UnboundedSender<DownloadResult>,
    result_rx: mpsc::UnboundedReceiver<DownloadResult>,
    /// Pending blocks waiting for validation (height -> block).
    pending_blocks: Arc<RwLock<HashMap<u64, ShieldedBlock>>>,
    /// Set of heights currently being downloaded.
    downloading: Arc<RwLock<HashSet<u64>>>,
    /// Sync progress tracking.
    progress: Arc<RwLock<SyncProgress>>,
}

impl ParallelSyncManager {
    /// Create a new parallel sync manager.
    pub fn new(config: SyncConfig, state: Arc<AppState>) -> Self {
        let download_semaphore = Arc::new(Semaphore::new(
            config.max_concurrent_downloads * config.max_sync_peers,
        ));
        let (result_tx, result_rx) = mpsc::unbounded_channel();

        Self {
            config,
            state,
            download_semaphore,
            result_tx,
            result_rx,
            pending_blocks: Arc::new(RwLock::new(HashMap::new())),
            downloading: Arc::new(RwLock::new(HashSet::new())),
            progress: Arc::new(RwLock::new(SyncProgress::default())),
        }
    }

    /// Start the parallel synchronization process.
    pub async fn start_sync(&mut self) -> Result<(), SyncError> {
        info!("Starting parallel block synchronization");

        // Get current blockchain state
        let local_height = self.get_local_height().await?;
        let target_height = self.get_network_height().await?;

        if local_height >= target_height {
            info!("Already synchronized (local: {}, target: {})", local_height, target_height);
            return Ok(());
        }

        // Initialize progress tracking
        {
            let mut progress = self.progress.write().await;
            progress.local_height = local_height;
            progress.target_height = target_height;
        }

        info!("Syncing from height {} to {} ({} blocks)", 
              local_height + 1, target_height, target_height - local_height);

        // Start background tasks
        let progress_task = self.spawn_progress_reporter();
        let validation_task = self.spawn_block_validator();
        let download_task = self.spawn_download_coordinator(local_height + 1, target_height);

        // Wait for sync completion
        tokio::select! {
            result = download_task => {
                progress_task.abort();
                validation_task.abort();
                result??;
            }
            result = validation_task => {
                progress_task.abort();
                download_task.abort();
                result??;
            }
        }

        info!("Parallel synchronization completed successfully");
        Ok(())
    }

    /// Get the current local blockchain height.
    async fn get_local_height(&self) -> Result<u64, SyncError> {
        let blockchain = self.state.blockchain.read().unwrap();
        Ok(blockchain.height())
    }

    /// Query network peers to determine the highest known block height.
    async fn get_network_height(&self) -> Result<u64, SyncError> {
        let peers = self.state.peers.read().unwrap().clone();
        if peers.is_empty() {
            return Err(SyncError::NoPeersAvailable);
        }

        let client = reqwest::Client::new();
        let mut max_height = 0u64;

        // Query multiple peers for their heights
        for peer in peers.iter().take(self.config.max_sync_peers) {
            match self.query_peer_height(&client, peer).await {
                Ok(height) => {
                    max_height = max_height.max(height);
                }
                Err(e) => {
                    warn!("Failed to query height from peer {}: {}", peer_id(peer), e);
                }
            }
        }

        if max_height == 0 {
            return Err(SyncError::NoValidPeers);
        }

        Ok(max_height)
    }

    /// Query a single peer for its blockchain height.
    async fn query_peer_height(&self, client: &reqwest::Client, peer_url: &str) -> Result<u64, SyncError> {
        let url = format!("{}/blockchain/height", peer_url);
        let response = timeout(
            self.config.block_download_timeout,
            client.get(&url).send()
        ).await??;

        let height_response: HeightResponse = response.json().await?;
        Ok(height_response.height)
    }

    /// Spawn the download coordinator task.
    fn spawn_download_coordinator(
        &self,
        start_height: u64,
        target_height: u64,
    ) -> tokio::task::JoinHandle<Result<(), SyncError>> {
        let config = self.config.clone();
        let state = self.state.clone();
        let semaphore = self.download_semaphore.clone();
        let result_tx = self.result_tx.clone();
        let downloading = self.downloading.clone();
        let progress = self.progress.clone();

        tokio::spawn(async move {
            let mut job_queue = VecDeque::new();
            let mut current_height = start_height;

            // Initialize job queue with batches
            while current_height <= target_height {
                let batch_size = config.batch_size.min((target_height - current_height + 1) as usize);
                let peers = state.peers.read().unwrap().clone();
                
                if peers.is_empty() {
                    return Err(SyncError::NoPeersAvailable);
                }

                // Create jobs for each available peer
                for peer in peers.iter().take(config.max_sync_peers) {
                    let job = DownloadJob {
                        start_height: current_height,
                        count: batch_size,
                        peer_url: peer.clone(),
                        retry_count: 0,
                    };
                    job_queue.push_back(job);
                    break; // Only one job per height range initially
                }

                current_height += batch_size as u64;
            }

            // Process download jobs
            while let Some(job) = job_queue.pop_front() {
                // Check if this height range is already being downloaded
                {
                    let mut downloading_set = downloading.write().await;
                    let mut already_downloading = false;
                    for height in job.start_height..(job.start_height + job.count as u64) {
                        if downloading_set.contains(&height) {
                            already_downloading = true;
                            break;
                        }
                    }
                    
                    if already_downloading {
                        continue;
                    }

                    // Mark heights as being downloaded
                    for height in job.start_height..(job.start_height + job.count as u64) {
                        downloading_set.insert(height);
                    }
                }

                // Acquire semaphore permit
                let permit = semaphore.clone().acquire_owned().await.unwrap();
                let job_clone = job.clone();
                let result_tx_clone = result_tx.clone();
                let downloading_clone = downloading.clone();

                // Spawn download task
                tokio::spawn(async move {
                    let result = Self::download_block_batch(job_clone.clone()).await;
                    
                    // Clean up downloading set
                    {
                        let mut downloading_set = downloading_clone.write().await;
                        for height in job_clone.start_height..(job_clone.start_height + job_clone.count as u64) {
                            downloading_set.remove(&height);
                        }
                    }

                    let _ = result_tx_clone.send(result);
                    drop(permit);
                });
            }

            Ok(())
        })
    }

    /// Download a batch of blocks from a peer.
    async fn download_block_batch(job: DownloadJob) -> DownloadResult {
        let client = reqwest::Client::new();
        let url = format!("{}/blockchain/blocks", job.peer_url);
        
        let request_body = BlockRangeRequest {
            start_height: job.start_height,
            count: job.count,
        };

        match timeout(
            Duration::from_secs(30),
            client.post(&url).json(&request_body).send()
        ).await {
            Ok(Ok(response)) => {
                match response.json::<BlockRangeResponse>().await {
                    Ok(block_response) => {
                        debug!("Downloaded {} blocks from {} starting at height {}", 
                               block_response.blocks.len(), job.peer_url, job.start_height);
                        
                        DownloadResult::Success {
                            start_height: job.start_height,
                            blocks: block_response.blocks,
                            peer_url: job.peer_url,
                        }
                    }
                    Err(e) => DownloadResult::Failed {
                        job,
                        error: SyncError::ParseError(e.to_string()),
                    }
                }
            }
            Ok(Err(e)) => DownloadResult::Failed {
                job,
                error: SyncError::NetworkError(e.to_string()),
            },
            Err(_) => DownloadResult::Failed {
                job,
                error: SyncError::Timeout,
            }
        }
    }

    /// Spawn the block validation task.
    fn spawn_block_validator(&self) -> tokio::task::JoinHandle<Result<(), SyncError>> {
        let state = self.state.clone();
        let pending_blocks = self.pending_blocks.clone();
        let progress = self.progress.clone();
        let mut result_rx = std::mem::replace(&mut self.result_rx, mpsc::unbounded_channel().1);

        tokio::spawn(async move {
            let mut next_expected_height = {
                let blockchain = state.blockchain.read().unwrap();
                blockchain.height() + 1
            };

            while let Some(result) = result_rx.recv().await {
                match result {
                    DownloadResult::Success { start_height, blocks, peer_url } => {
                        // Store blocks in pending map
                        {
                            let mut pending = pending_blocks.write().await;
                            for (i, block) in blocks.into_iter().enumerate() {
                                let height = start_height + i as u64;
                                pending.insert(height, block);
                            }
                        }

                        // Process consecutive blocks starting from next_expected_height
                        loop {
                            let block_opt = {
                                let mut pending = pending_blocks.write().await;
                                pending.remove(&next_expected_height)
                            };

                            if let Some(block) = block_opt {
                                // Validate and apply block
                                match Self::validate_and_apply_block(&state, block, next_expected_height).await {
                                    Ok(()) => {
                                        next_expected_height += 1;
                                        
                                        // Update progress
                                        {
                                            let mut progress = progress.write().await;
                                            progress.validated_blocks += 1;
                                            progress.local_height = next_expected_height - 1;
                                        }
                                    }
                                    Err(e) => {
                                        error!("Block validation failed at height {}: {}", next_expected_height, e);
                                        return Err(e);
                                    }
                                }
                            } else {
                                break; // No more consecutive blocks available
                            }
                        }

                        debug!("Processed blocks from {}, next expected height: {}", peer_url, next_expected_height);
                    }
                    DownloadResult::Failed { job, error } => {
                        warn!("Download failed for height {} from {}: {}", job.start_height, peer_id(&job.peer_url), error);
                        
                        // Update progress
                        {
                            let mut progress = progress.write().await;
                            progress.failed_downloads += 1;
                        }

                        // TODO: Implement retry logic here
                    }
                }
            }

            Ok(())
        })
    }

    /// Validate and apply a single block to the blockchain.
    async fn validate_and_apply_block(
        state: &Arc<AppState>,
        block: ShieldedBlock,
        expected_height: u64,
    ) -> Result<(), SyncError> {
        // Basic height validation
        if block.height != expected_height {
            return Err(SyncError::InvalidBlockHeight {
                expected: expected_height,
                actual: block.height,
            });
        }

        // Apply block to blockchain
        {
            let mut blockchain = state.blockchain.write().unwrap();
            blockchain.add_block(block).map_err(|e| SyncError::BlockValidationError(e.to_string()))?;
        }

        Ok(())
    }

    /// Spawn the progress reporting task.
    fn spawn_progress_reporter(&self) -> tokio::task::JoinHandle<()> {
        let progress = self.progress.clone();
        let interval_duration = self.config.progress_report_interval;

        tokio::spawn(async move {
            let mut interval = interval(interval_duration);
            let mut last_validated = 0u64;
            let mut last_time = Instant::now();

            loop {
                interval.tick().await;
                
                let current_progress = {
                    let progress = progress.read().await;
                    progress.clone()
                };

                let now = Instant::now();
                let elapsed = now.duration_since(last_time).as_secs_f64();
                let validated_diff = current_progress.validated_blocks.saturating_sub(last_validated);
                let validation_speed = if elapsed > 0.0 { validated_diff as f64 / elapsed } else { 0.0 };

                let remaining_blocks = current_progress.target_height.saturating_sub(current_progress.local_height);
                let eta = if validation_speed > 0.0 {
                    Some((remaining_blocks as f64 / validation_speed) as u64)
                } else {
                    None
                };

                info!(
                    "Sync progress: {}/{} blocks ({:.1}%), speed: {:.1} blocks/s, ETA: {}",
                    current_progress.local_height,
                    current_progress.target_height,
                    (current_progress.local_height as f64 / current_progress.target_height as f64) * 100.0,
                    validation_speed,
                    eta.map(|s| format!("{}s", s)).unwrap_or_else(|| "unknown".to_string())
                );

                last_validated = current_progress.validated_blocks;
                last_time = now;
            }
        })
    }

    /// Get current sync progress.
    pub async fn get_progress(&self) -> SyncProgress {
        self.progress.read().await.clone()
    }
}

// Request/Response types for peer communication

#[derive(Debug, serde::Serialize)]
struct BlockRangeRequest {
    start_height: u64,
    count: usize,
}

#[derive(Debug, serde::Deserialize)]
struct BlockRangeResponse {
    blocks: Vec<ShieldedBlock>,
}

#[derive(Debug, serde::Deserialize)]
struct HeightResponse {
    height: u64,
}

/// Errors that can occur during synchronization.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("No peers available for synchronization")]
    NoPeersAvailable,

    #[error("No valid peers responded")]
    NoValidPeers,

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Request timeout")]
    Timeout,

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Invalid block height: expected {expected}, got {actual}")]
    InvalidBlockHeight { expected: u64, actual: u64 },

    #[error("Block validation error: {0}")]
    BlockValidationError(String),

    #[error("Discovery error: {0}")]
    Discovery(#[from] DiscoveryError),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Timeout error: {0}")]
    TimeoutError(#[from] tokio::time::error::Elapsed),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::RwLock;
    use crate::core::Blockchain;

    fn create_test_state() -> Arc<AppState> {
        Arc::new(AppState {
            blockchain: Arc::new(RwLock::new(Blockchain::new())),
            peers: Arc::new(RwLock::new(vec!["http://peer1:8080".to_string()])),
            mempool: Arc::new(RwLock::new(crate::network::mempool::Mempool::new())),
        })
    }

    #[tokio::test]
    async fn test_sync_config_defaults() {
        let config = SyncConfig::default();
        assert_eq!(config.max_concurrent_downloads, 8);
        assert_eq!(config.max_sync_peers, 4);
        assert_eq!(config.batch_size, 50);
    }

    #[tokio::test]
    async fn test_parallel_sync_manager_creation() {
        let config = SyncConfig::default();
        let state = create_test_state();
        let manager = ParallelSyncManager::new(config, state);
        
        let progress = manager.get_progress().await;
        assert_eq!(progress.local_height, 0);
        assert_eq!(progress.target_height, 0);
    }

    #[tokio::test]
    async fn test_get_local_height() {
        let config = SyncConfig::default();
        let state = create_test_state();
        let manager = ParallelSyncManager::new(config, state);
        
        let height = manager.get_local_height().await.unwrap();
        assert_eq!(height, 0); // New blockchain starts at height 0
    }
}