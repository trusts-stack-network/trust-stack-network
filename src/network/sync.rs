use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

use crate::core::ShieldedBlock;

use crate::network::api::AppState;

/// Sync the local chain from a peer node.
/// Handles both catching up and chain reorganizations.
pub async fn sync_from_peer(state: Arc<AppState>, peer_url: &str) -> Result<u64, SyncError> {
    let client = reqwest::Client::new();

    // Get peer's chain info
    let info_url = format!("{}/chain/info", peer_url);
    let response = client
        .get(&info_url)
        .send()
        .await?;

    // Check for rate limiting or other HTTP errors
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(SyncError::HttpError(format!("HTTP {}: {}", status, body)));
    }

    let peer_info: PeerChainInfo = response.json().await?;

    let (local_height, local_hash) = {
        // SECURITY FIX: Gestion sécurisée du RwLock poisoning
        // Un thread qui panique en tenant le lock empoisonne le RwLock
        // → Tous les threads suivants paniquent aussi → DoS total
        let chain = state.blockchain.read()
            .map_err(|e| SyncError::LockPoisoned(format!("Blockchain read lock poisoned: {}", e)))?;
        (chain.height(), hex::encode(chain.latest_hash()))
    };

    // Check if peer is ahead OR if we have a fork at the same height
    let is_fork = peer_info.height == local_height && peer_info.latest_hash != local_hash;
    let peer_ahead = peer_info.height > local_height;

    if !peer_ahead && !is_fork {
        info!(
            "Peer {} is not ahead (peer: {}, local: {})",
            peer_url, peer_info.height, local_height
        );
        return Ok(0);
    }

    if is_fork {
        info!(
            "Fork detected with peer {} at height {} (peer: {}..., local: {}...)",
            peer_url, peer_info.height, &peer_info.latest_hash[..16], &local_hash[..16]
        );
    } else {
        info!(
            "Syncing from peer {} (peer height: {}, local: {})",
            peer_url, peer_info.height, local_height
        );
    }

    // Find common ancestor by checking recent blocks
    let sync_from_height = if is_fork {
        find_common_ancestor(&state, &client, peer_url, local_height).await?
    } else {
        local_height
    };

    // Fetch blocks from common ancestor
    let blocks_url = format!("{}/blocks/since/{}", peer_url, sync_from_height);
    let response = client
        .get(&blocks_url)
        .send()
        .await?;

    // Check for rate limiting or other HTTP errors
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(SyncError::HttpError(format!("HTTP {}: {}", status, body)));
    }

    let blocks: Vec<ShieldedBlock> = response.json().await?;

    let mut synced = 0u64;
    let mut reorged = false;
    let total_blocks = blocks.len() as u64;
    let show_progress = total_blocks > 0;

    for (idx, block) in blocks.into_iter().enumerate() {
        // SECURITY FIX: Gestion sécurisée du RwLock poisoning
        let mut chain = state.blockchain.write()
            .map_err(|e| SyncError::LockPoisoned(format!("Blockchain write lock poisoned: {}", e)))?;
        match chain.try_add_block(block) {
            Ok(true) => {
                synced += 1;
                if is_fork && !reorged {
                    reorged = true;
                    info!("Chain reorganization triggered from peer {}", peer_url);
                }
            }
            Ok(false) => {
                // Block was duplicate or stored as side chain - continue
            }
            Err(e) => {
                warn!("Failed to add block during sync: {}", e);
                break;
            }
        }

        if show_progress {
            let current = (idx as u64) + 1;
            if current == total_blocks || current % 100 == 0 {
                use std::io::{self, Write};
                print!("\rSyncing blocks: {}/{}", current, total_blocks);
                let _ = io::stdout().flush();
                if current == total_blocks {
                    println!();
                }
            }
        }
    }

    if synced > 0 {
        if reorged {
            // SECURITY FIX: Gestion sécurisée du RwLock poisoning
            let height = state.blockchain.read()
                .map_err(|e| SyncError::LockPoisoned(format!("Blockchain read lock poisoned: {}", e)))?
                .height();
            info!("Reorg complete: synced {} blocks from {} (new height: {})",
                synced, peer_url, height);
        } else {
            info!("Synced {} blocks from {}", synced, peer_url);
        }
    }
    Ok(synced)
}

/// Find the common ancestor block between our chain and the peer's chain.
/// Returns the height to sync from.
async fn find_common_ancestor(
    state: &Arc<AppState>,
    client: &reqwest::Client,
    peer_url: &str,
    start_height: u64,
) -> Result<u64, SyncError> {
    // Check recent blocks to find where chains diverged
    // Start from current height and go back until we find a matching block
    let check_depth = 100u64.min(start_height); // Don't go back more than 100 blocks

    for offset in 0..check_depth {
        let height = start_height - offset;

        // Get our block at this height
        // SECURITY FIX: Gestion sécurisée du RwLock poisoning
        let local_hash = {
            let chain = state.blockchain.read()
                .map_err(|e| SyncError::LockPoisoned(format!("Blockchain read lock poisoned: {}", e)))?;
            chain.get_block_by_height(height).map(|b| hex::encode(b.hash()))
        };

        if let Some(local_hash) = local_hash {
            // Get peer's block at this height
            let block_url = format!("{}/block/height/{}", peer_url, height);
            if let Ok(resp) = client.get(&block_url).send().await {
                if resp.status().is_success() {
                    if let Ok(peer_block) = resp.json::<PeerBlockInfo>().await {
                        if peer_block.hash == local_hash {
                            info!("Found common ancestor at height {}", height);
                            return Ok(height);
                        }
                    }
                }
            }
        }
    }

    // If we can't find common ancestor in recent blocks, sync from beginning
    // This is a safety fallback - shouldn't normally happen
    warn!("Could not find common ancestor in last {} blocks, syncing from genesis", check_depth);
    Ok(0)
}

/// Broadcast a newly mined block to all peers.
pub async fn broadcast_block(block: &ShieldedBlock, peers: &[String]) -> Vec<Result<(), SyncError>> {
    let client = reqwest::Client::new();
    let mut results = Vec::new();

    for peer in peers {
        let url = format!("{}/blocks", peer);
        let result = client
            .post(&url)
            .json(block)
            .send()
            .await
            .map(|_| ())
            .map_err(SyncError::from);

        if let Err(ref e) = result {
            warn!("Failed to broadcast block to {}: {}", peer, e);
        } else {
            info!("Broadcast block {} to {}", block.hash_hex(), peer);
        }

        results.push(result);
    }

    results
}

/// Background task that periodically syncs with peers.
pub async fn sync_loop(state: Arc<AppState>, peers: Vec<String>, sync_interval_secs: u64) {
    if peers.is_empty() {
        return;
    }

    let mut interval = interval(Duration::from_secs(sync_interval_secs));

    loop {
        interval.tick().await;

        for peer in &peers {
            match sync_from_peer(state.clone(), peer).await {
                Ok(n) if n > 0 => {
                    info!("Synced {} blocks from {}", n, peer);
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("Sync from {} failed: {}", peer, e);
                }
            }
        }
    }
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct PeerChainInfo {
    height: u64,
    latest_hash: String,
    difficulty: u64,
    commitment_count: u64,
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct PeerBlockInfo {
    hash: String,
    height: u64,
    prev_hash: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("HTTP error: {0}")]
    HttpError(String),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("Lock poisoned: {0}")]
    LockPoisoned(String),
}

/// Configuration de synchronisation
#[derive(Debug, Clone)]
pub struct SyncConfig {
    pub max_concurrent_requests: usize,
    pub timeout: Duration,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 10,
            timeout: Duration::from_secs(30),
        }
    }
}

/// Gestionnaire de synchronisation
pub struct BlockSync {
    _config: SyncConfig,
}

impl BlockSync {
    pub fn new(config: SyncConfig) -> Self {
        Self { _config: config }
    }
    
    pub async fn sync(
        &self,
        _peer: &str,
        _from_height: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // TODO: Implémenter
        Ok(())
    }
}