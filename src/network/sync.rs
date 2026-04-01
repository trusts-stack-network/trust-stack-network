use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::time::{interval, Duration};
use tracing::{info, warn, debug};

use crate::core::ShieldedBlock;

use crate::network::api::AppState;
use crate::network::peer_id;

/// Remove IP addresses and URLs from error messages for privacy.
fn sanitize_error(e: &dyn std::fmt::Display) -> String {
    let msg = e.to_string();
    // Strip anything after "url (" to hide the full URL with IP
    if let Some(idx) = msg.find("url (") {
        format!("{}connection failed", &msg[..idx])
    } else if let Some(idx) = msg.find("http://") {
        format!("{}<hidden>", &msg[..idx])
    } else if let Some(idx) = msg.find("https://") {
        format!("{}<hidden>", &msg[..idx])
    } else {
        msg
    }
}

/// Sync the local chain from a peer node.
/// Handles both catching up and chain reorganizations.
pub async fn sync_from_peer(state: Arc<AppState>, peer_url: &str) -> Result<u64, SyncError> {
    let client = state.http_client.clone();

    // Check peer version — reject outdated peers to prevent forks
    {
        let version_url = format!("{}/version.json", peer_url);
        if let Ok(resp) = client.get(&version_url).timeout(Duration::from_secs(5)).send().await {
            if let Ok(info) = resp.json::<serde_json::Value>().await {
                if let Some(peer_version) = info["version"].as_str() {
                    if !crate::network::version_check::version_meets_minimum(peer_version) {
                        warn!(
                            "Rejecting sync from {} — outdated version {} (minimum: {})",
                            crate::network::peer_id(peer_url),
                            peer_version,
                            crate::network::version_check::MINIMUM_VERSION
                        );
                        return Err(SyncError::HttpError(format!(
                            "Peer version {} below minimum {}",
                            peer_version,
                            crate::network::version_check::MINIMUM_VERSION
                        )));
                    }
                }
            }
        }
        // If we can't check version, proceed anyway (peer might just not expose /version.json yet)
    }

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

    let (local_height, local_hash, local_genesis) = {
        let chain = state.blockchain.read()
            .map_err(|e| SyncError::LockPoisoned(format!("Blockchain read lock poisoned: {}", e)))?;
        let genesis = chain.info().genesis_hash;
        (chain.height(), hex::encode(chain.latest_hash()), genesis)
    };

    // FORK PROTECTION: reject peers with incompatible genesis
    // Skip check if either side has a placeholder genesis (fast-sync nodes)
    // Also skip if local height is 0 — fresh node should accept any peer's chain
    let placeholder = "0".repeat(64);
    let peer_has_real_genesis = !peer_info.genesis_hash.is_empty() && peer_info.genesis_hash != placeholder;
    let local_has_real_genesis = !local_genesis.is_empty() && local_genesis != placeholder;
    if local_height > 0 && peer_has_real_genesis && local_has_real_genesis && peer_info.genesis_hash != local_genesis {
        warn!(
            "Rejecting peer {} — incompatible genesis hash (peer: {}…, local: {}…)",
            peer_id(peer_url),
            &peer_info.genesis_hash[..16.min(peer_info.genesis_hash.len())],
            &local_genesis[..16.min(local_genesis.len())]
        );
        return Ok(0);
    }

    // Get local cumulative work for fork resolution (heaviest chain wins, not longest)
    let local_work = {
        let chain = state.blockchain.read()
            .map_err(|e| SyncError::LockPoisoned(format!("Blockchain read lock poisoned: {}", e)))?;
        chain.cumulative_work()
    };

    // Check if peer is ahead by work OR height, or if we have a fork
    let mut is_fork = peer_info.height == local_height && peer_info.latest_hash != local_hash;
    let peer_ahead = peer_info.height > local_height || peer_info.cumulative_work > local_work as u128;

    if !peer_ahead && !is_fork {
        debug!(
            "Peer {} is not ahead (peer h={} w={}, local h={} w={})",
            peer_id(peer_url), peer_info.height, peer_info.cumulative_work, local_height, local_work
        );
        return Ok(0);
    }

    // Also detect fork when peer is ahead: compare their block at our height vs ours
    if peer_ahead && !is_fork {
        let check_url = format!("{}/block/height/{}", peer_url, local_height);
        if let Ok(resp) = client.get(&check_url).send().await {
            if resp.status().is_success() {
                if let Ok(peer_block) = resp.json::<PeerBlockInfo>().await {
                    if peer_block.hash != local_hash {
                        is_fork = true;
                        info!(
                            "Fork detected with peer {} (peer ahead at h={} w={}, diverged at our height {})",
                            peer_id(peer_url), peer_info.height, peer_info.cumulative_work, local_height
                        );
                    }
                }
            }
        }
    }

    if is_fork {
        // HEAVIEST CHAIN RULE: only switch to a chain with more cumulative work
        // A shorter chain with more work is valid (e.g. higher difficulty blocks)
        // A longer chain with less work is a spam attack (easy blocks)
        if peer_info.cumulative_work <= local_work as u128 {
            warn!(
                "Ignoring fork from peer {} — peer work {} <= local work {}. Heaviest chain wins.",
                peer_id(peer_url), peer_info.cumulative_work, local_work
            );
            return Ok(0);
        }
        // Same height but different block: ALWAYS take the peer's chain.
        // The peer's block was already accepted by the network (seeds follow it).
        // Our block hasn't been propagated yet. Network consensus wins.
        if peer_info.height == local_height {
            info!(
                "Fork at same height {} — taking peer's chain (network consensus). Switching.",
                peer_info.height
            );
        }
        info!(
            "Fork detected with peer {} at height {} (peer: {}..., local: {}...)",
            peer_id(peer_url), peer_info.height, &peer_info.latest_hash[..16], &local_hash[..16]
        );
    } else {
        info!(
            "Syncing from peer {} (peer height: {}, local: {})",
            peer_id(peer_url), peer_info.height, local_height
        );
    }

    // Find common ancestor by checking recent blocks
    // If local height is 0, attempt snapshot sync (block-by-block from 0 doesn't work)
    if local_height == 0 && peer_info.height > 0 {
        info!("Local height is 0, attempting snapshot sync from {}", peer_id(peer_url));
        let info_url = format!("{}/snapshot/info", peer_url);
        if let Ok(resp) = client.get(&info_url)
            .timeout(Duration::from_secs(10))
            .send().await
        {
            if let Ok(info) = resp.json::<serde_json::Value>().await {
                if info["available"].as_bool() == Some(true) {
                    let snap_height = info["height"].as_u64().unwrap_or(0);
                    if snap_height > 0 {
                        let snap_hash_str = info["block_hash"].as_str().unwrap_or("");
                        let dl_url = format!("{}/snapshot/download", peer_url);
                        if let Ok(resp) = client.get(&dl_url)
                            .timeout(Duration::from_secs(30))
                            .send().await
                        {
                            if let Ok(compressed) = resp.bytes().await {
                                use std::io::Read;
                                let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
                                let mut json_data = Vec::new();
                                if decoder.read_to_end(&mut json_data).is_ok() {
                                    if let Ok(snapshot) = serde_json::from_slice::<crate::core::StateSnapshotPQ>(&json_data) {
                                        let mut block_hash = [0u8; 32];
                                        if let Ok(bytes) = hex::decode(snap_hash_str) {
                                            if bytes.len() == 32 { block_hash.copy_from_slice(&bytes); }
                                        }
                                        let ci_url = format!("{}/chain/info", peer_url);
                                        let (diff, next_diff, peer_work) = if let Ok(r) = client.get(&ci_url).send().await {
                                            let i = r.json::<serde_json::Value>().await.ok();
                                            let d = i.as_ref().and_then(|v| v["difficulty"].as_u64()).unwrap_or(1000);
                                            let nd = i.as_ref().and_then(|v| v["next_difficulty"].as_u64()).unwrap_or(d);
                                            let w = i.as_ref().and_then(|v| v["cumulative_work"].as_u64()).unwrap_or(0);
                                            (d, nd, w as u128)
                                        } else { (1000, 1000, 0u128) };

                                        let mut chain = state.blockchain.write()
                                            .map_err(|e| SyncError::LockPoisoned(format!("Blockchain write lock poisoned: {}", e)))?;
                                        chain.import_snapshot_at_height(snapshot, snap_height, block_hash, diff, next_diff, peer_work);
                                        info!("Snapshot sync complete: jumped to height {} from {}", snap_height, peer_id(peer_url));
                                        return Ok(snap_height);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // Snapshot unavailable — fall through to block-by-block (may be slow)
        warn!("Snapshot sync failed from {} — falling back to block-by-block sync", peer_id(peer_url));
    }

    let sync_from_height = if local_height == 0 {
        0
    } else if is_fork {
        match find_common_ancestor(&state, &client, peer_url, local_height).await {
            Ok(ancestor) => {
                // IMMEDIATELY cancel mining and set reorg height BEFORE rollback
                state.last_reorg_height.store(ancestor, std::sync::atomic::Ordering::Relaxed);
                state.reorg_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if let Some(cancel) = state.mining_cancel.read().unwrap().as_ref() {
                    cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                }

                // Rollback to common ancestor so peer's blocks can be added as tip extensions
                let mut chain = state.blockchain.write()
                    .map_err(|e| SyncError::LockPoisoned(format!("Blockchain write lock poisoned: {}", e)))?;
                if let Err(e) = chain.rollback_to_height(ancestor) {
                    warn!("Rollback to height {} failed: {}", ancestor, e);
                    return Err(SyncError::HttpError(format!("Rollback failed: {}", e)));
                }
                info!("Rolled back to common ancestor at height {}", ancestor);
                ancestor
            }
            Err(_) => {
                // No common ancestor found — chains are incompatible.
                // If peer has a heavier chain, wipe local state and fast-sync from scratch.
                // This is the "majority consensus" rule: if we can't merge, take the network's chain.
                warn!("No common ancestor with peer {}. Force re-sync from network (reset local chain).", peer_id(peer_url));
                if let Some(cancel) = state.mining_cancel.read().unwrap().as_ref() {
                    cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                {
                    let mut chain = state.blockchain.write()
                        .map_err(|e| SyncError::LockPoisoned(format!("Blockchain write lock poisoned: {}", e)))?;
                    chain.reset_for_resync();
                }
                0 // Start sync from genesis
            }
        }
    } else {
        local_height
    };

    // Fetch blocks in paginated batches (50 blocks per request)
    let mut synced = 0u64;
    let mut reorged = false;
    let mut current_sync_height = sync_from_height;

    loop {
        let blocks_url = format!("{}/blocks/since/{}", peer_url, current_sync_height);
        let response = client
            .get(&blocks_url)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(SyncError::HttpError(format!("HTTP {}: {}", status, body)));
        }

        let blocks: Vec<ShieldedBlock> = response.json().await?;
        let batch_size = blocks.len();

        if batch_size == 0 {
            break; // No more blocks to sync
        }

        for block in blocks.into_iter() {
            let mut chain = state.blockchain.write()
                .map_err(|e| SyncError::LockPoisoned(format!("Blockchain write lock poisoned: {}", e)))?;
            match chain.try_add_block(block) {
                Ok(true) => {
                    synced += 1;
                    current_sync_height = chain.height();
                    if is_fork && !reorged {
                        reorged = true;
                        info!("Chain reorganization triggered from peer {}", peer_id(peer_url));
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
        }

        if synced > 0 && synced % 50 == 0 {
            info!("Synced {} blocks from {} (height: {})", synced, peer_id(peer_url), current_sync_height);
        }

        // If we got fewer blocks than the default batch, we're caught up
        if batch_size < 50 {
            break;
        }
    }

    if synced > 0 {
        if is_fork {
            let height = state.blockchain.read()
                .map_err(|e| SyncError::LockPoisoned(format!("Blockchain read lock poisoned: {}", e)))?
                .height();
            info!("Fork resolved: synced {} blocks from {} (new height: {})",
                synced, peer_id(peer_url), height);
            // Signal miner to restart on new tip after fork resolution
            if let Some(cancel) = state.mining_cancel.read().unwrap().as_ref() {
                cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        } else {
            info!("Synced {} blocks from {}", synced, peer_id(peer_url));
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

    // SECURITY: If we can't find common ancestor, the peer's chain is incompatible.
    // NEVER rollback to genesis — this would destroy the entire chain.
    warn!(
        "No common ancestor found in last {} blocks — chains are incompatible. Ignoring peer.",
        check_depth
    );
    Err(SyncError::InvalidResponse(format!(
        "No common ancestor found in last {} blocks — peer chain incompatible",
        check_depth
    )))
}

/// Broadcast a newly mined block to all peers.
pub async fn broadcast_block(block: &ShieldedBlock, peers: &[String], client: &reqwest::Client) -> Vec<Result<(), SyncError>> {
    let mut results = Vec::new();

    for peer in peers {
        let url = format!("{}/blocks", peer);
        let result = client
            .post(&url)
            .header("X-TSN-Version", env!("CARGO_PKG_VERSION"))
            .json(block)
            .send()
            .await
            .map(|_| ())
            .map_err(SyncError::from);

        if let Err(ref e) = result {
            debug!("Failed to broadcast block to {}: {}", peer_id(peer), sanitize_error(e));
        } else {
            debug!("Broadcast block {} to {}", block.hash_hex(), peer_id(peer));
        }

        results.push(result);
    }

    results
}

/// Consecutive failure counter for sync loop (reduces log spam).
static SYNC_FAIL_COUNT: AtomicU32 = AtomicU32::new(0);

/// Background task that periodically syncs with peers.
pub async fn sync_loop(state: Arc<AppState>, seed_peers: Vec<String>, sync_interval_secs: u64) {
    if seed_peers.is_empty() {
        return;
    }

    let mut interval = interval(Duration::from_secs(sync_interval_secs));
    let mut peer_failures: std::collections::HashMap<String, u32> = std::collections::HashMap::new();

    loop {
        interval.tick().await;

        // Use current peer list (may have been modified by discovery)
        let peers = state.peers.read().unwrap().clone();

        for peer in &peers {
            // Keep syncing until caught up (not just one batch per cycle)
            loop {
                match sync_from_peer(state.clone(), peer).await {
                    Ok(n) if n > 0 => {
                        SYNC_FAIL_COUNT.store(0, Ordering::Relaxed);
                        peer_failures.remove(peer);
                        info!("Synced {} blocks from {}", n, peer_id(peer));
                        // If we got blocks, immediately try again (peer may have more)
                        continue;
                    }
                    Ok(_) => {
                        peer_failures.remove(peer);
                        break; // caught up with this peer
                    }
                    Err(e) => {
                        let count = SYNC_FAIL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                        let peer_count = peer_failures.entry(peer.clone()).or_insert(0);
                        *peer_count += 1;

                        // Log first failure, then every 10th to reduce spam
                        if count == 1 {
                            warn!("Sync from {} failed: {}", peer_id(peer), sanitize_error(&e));
                        } else if count % 10 == 0 {
                            warn!("Sync from {} failed ({} consecutive): {}", peer_id(peer), count, sanitize_error(&e));
                        }

                        // Ghost peer cleanup: remove non-seed peers after 10 consecutive failures
                        if *peer_count >= 10 && !seed_peers.contains(peer) {
                            info!("Removing ghost peer {} after {} consecutive failures", peer_id(peer), peer_count);
                            let mut peers_write = state.peers.write().unwrap();
                            peers_write.retain(|p| p != peer);
                            peer_failures.remove(peer);
                        }
                        break;
                    }
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
    #[serde(default)]
    genesis_hash: String,
    #[serde(default)]
    cumulative_work: u128,
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

/// Réponse d'un peer pour /snapshot/info
#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct PeerSnapshotInfo {
    block_hash: String,
    height: u64,
    state_root: String,
}

/// Résultat de la vérification multi-peer d'un snapshot
#[derive(Debug)]
pub struct SnapshotVerification {
    /// Nombre de peers qui ont répondu
    pub responding_peers: usize,
    /// Nombre de peers en accord avec le hash majoritaire
    pub agreeing_peers: usize,
    /// Hash majoritaire du snapshot (block_hash)
    pub majority_hash: Option<String>,
}

/// Vérifie un snapshot auprès de plusieurs peers.
///
/// Interroge GET /snapshot/info sur au moins 3 peers et vérifie
/// que la majorité (>50%) s'accorde sur le même block_hash et height.
/// Logue un warning pour chaque peer en désaccord.
pub async fn verify_snapshot_multi_peer(
    peer_urls: &[String],
    expected_state_root: &str,
) -> Result<SnapshotVerification, SyncError> {
    const MIN_PEERS: usize = 3;

    if peer_urls.len() < MIN_PEERS {
        return Err(SyncError::InvalidResponse(format!(
            "Au moins {} peers requis pour la vérification, {} fournis",
            MIN_PEERS, peer_urls.len()
        )));
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(SyncError::Request)?;

    // Interroger tous les peers en parallèle
    let mut handles = Vec::new();
    for peer_url in peer_urls {
        let client = client.clone();
        let url = format!("{}/snapshot/info", peer_url);
        let peer = peer_url.clone();
        handles.push(tokio::spawn(async move {
            let result = client.get(&url).send().await;
            (peer, result)
        }));
    }

    // Collecter les réponses
    let mut responses: Vec<(String, PeerSnapshotInfo)> = Vec::new();
    for handle in handles {
        if let Ok((peer, result)) = handle.await {
            match result {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<PeerSnapshotInfo>().await {
                        Ok(info) => responses.push((peer, info)),
                        Err(e) => {
                            warn!("Peer {} a renvoyé une réponse invalide: {}", peer_id(&peer), e);
                        }
                    }
                }
                Ok(resp) => {
                    warn!("Peer {} a renvoyé HTTP {}", peer_id(&peer), resp.status());
                }
                Err(e) => {
                    warn!("Peer {} injoignable: {}", peer_id(&peer), e);
                }
            }
        }
    }

    let responding_peers = responses.len();
    if responding_peers < MIN_PEERS {
        return Err(SyncError::InvalidResponse(format!(
            "Seulement {} peers ont répondu, minimum {} requis",
            responding_peers, MIN_PEERS
        )));
    }

    // Compter les votes par (block_hash, height)
    let mut votes: std::collections::HashMap<(String, u64), Vec<String>> =
        std::collections::HashMap::new();
    for (peer, info) in &responses {
        votes
            .entry((info.block_hash.clone(), info.height))
            .or_default()
            .push(peer.clone());
    }

    // Trouver le consensus majoritaire
    let (majority_key, majority_peers) = votes
        .iter()
        .max_by_key(|(_, peers)| peers.len())
        .map(|(k, p)| (k.clone(), p.clone()))
        .unwrap(); // safe: responding_peers >= MIN_PEERS > 0

    let agreeing_peers = majority_peers.len();
    let majority_hash = majority_key.0.clone();
    let is_majority = agreeing_peers * 2 > responding_peers;

    // Loguer les peers en désaccord
    for (peer, info) in &responses {
        if info.block_hash != majority_hash || info.height != majority_key.1 {
            warn!(
                "Peer {} en désaccord: block_hash={}, height={} (majorité: hash={}, height={})",
                peer_id(peer), info.block_hash, info.height, majority_hash, majority_key.1
            );
        }
    }

    // Vérifier que le state_root attendu correspond
    let majority_root_matches = responses
        .iter()
        .any(|(_, info)| info.state_root == expected_state_root && info.block_hash == majority_hash);

    if !majority_root_matches {
        warn!(
            "Le state_root attendu {} ne correspond à aucun peer majoritaire",
            expected_state_root
        );
    }

    if !is_majority {
        return Err(SyncError::InvalidResponse(format!(
            "Pas de majorité: {}/{} peers d'accord sur le même snapshot",
            agreeing_peers, responding_peers
        )));
    }

    info!(
        "Vérification snapshot OK: {}/{} peers d'accord (hash={}, height={})",
        agreeing_peers, responding_peers, majority_hash, majority_key.1
    );

    Ok(SnapshotVerification {
        responding_peers,
        agreeing_peers,
        majority_hash: Some(majority_hash),
    })
}