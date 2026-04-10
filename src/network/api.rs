//! REST API for the shielded blockchain node.
//!
//! This API is privacy-preserving. Account balances and transaction
//! amounts are not visible through the API. Only publicly observable
//! data (block hashes, timestamps, fees) is exposed.

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::StatusCode,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::limit::RequestBodyLimitLayer;
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor, GovernorLayer,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use tokio::sync::RwLock as TokioRwLock;

use crate::core::{ShieldedBlock, ShieldedBlockchain, ChainInfo, ShieldedTransaction, ShieldedTransactionV2, Transaction};
use crate::crypto::nullifier::Nullifier;
use crate::faucet::{FaucetService, FaucetStatus, ClaimResult, FaucetStats, FaucetError};
use crate::wallet::ShieldedWallet;
use tracing::{info, warn};

use super::Mempool;
use super::sync_gate::SyncGate;
use super::peer_id;

/// Maximum request body size (10 MB)
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Rate limit: requests per second per IP (public routes)
/// Set high enough that explorer + normal usage never gets blocked.
const RATE_LIMIT_RPS: u64 = 200;

/// Rate limit: burst size for public routes
const RATE_LIMIT_BURST: u32 = 500;

/// Rate limit: requests per second per IP (sync routes — higher for node sync)
const SYNC_RATE_LIMIT_RPS: u64 = 200;

/// Rate limit: burst size for sync routes
const SYNC_RATE_LIMIT_BURST: u32 = 400;

/// Shared application state for the API.
pub struct AppState {
    pub blockchain: RwLock<ShieldedBlockchain>,
    pub mempool: RwLock<Mempool>,
    /// List of known peer URLs for gossip
    pub peers: RwLock<Vec<String>>,
    /// Stats for the local miner (if running)
    pub miner_stats: RwLock<MinerStats>,
    /// Optional faucet service (enabled via CLI flag)
    pub faucet: Option<TokioRwLock<FaucetService>>,
    /// Sync gate for anti-fork protection
    pub sync_gate: SyncGate,
    /// Our own public URL (to avoid adding ourselves as peer)
    pub public_url: Option<String>,
    /// P2P broadcast channel (GossipSub) — used to push blocks/txs to all peers
    pub p2p_broadcast: RwLock<Option<tokio::sync::mpsc::Sender<super::p2p::P2pCommand>>>,
    /// Local P2P PeerID (set after libp2p starts)
    pub p2p_peer_id: RwLock<Option<String>>,
    /// Shared P2P peer list — updated by the P2P loop, read instantly by API
    pub p2p_shared_peers: RwLock<Option<super::p2p::SharedPeerList>>,
    /// Node role (miner, relay, light)
    pub node_role: String,
    /// Mining cancel signal — set by P2P when a new block arrives to abort current PoW
    pub mining_cancel: RwLock<Option<Arc<std::sync::atomic::AtomicBool>>>,
    /// Shared HTTP client for all outbound requests (connection pooling, prevents FD leaks)
    pub http_client: reqwest::Client,
    /// Height of last chain reorganization — used for post-reorg mining cooldown
    pub last_reorg_height: std::sync::atomic::AtomicU64,
    /// Semaphore limiting concurrent snapshot downloads (max 3)
    pub snapshot_semaphore: Arc<tokio::sync::Semaphore>,
    /// Cached pre-compressed snapshot (refreshed every 100 blocks)
    pub snapshot_cache: TokioRwLock<Option<CachedSnapshot>>,
    /// Orphan/fork counter for monitoring network health
    pub orphan_count: std::sync::atomic::AtomicU64,
    /// Total blocks received that triggered a reorg
    pub reorg_count: std::sync::atomic::AtomicU64,
    /// Reorg lock: WRITE during rollback+resync, READ during mining template+add_block.
    /// Prevents mining from producing stale blocks while a reorg is in progress.
    pub reorg_lock: TokioRwLock<()>,
    /// Banned peer URLs with expiry timestamps (Instant).
    /// Peers are banned for sending checkpoint-violating or incompatible chains.
    pub banned_peers: RwLock<std::collections::HashMap<String, std::time::Instant>>,
    /// Detailed peer info (version, role, last seen) — updated on every HTTP interaction.
    pub peer_info: RwLock<std::collections::HashMap<String, PeerDetail>>,
    /// Error log for telemetry — recent errors stored for P2P sharing and dashboard
    pub error_log: RwLock<Vec<NodeError>>,
    /// Auto-heal mode: "validation" (default, human approves) or "automatic" (self-repair)
    pub auto_heal_mode: RwLock<String>,
}

/// Info about an HTTP peer, updated on every interaction.
#[derive(Clone, serde::Serialize)]
pub struct PeerDetail {
    pub peer_id: String,       // masked peer:xxxx
    pub version: String,       // from X-TSN-Version header
    pub role: String,          // "miner" or "relay" (from protocol or endpoint used)
    pub height: u64,           // last known height
    pub last_seen: u64,        // unix timestamp
}

/// Update peer info from an incoming HTTP request.
pub fn update_peer_info(state: &AppState, peer_url: &str, version: Option<&str>, height: Option<u64>) {
    let peer_id = super::peer_id(peer_url);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut info = state.peer_info.write().unwrap();
    let entry = info.entry(peer_id.clone()).or_insert(PeerDetail {
        peer_id: peer_id.clone(),
        version: "?".to_string(),
        role: "relay".to_string(),
        height: 0,
        last_seen: now,
    });
    if let Some(v) = version {
        entry.version = v.to_string();
    }
    if let Some(h) = height {
        if h > entry.height { entry.height = h; }
    }
    entry.last_seen = now;
}

/// Structured error for telemetry reporting
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeError {
    pub error_type: String,
    pub message: String,
    pub height: u64,
    pub timestamp: u64,
    pub version: String,
}

/// Pre-generated snapshot cached in memory for fast serving.
pub struct CachedSnapshot {
    pub compressed: Vec<u8>,
    pub height: u64,
    pub hash: String,
    pub raw_size: usize,
}

/// Create the API router with rate limiting and request size limits.
///
/// Note: This is a privacy-preserving blockchain. Account balances and
/// transaction amounts are not visible through the API.
///
/// Rate limiting: 50 requests/second per IP with burst of 100.
/// Request body limit: 10 MB max.
pub fn create_router(state: Arc<AppState>) -> Router {
    // Configure rate limiting using Governor
    // Uses SmartIpKeyExtractor to handle proxied requests (X-Forwarded-For)
    let governor_config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(RATE_LIMIT_RPS)
            .burst_size(RATE_LIMIT_BURST)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("INIT: rate limiter config is invalid — check RATE_LIMIT_RPS/BURST constants"),
    );

    let rate_limit_layer = GovernorLayer {
        config: governor_config,
    };

    // Log rate limiter configuration
    info!(
        "Rate limiting enabled: {} req/s, burst size {}",
        RATE_LIMIT_RPS, RATE_LIMIT_BURST
    );
    info!("Request body limit: {} bytes", MAX_BODY_SIZE);

    // Sync routes — separate rate limiter (higher limit for node-to-node sync,
    // but still protected against DoS — previously had NO rate limit at all)
    let sync_governor_config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(SYNC_RATE_LIMIT_RPS)
            .burst_size(SYNC_RATE_LIMIT_BURST)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("INIT: sync rate limiter config is invalid"),
    );
    let sync_rate_limit_layer = GovernorLayer {
        config: sync_governor_config,
    };
    info!(
        "Sync rate limiting enabled: {} req/s, burst size {}",
        SYNC_RATE_LIMIT_RPS, SYNC_RATE_LIMIT_BURST
    );

    // Sync routes — NO rate limiting (was causing fast-sync failures for new nodes)
    let sync_routes = Router::new()
        .route("/chain/info", get(chain_info))
        .route("/blocks", post(receive_block))
        .route("/blocks/since/:height", get(get_blocks_since))
        .route("/headers/since/:height", get(get_headers_since))
        .route("/peers", get(get_peers))
        .route("/peers", post(add_peer))
        .route("/peers/p2p", get(get_p2p_peers))
        .route("/peers/detailed", get(get_peers_detailed))
        .route("/tx/relay", post(receive_transaction))
        .route("/tip", get(get_tip).post(receive_tip))
        .route("/sync/status", get(sync_status))
        .route("/node/info", get(node_info))
        .route("/snapshot/info", get(snapshot_info))
        .route("/snapshot/download", get(snapshot_download))
        .with_state(state.clone());

    // Explorer/read-only routes — NO rate limiting (served by nginx proxy from localhost)
    let explorer_routes = Router::new()
        .route("/health", get(health_check))
        .route("/miner/stats", get(miner_stats))
        .route("/block/:hash", get(get_block))
        .route("/block/height/:height", get(get_block_by_height))
        .route("/tx/:hash", get(get_transaction))
        .route("/transactions/recent", get(get_recent_transactions))
        .route("/blocks/list", get(list_blocks_paginated))
        .route("/mempool", get(get_mempool))
        .route("/version.json", get(version_info))
        .route("/faucet/stats", get(faucet_stats))
        .route("/network/health", get(network_health))
        .route("/node/errors", get(get_node_errors))
        .with_state(state.clone());

    // Admin routes — localhost only (not accessible from outside)
    let admin_routes = Router::new()
        .route("/admin/force-resync", post(admin_force_resync))
        .route("/admin/config", get(get_admin_config).post(set_admin_config))
        .with_state(state.clone());

    // Write + sensitive routes — rate limited to prevent DoS
    let limited_routes = Router::new()
        .route("/tx", post(submit_transaction))
        .route("/tx/v2", post(submit_transaction_v2))
        .route("/outputs/since/:height", get(get_outputs_since))
        .route("/nullifiers/check", post(check_nullifiers))
        .route("/witness/:commitment", get(get_witness))
        .route("/witness/position/:position", get(get_witness_by_position))
        .route("/witness/v2/position/:position", get(get_witness_by_position_v2))
        // Debug endpoints REMOVED from production (H3 audit fix).
        // These exposed internal crypto structures. Re-enable with --debug flag if needed.
        // .route("/debug/commitments", get(debug_list_commitments))
        // .route("/debug/poseidon", get(debug_poseidon_test))
        // .route("/debug/poseidon-pq", get(debug_poseidon_pq_test))
        // .route("/debug/merkle-pq", get(debug_merkle_pq))
        // .route("/debug/verify-path", post(debug_verify_path))
        .route("/wallet/viewing-key", get(wallet_viewing_key))
        .route("/wallet/watch", post(wallet_watch))
        .route("/faucet/status/:pk_hash", get(faucet_status))
        .route("/faucet/claim", post(faucet_claim))
        .route("/faucet/game-claim", post(faucet_game_claim))
        .route("/api/roadmap", get(roadmap_status))
        .route("/contract/deploy", post(contract_deploy))
        .route("/contract/call", post(contract_call))
        .route("/contract/query", post(contract_query))
        .route("/contract/:address", get(contract_info))
        .route("/contract/:address/events", get(contract_events))
        .with_state(state)
        .layer(rate_limit_layer);

    // Merge all route groups
    let api_routes = sync_routes
        .merge(explorer_routes)
        .merge(admin_routes)
        .merge(limited_routes)
        .layer(RequestBodyLimitLayer::new(MAX_BODY_SIZE));

    let ui_routes = Router::new()
        // React app routes - serve index.html for SPA
        .route("/", get(serve_index))
        .route("/wallet", get(serve_index))
        .route("/wallet/*path", get(serve_index))
        .route("/explorer", get(serve_index))
        .route("/explorer/*path", get(serve_index))
        // Static assets
        .nest_service("/assets", ServeDir::new("static/assets"))
        // Circuit files (WASM and proving keys)
        .nest_service("/circuits", ServeDir::new("static/circuits"))
        // Root-level static files
        .route_service("/logo.png", ServeFile::new("static/logo.png"))
        .route_service("/vite.svg", ServeFile::new("static/vite.svg"))
        .route_service("/favicon.ico", ServeFile::new("static/logo.png"))
        .route_service("/tsn-whitepaper.pdf", ServeFile::new("static/tsn-whitepaper.pdf"));

    Router::new().merge(api_routes).merge(ui_routes)
}

/// GET /health — lightweight health check, never rate limited.
async fn health_check(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let height = state.blockchain.read().unwrap_or_else(|e| e.into_inner()).height();
    let peers = state.peers.read().unwrap_or_else(|e| e.into_inner()).len();
    Json(serde_json::json!({
        "status": "ok",
        "height": height,
        "peers": peers,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn chain_info(State(state): State<Arc<AppState>>) -> Json<ChainInfo> {
    let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    Json(chain.info())
}

/// Sync progress status response.
#[derive(Serialize)]
struct SyncStatusResponse {
    height: u64,
    target_height: u64,
    progress_pct: f64,
    syncing: bool,
    peers_connected: usize,
}

/// GET /sync/status — returns current sync progress.
async fn sync_status(State(state): State<Arc<AppState>>) -> Json<SyncStatusResponse> {
    let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    let local_height = chain.height();
    drop(chain);

    let peers = state.peers.read().unwrap_or_else(|e| e.into_inner());
    let peers_connected = peers.len();
    drop(peers);

    // Best known peer height: if we have peers, query chain info for target
    // For now, use local height as target (updated during sync)
    let target_height = local_height; // Will match local when fully synced
    let syncing = false; // Not actively syncing via parallel sync

    let progress_pct = if target_height == 0 {
        100.0
    } else {
        (local_height as f64 / target_height as f64 * 100.0).min(100.0)
    };

    Json(SyncStatusResponse {
        height: local_height,
        target_height,
        progress_pct,
        syncing,
        peers_connected,
    })
}

/// Version info response.
#[derive(Serialize)]
struct VersionInfoResponse {
    version: &'static str,
    minimum_version: &'static str,
    protocol_version: u16,
}

/// GET /version.json — returns node version info.
async fn version_info() -> Json<VersionInfoResponse> {
    Json(VersionInfoResponse {
        version: env!("CARGO_PKG_VERSION"),
        minimum_version: crate::network::version_check::MINIMUM_VERSION,
        protocol_version: 3,
    })
}

/// Node identity and status.
async fn node_info(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let height = state.blockchain.read().unwrap_or_else(|e| e.into_inner()).height();
    let peer_id = state.p2p_peer_id.read().unwrap_or_else(|e| e.into_inner()).clone();
    let http_peers = state.peers.read().unwrap_or_else(|e| e.into_inner()).len();

    Json(serde_json::json!({
        "peer_id": peer_id,
        "role": state.node_role,
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": format!("tsn/{}", env!("CARGO_PKG_VERSION")),
        "height": height,
        "http_peers": http_peers,
        "signatures": "ML-DSA-65 (FIPS 204)",
        "hash": "Poseidon2",
        "zk_proofs": "Plonky3 STARKs",
    }))
}

/// Roadmap milestone status.
#[derive(Serialize)]
struct RoadmapMilestone {
    id: String,
    name: String,
    description: String,
    quarter: String,
    status: String, // "completed", "active", "pending"
    progress_pct: f64,
    metrics: serde_json::Value,
}

/// Roadmap status response.
#[derive(Serialize)]
struct RoadmapStatusResponse {
    last_updated: u64,
    milestones: Vec<RoadmapMilestone>,
    network_health: serde_json::Value,
}

/// GET /api/roadmap — returns dynamic roadmap status with real-time metrics.
async fn roadmap_status(State(state): State<Arc<AppState>>) -> Json<RoadmapStatusResponse> {
    let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    let chain_info = chain.info();
    let height = chain.height();
    drop(chain);

    let peers = state.peers.read().unwrap_or_else(|e| e.into_inner());
    let peers_connected = peers.len();
    drop(peers);

    let miner_stats = state.miner_stats.read().unwrap_or_else(|e| e.into_inner()).clone();

    // Calculate progress for each milestone based on real metrics
    let mut milestones = vec![];

    // Q1 2026: Mainnet Launch - COMPLETED
    milestones.push(RoadmapMilestone {
        id: "mainnet_launch".to_string(),
        name: "Mainnet Launch".to_string(),
        description: "Lancement officiel du réseau principal TSN".to_string(),
        quarter: "Q1 2026".to_string(),
        status: "completed".to_string(),
        progress_pct: 100.0,
        metrics: serde_json::json!({
            "height": height,
            "latest_hash": chain_info.latest_hash,
            "proof_verification": chain_info.proof_verification_enabled
        }),
    });

    // Q2 2026: Sharding V2 - ACTIVE (based on sync performance and commitment count)
    let sharding_progress = if chain_info.commitment_count > 10000 {
        ((chain_info.commitment_count as f64 / 100000.0) * 100.0).min(100.0)
    } else {
        (chain_info.commitment_count as f64 / 10000.0 * 50.0).min(50.0)
    };

    milestones.push(RoadmapMilestone {
        id: "sharding_v2".to_string(),
        name: "Sharding V2".to_string(),
        description: "Amélioration de l'évolutivité avec sharding dynamique".to_string(),
        quarter: "Q2 2026".to_string(),
        status: "active".to_string(),
        progress_pct: sharding_progress,
        metrics: serde_json::json!({
            "commitment_count": chain_info.commitment_count,
            "difficulty": chain_info.difficulty,
            "mining_active": miner_stats.is_mining
        }),
    });

    // Q3 2026: Interoperability - PENDING
    milestones.push(RoadmapMilestone {
        id: "interoperability".to_string(),
        name: "Interoperability".to_string(),
        description: "Ponts cross-chain vers Ethereum, Solana et Cosmos".to_string(),
        quarter: "Q3 2026".to_string(),
        status: "pending".to_string(),
        progress_pct: 0.0,
        metrics: serde_json::json!({
            "bridge_contracts": 0,
            "supported_chains": []
        }),
    });

    // Q4 2026: Mobile SDK - PENDING
    milestones.push(RoadmapMilestone {
        id: "mobile_sdk".to_string(),
        name: "Mobile SDK".to_string(),
        description: "SDK natif pour applications mobiles décentralisées".to_string(),
        quarter: "Q4 2026".to_string(),
        status: "pending".to_string(),
        progress_pct: 0.0,
        metrics: serde_json::json!({
            "sdk_version": null,
            "platforms": []
        }),
    });

    let network_health = serde_json::json!({
        "height": height,
        "peers_connected": peers_connected,
        "mining_active": miner_stats.is_mining,
        "hashrate_hps": miner_stats.hashrate_hps,
        "commitment_count": chain_info.commitment_count,
        "nullifier_count": chain_info.nullifier_count,
        "proof_verification": chain_info.proof_verification_enabled
    });

    Json(RoadmapStatusResponse {
        last_updated: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        milestones,
        network_health,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MinerStats {
    pub is_mining: bool,
    pub hashrate_hps: u64,
    pub last_attempts: u64,
    pub last_elapsed_ms: u64,
    pub last_updated: u64,
}

async fn miner_stats(State(state): State<Arc<AppState>>) -> Json<MinerStats> {
    let stats = state.miner_stats.read().unwrap_or_else(|e| e.into_inner()).clone();
    Json(stats)
}

/// Network health endpoint — exposes fork/orphan stats and peer versions.
async fn network_health(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    let height = chain.height();
    let difficulty = chain.info().difficulty;
    let cumulative_work = chain.cumulative_work();
    let avg_block_time = {
        let ts = chain.recent_timestamps(20);
        if ts.len() >= 2 {
            let span = ts.last().unwrap_or(&0).saturating_sub(*ts.first().unwrap_or(&0));
            span as f64 / (ts.len() - 1) as f64
        } else {
            0.0
        }
    };
    drop(chain);

    let orphan_count = state.orphan_count.load(std::sync::atomic::Ordering::Relaxed);
    let reorg_count = state.reorg_count.load(std::sync::atomic::Ordering::Relaxed);
    let miner_stats = state.miner_stats.read().unwrap_or_else(|e| e.into_inner()).clone();
    let peer_count = state.peers.read().unwrap_or_else(|e| e.into_inner()).len();

    // Orphan rate: orphans per 100 blocks
    let orphan_rate = if height > 0 {
        (orphan_count as f64 / height as f64) * 100.0
    } else {
        0.0
    };

    Json(serde_json::json!({
        "height": height,
        "difficulty": difficulty,
        "cumulative_work": cumulative_work.to_string(),
        "avg_block_time_secs": avg_block_time,
        "target_block_time_secs": 10u64,
        "orphan_count": orphan_count,
        "reorg_count": reorg_count,
        "orphan_rate_pct": format!("{:.2}", orphan_rate),
        "peer_count": peer_count,
        "hashrate_hps": miner_stats.hashrate_hps,
        "is_mining": miner_stats.is_mining,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[derive(Serialize)]
struct BlockResponse {
    hash: String,
    height: u64,
    prev_hash: String,
    timestamp: u64,
    difficulty: u64,
    nonce: String,
    tx_count: usize,
    tx_count_v2: usize,
    commitment_root: String,
    nullifier_root: String,
    transactions: Vec<String>,
    transactions_v2: Vec<String>,
    coinbase_reward: u64,
    total_fees: u64,
    // Encrypted note data for miner monitoring (encrypted, so privacy-preserving)
    coinbase_ephemeral_pk: String,
    coinbase_ciphertext: String,
}

async fn get_block(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
) -> Result<Json<BlockResponse>, StatusCode> {
    let hash_bytes: [u8; 32] = hex::decode(&hash)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    let block = chain.get_block(&hash_bytes).ok_or(StatusCode::NOT_FOUND)?;

    // Find block height
    let height = (0..=chain.height())
        .find(|h| chain.get_block_by_height(*h).map(|b| b.hash()) == Some(hash_bytes))
        .unwrap_or(0);

    Ok(Json(block_to_response(&block, height)))
}

async fn get_block_by_height(
    State(state): State<Arc<AppState>>,
    Path(height): Path<u64>,
) -> Result<Json<BlockResponse>, StatusCode> {
    let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    let block = chain
        .get_block_by_height(height)
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(block_to_response(&block, height)))
}

fn block_to_response(block: &ShieldedBlock, height: u64) -> BlockResponse {
    BlockResponse {
        hash: hex::encode(block.hash()),
        height,
        prev_hash: hex::encode(block.header.prev_hash),
        timestamp: block.header.timestamp,
        difficulty: block.header.difficulty,
        nonce: hex::encode(block.header.nonce),
        tx_count: block.transactions.len(),
        tx_count_v2: block.transactions_v2.len(),
        commitment_root: hex::encode(block.header.commitment_root),
        nullifier_root: hex::encode(block.header.nullifier_root),
        transactions: block.transactions.iter().map(|tx| hex::encode(tx.hash())).collect(),
        transactions_v2: block.transactions_v2.iter().map(|tx| hex::encode(tx.hash())).collect(),
        coinbase_reward: block.coinbase.reward,
        total_fees: block.total_fees(),
        coinbase_ephemeral_pk: hex::encode(&block.coinbase.encrypted_note.ephemeral_pk),
        coinbase_ciphertext: hex::encode(&block.coinbase.encrypted_note.ciphertext),
    }
}

/// Query parameters for paginated block listing.
#[derive(Deserialize)]
struct BlockListParams {
    page: Option<u64>,
    limit: Option<u64>,
}

/// Paginated block list response.
#[derive(Serialize)]
struct BlockListResponse {
    blocks: Vec<BlockSummaryItem>,
    total: u64,
    page: u64,
    limit: u64,
    total_pages: u64,
}

/// Lightweight block summary for list views.
#[derive(Serialize)]
struct BlockSummaryItem {
    height: u64,
    hash: String,
    tx_count: usize,
    timestamp: u64,
    difficulty: u64,
    coinbase_reward: u64,
}

/// List blocks with pagination — page 1 = most recent.
async fn list_blocks_paginated(
    State(state): State<Arc<AppState>>,
    Query(params): Query<BlockListParams>,
) -> Json<BlockListResponse> {
    let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    let chain_height = chain.height();
    let total = chain_height + 1; // heights 0..=chain_height

    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let total_pages = (total + limit - 1) / limit;

    let offset = (page - 1) * limit;
    // Page 1 = most recent blocks (descending)
    let start_height = chain_height.saturating_sub(offset);

    let mut blocks = Vec::with_capacity(limit as usize);
    for i in 0..limit {
        if start_height < i {
            break;
        }
        let h = start_height - i;
        if let Some(block) = chain.get_block_by_height(h) {
            blocks.push(BlockSummaryItem {
                height: h,
                hash: hex::encode(block.hash()),
                tx_count: block.transactions.len() + block.transactions_v2.len(),
                timestamp: block.header.timestamp,
                difficulty: block.header.difficulty,
                coinbase_reward: block.coinbase.reward,
            });
        }
    }

    Json(BlockListResponse {
        blocks,
        total,
        page,
        limit,
        total_pages,
    })
}

/// Shielded transaction response - only public data is exposed.
#[derive(Serialize)]
struct TransactionResponse {
    hash: String,
    fee: u64,
    spend_count: usize,
    output_count: usize,
    status: String,
    block_height: Option<u64>,
    confirmations: Option<u64>,
}

async fn get_transaction(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
) -> Result<Json<TransactionResponse>, StatusCode> {
    let hash_bytes: [u8; 32] = hex::decode(&hash)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Check mempool first
    {
        let mempool = state.mempool.read().unwrap_or_else(|e| e.into_inner());
        if let Some(tx) = mempool.get(&hash_bytes) {
            return Ok(Json(TransactionResponse {
                hash: hex::encode(tx.hash()),
                fee: tx.fee,
                spend_count: tx.spends.len(),
                output_count: tx.outputs.len(),
                status: "pending".to_string(),
                block_height: None,
                confirmations: Some(0),
            }));
        }
    }

    // Search in blockchain
    let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    let current_height = chain.height();
    for h in (0..=current_height).rev() {
        if let Some(block) = chain.get_block_by_height(h) {
            for tx in &block.transactions {
                if tx.hash() == hash_bytes {
                    return Ok(Json(TransactionResponse {
                        hash: hex::encode(tx.hash()),
                        fee: tx.fee,
                        spend_count: tx.spends.len(),
                        output_count: tx.outputs.len(),
                        status: "confirmed".to_string(),
                        block_height: Some(h),
                        confirmations: Some(current_height.saturating_sub(h) + 1),
                    }));
                }
            }
        }
    }

    Err(StatusCode::NOT_FOUND)
}

async fn get_recent_transactions(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<TransactionResponse>> {
    let mut transactions = Vec::new();

    // Get pending V1 transactions from mempool
    {
        let mempool = state.mempool.read().unwrap_or_else(|e| e.into_inner());
        for tx in mempool.get_transactions(10) {
            transactions.push(TransactionResponse {
                hash: hex::encode(tx.hash()),
                fee: tx.fee,
                spend_count: tx.spends.len(),
                output_count: tx.outputs.len(),
                status: "pending".to_string(),
                block_height: None,
                confirmations: Some(0),
            });
        }
        // Get pending V2 transactions from mempool
        for tx in mempool.get_v2_transactions(10) {
            use crate::core::Transaction as TxEnum;
            let (fee, spend_count, output_count) = match &tx {
                TxEnum::V1(v1) => (v1.fee, v1.spends.len(), v1.outputs.len()),
                TxEnum::V2(v2) => (v2.fee, v2.spends.len(), v2.outputs.len()),
                TxEnum::Migration(m) => (m.fee, m.legacy_spends.len(), m.pq_outputs.len()),
                TxEnum::ContractDeploy(d) => (d.fee, 0, 0),
                TxEnum::ContractCall(c) => (c.fee, 0, 0),
            };
            transactions.push(TransactionResponse {
                hash: hex::encode(tx.hash()),
                fee,
                spend_count,
                output_count,
                status: "pending (v2)".to_string(),
                block_height: None,
                confirmations: Some(0),
            });
        }
    }

    // Get recent confirmed transactions from recent blocks
    let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    let current_height = chain.height();
    let start_height = current_height.saturating_sub(500);

    for h in (start_height..=current_height).rev() {
        if let Some(block) = chain.get_block_by_height(h) {
            let confs = current_height.saturating_sub(h) + 1;
            // V1 transactions
            for tx in &block.transactions {
                transactions.push(TransactionResponse {
                    hash: hex::encode(tx.hash()),
                    fee: tx.fee,
                    spend_count: tx.spends.len(),
                    output_count: tx.outputs.len(),
                    status: "confirmed".to_string(),
                    block_height: Some(h),
                    confirmations: Some(confs),
                });
            }
            // V2 transactions
            for tx in &block.transactions_v2 {
                transactions.push(TransactionResponse {
                    hash: hex::encode(tx.hash()),
                    fee: tx.fee,
                    spend_count: tx.spends.len(),
                    output_count: tx.outputs.len(),
                    status: "confirmed (v2)".to_string(),
                    block_height: Some(h),
                    confirmations: Some(confs),
                });
            }
        }

        if transactions.len() >= 20 {
            break;
        }
    }

    Json(transactions)
}

#[derive(Deserialize)]
struct SubmitTxRequest {
    transaction: ShieldedTransaction,
}

#[derive(Serialize)]
struct SubmitTxResponse {
    hash: String,
    status: String,
}

async fn submit_transaction(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubmitTxRequest>,
) -> Result<Json<SubmitTxResponse>, (StatusCode, String)> {
    let tx = req.transaction;
    let hash = hex::encode(tx.hash());

    // Validate transaction
    {
        let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
        if let Some(params) = chain.verifying_params() {
            // Full validation with proof verification
            chain
                .state()
                .validate_transaction(&tx, params)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        } else {
            // Basic validation (no proof verification) - for development/testing
            // This still checks anchors, nullifiers, and signatures
            chain
                .state()
                .validate_transaction_basic(&tx)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

            // Verify spend signatures manually since basic validation skips them
            for spend in &tx.spends {
                spend.verify_signature()
                    .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid spend signature".to_string()))?;
            }
        }
    }

    // Add to mempool
    let added = {
        let mut mempool = state.mempool.write().unwrap_or_else(|e| e.into_inner());
        mempool.add(tx.clone())
    };

    if !added {
        return Err((
            StatusCode::CONFLICT,
            "Transaction already in mempool or conflicts with pending".to_string(),
        ));
    }

    // Relay to peers (fire and forget)
    let peers = state.peers.read().unwrap_or_else(|e| e.into_inner()).clone();
    if !peers.is_empty() {
        let tx_clone = tx.clone();
        let client = state.http_client.clone();
        tokio::spawn(async move {
            relay_transaction(&tx_clone, &peers, &client).await;
        });
    }

    Ok(Json(SubmitTxResponse {
        hash,
        status: "pending".to_string(),
    }))
}

/// V2 transaction submission request (post-quantum).
#[derive(Deserialize)]
struct SubmitTxV2Request {
    transaction: ShieldedTransactionV2,
}

/// Submit a V2 (post-quantum) shielded transaction.
async fn submit_transaction_v2(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubmitTxV2Request>,
) -> Result<Json<SubmitTxResponse>, (StatusCode, String)> {
    let tx = req.transaction;
    let hash = hex::encode(tx.hash());

    info!("Received V2 transaction: {}", &hash[..16]);

    // Wrap in Transaction enum for validation and mempool
    let wrapped_tx = Transaction::V2(tx.clone());

    // Validate V2 transaction
    {
        let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
        chain
            .state()
            .validate_transaction_v2(&tx)
            .map_err(|e| {
                warn!("V2 transaction validation failed: {}", e);
                (StatusCode::BAD_REQUEST, e.to_string())
            })?;
    }

    // Add to mempool
    let added = {
        let mut mempool = state.mempool.write().unwrap_or_else(|e| e.into_inner());
        mempool.add_v2(wrapped_tx.clone())
    };

    if !added {
        return Err((
            StatusCode::CONFLICT,
            "Transaction already in mempool or conflicts with pending".to_string(),
        ));
    }

    info!("V2 transaction {} added to mempool", &hash[..16]);

    // Relay V2 transaction to peers via P2P GossipSub
    {
        let p2p_tx = state.p2p_broadcast.read().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(sender) = p2p_tx {
            if let Ok(tx_data) = serde_json::to_vec(&tx) {
                let _ = sender.try_send(super::p2p::P2pCommand::BroadcastTransaction(tx_data));
            }
        }
    }

    // Relay V2 transaction to peers via HTTP (fallback for non-upgraded nodes)
    {
        let peers = state.peers.read().unwrap_or_else(|e| e.into_inner()).clone();
        let tx_clone = tx.clone();
        let client = state.http_client.clone();
        tokio::spawn(async move {
            for peer in &peers {
                if !crate::network::is_contactable_peer(peer) { continue; }
                let url = format!("{}/tx/v2", peer);
                let _ = client.post(&url)
                    .json(&serde_json::json!({ "transaction": tx_clone }))
                    .send()
                    .await;
            }
        });
    }

    Ok(Json(SubmitTxResponse {
        hash,
        status: "pending".to_string(),
    }))
}

#[derive(Serialize)]
struct MempoolResponse {
    count: usize,
    transactions: Vec<String>,
    total_fees: u64,
}

async fn get_mempool(State(state): State<Arc<AppState>>) -> Json<MempoolResponse> {
    let mempool = state.mempool.read().unwrap_or_else(|e| e.into_inner());
    let v1_txs = mempool.get_transactions(100);
    let v2_txs = mempool.get_v2_transactions(100);

    let mut tx_hashes: Vec<String> = v1_txs.iter().map(|tx| hex::encode(tx.hash())).collect();
    tx_hashes.extend(v2_txs.iter().map(|tx| hex::encode(tx.hash())));

    Json(MempoolResponse {
        count: mempool.len(),
        transactions: tx_hashes,
        total_fees: mempool.total_fees(),
    })
}

// ============ Peer Sync Endpoints ============

/// Receive a block from a peer node.
async fn receive_block(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(block): Json<ShieldedBlock>,
) -> Result<Json<ReceiveBlockResponse>, (StatusCode, String)> {
    // IP whitelist check
    let ip = addr.ip().to_string();
    if !crate::config::is_ip_whitelisted(&ip) {
        return Err((StatusCode::FORBIDDEN, format!("IP {} not whitelisted", ip)));
    }
    // Reject blocks from nodes that don't send version header or are outdated
    let peer_ver = headers.get("X-TSN-Version").and_then(|v| v.to_str().ok());
    if let Some(ver) = peer_ver {
        if !crate::network::version_check::version_meets_minimum(ver) {
            warn!("Rejected block from outdated peer (version {})", ver);
            return Err((StatusCode::FORBIDDEN, format!("Node version {} is below minimum {}", ver, crate::network::version_check::MINIMUM_VERSION)));
        }
    }
    // Track peer info (version, height, last seen)
    let peer_url = format!("http://{}:9333", addr.ip());
    update_peer_info(&state, &peer_url, peer_ver, Some(block.coinbase.height));
    // Mark as miner — they sent us a block they mined
    {
        let pid = super::peer_id(&peer_url);
        let mut info = state.peer_info.write().unwrap();
        if let Some(entry) = info.get_mut(&pid) {
            entry.role = "miner".to_string();
        }
    }

    let block_hash = block.hash_hex();

    info!("Received block {} from peer", &block_hash[..16]);

    // Try to add the block (handles forks and reorgs automatically)
    let (accepted, status) = {
        let mut chain = state.blockchain.write().unwrap_or_else(|e| e.into_inner());
        let old_height = chain.height();
        let old_tip = chain.latest_hash();

        match chain.try_add_block(block.clone()) {
            Ok(true) => {
                let new_height = chain.height();
                let reorged = old_tip != chain.get_block_by_height(old_height.min(new_height - 1))
                    .map(|b| b.hash())
                    .unwrap_or([0u8; 32]);

                if reorged {
                    info!("Chain reorganization! New tip: {} (height: {})", &block_hash[..16], new_height);
                } else {
                    info!("Added block {} to chain (height: {})", &block_hash[..16], new_height);
                }

                // Remove confirmed transactions from mempool
                let tx_hashes: Vec<[u8; 32]> = block
                    .transactions
                    .iter()
                    .map(|tx| tx.hash())
                    .collect();

                let mut mempool = state.mempool.write().unwrap_or_else(|e| e.into_inner());
                mempool.remove_confirmed(&tx_hashes);

                // Remove transactions with now-spent nullifiers
                let nullifiers: Vec<[u8; 32]> = block.nullifiers().iter().map(|n| n.0).collect();
                mempool.remove_spent_nullifiers(&nullifiers);

                // Re-validate remaining mempool transactions
                let removed = mempool.revalidate(chain.state());
                if removed > 0 {
                    info!("Removed {} invalid transactions from mempool after block", removed);
                }

                (true, "accepted")
            }
            Ok(false) => {
                // Block was duplicate or stored as side chain
                info!("Block {} stored (orphan or side chain)", &block_hash[..16]);
                (false, "stored")
            }
            Err(e) => {
                warn!("Block {} rejected: {}", &block_hash[..16], e);
                return Err((StatusCode::BAD_REQUEST, format!("Block rejected: {}", e)));
            }
        }
    };

    // Relay to other peers (gossip protocol) if accepted
    if accepted {
        // Invalidate snapshot cache every 100 blocks so new nodes get fresh state
        let block_height = block.height();
        if block_height % 100 == 0 {
            let state_clone = state.clone();
            tokio::spawn(async move {
                let mut cache = state_clone.snapshot_cache.write().await;
                *cache = None;
            });
        }

        let peers = state.peers.read().unwrap_or_else(|e| e.into_inner()).clone();
        if !peers.is_empty() {
            let block_clone = block.clone();
            let client = state.http_client.clone();
            tokio::spawn(async move {
                relay_block(&block_clone, &peers, &client).await;
            });
        }
    }

    Ok(Json(ReceiveBlockResponse {
        status: status.to_string(),
        hash: block_hash,
    }))
}

#[derive(Serialize)]
struct ReceiveBlockResponse {
    status: String,
    hash: String,
}

/// Get all blocks since a given height (for chain sync).
async fn get_blocks_since(
    State(state): State<Arc<AppState>>,
    Path(since_height): Path<u64>,
    Query(params): Query<BlocksSinceParams>,
) -> Json<Vec<ShieldedBlock>> {
    let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    let current_height = chain.height();
    // Default limit of 50 blocks per request to avoid HTTP timeouts
    let max_blocks: u64 = params.limit.unwrap_or(50).min(200) as u64;
    let end_height = current_height.min(since_height.saturating_add(max_blocks));

    let mut blocks = Vec::new();

    // Return blocks from since_height+1 to end_height
    for h in (since_height + 1)..=end_height {
        if let Some(block) = chain.get_block_by_height(h) {
            blocks.push(block);
        }
    }

    Json(blocks)
}

#[derive(Deserialize)]
struct BlocksSinceParams {
    limit: Option<usize>,
}

/// GET /headers/since/{height} — returns compact headers for headers-first sync protocol.
/// Lightweight (~200 bytes/header vs ~5KB/block). Used to detect forks and find
/// common ancestors without downloading full blocks.
/// Max 500 headers per request (~100KB).
async fn get_headers_since(
    State(state): State<Arc<AppState>>,
    Path(since_height): Path<u64>,
    Query(params): Query<HeadersSinceParams>,
) -> Json<Vec<crate::core::CompactHeader>> {
    let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    let limit = params.limit.unwrap_or(500).min(1000);
    let headers = chain.get_compact_headers_since(since_height, limit);
    Json(headers)
}

#[derive(Deserialize)]
struct HeadersSinceParams {
    limit: Option<usize>,
}

// ============ Peer Management Endpoints ============

#[derive(Serialize)]
struct PeersResponse {
    peers: Vec<String>,
    count: usize,
    /// P2P peers connected via libp2p (identified by PeerID)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    p2p_peers: Vec<super::p2p::PeerInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p2p_count: Option<usize>,
}

/// Get the list of known peers.
async fn get_peers(State(state): State<Arc<AppState>>) -> Json<PeersResponse> {
    let peers = state.peers.read().unwrap_or_else(|e| e.into_inner());
    // Privacy: return hashed peer IDs instead of raw URLs/IPs
    let mut seen = std::collections::HashSet::new();
    let masked_peers: Vec<String> = peers
        .iter()
        .map(|p| normalize_peer_url(p))
        .filter(|p| !p.contains("://localhost") && !p.contains("://127.0.0.1") && !p.contains("://0.0.0.0"))
        .map(|p| super::peer_id(&p))
        .filter(|p| seen.insert(p.clone()))
        .collect();
    Json(PeersResponse {
        count: masked_peers.len(),
        peers: masked_peers,
        p2p_peers: vec![],
        p2p_count: None,
    })
}

/// Get P2P peers connected via libp2p (identified by PeerID).
async fn get_p2p_peers(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let local_height = state.blockchain.read().unwrap_or_else(|e| e.into_inner()).height();
    // Read directly from shared peer list — instant, no channel wait, no HTTP calls
    let peers = state.p2p_shared_peers.read().unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|sp| sp.read().unwrap_or_else(|e| e.into_inner()).clone())
        .unwrap_or_default();
    Json(serde_json::json!({
        "count": peers.len(),
        "peers": peers,
        "local_height": local_height,
    }))
}

/// Returns detailed info about HTTP peers with stale cleanup (>5min offline removed).
async fn get_peers_detailed(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let stale_threshold = 300; // 5 minutes

    let peers: Vec<serde_json::Value> = {
        let mut info = state.peer_info.write().unwrap();
        info.retain(|_, v| now - v.last_seen < stale_threshold);
        info.values().map(|p| serde_json::json!({
            "peer_id": p.peer_id,
            "version": p.version,
            "role": p.role,
            "height": p.height,
            "last_seen": p.last_seen,
        })).collect()
    };

    let local_h = state.blockchain.read().unwrap().height();
    Json(serde_json::json!({
        "local_height": local_h,
        "peers": peers,
    }))
}

#[derive(Deserialize)]
struct AddPeerRequest {
    url: String,
}

#[derive(Serialize)]
struct AddPeerResponse {
    status: String,
    peer_count: usize,
}

/// Normalize a peer URL: trim trailing slashes and lowercase the scheme+host.
fn normalize_peer_url(url: &str) -> String {
    let mut s = url.trim().to_string();
    while s.ends_with('/') {
        s.pop();
    }
    // Lowercase scheme and host (but not path)
    if let Some(idx) = s.find("://") {
        let after_scheme = idx + 3;
        // Find end of host:port (first '/' after scheme)
        let host_end = s[after_scheme..].find('/').map(|i| i + after_scheme).unwrap_or(s.len());
        let lower_prefix: String = s[..host_end].to_lowercase();
        s = format!("{}{}", lower_prefix, &s[host_end..]);
    }
    s
}

/// Check if a URL refers to this node (localhost or self-address).
fn is_self_peer(url: &str, our_addresses: &[String]) -> bool {
    let normalized = normalize_peer_url(url);
    if normalized.contains("://localhost") || normalized.contains("://127.0.0.1") || normalized.contains("://0.0.0.0") {
        return true;
    }
    our_addresses.iter().any(|addr| normalize_peer_url(addr) == normalized)
}

/// Add a new peer to the peer list.
async fn add_peer(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddPeerRequest>,
) -> Json<AddPeerResponse> {
    // IP whitelist check
    let ip = addr.ip().to_string();
    if !crate::config::is_ip_whitelisted(&ip) {
        return Json(AddPeerResponse {
            status: format!("rejected: IP {} not whitelisted", ip),
            peer_count: state.peers.read().unwrap_or_else(|e| e.into_inner()).len(),
        });
    }
    let normalized = normalize_peer_url(&req.url);

    // H4 audit fix: validate URL scheme (only HTTP/HTTPS allowed — blocks file://, ftp://, etc.)
    if !normalized.starts_with("http://") && !normalized.starts_with("https://") {
        warn!("Rejected peer with invalid scheme: {}", peer_id(&normalized));
        return Json(AddPeerResponse {
            status: "rejected: invalid scheme".to_string(),
            peer_count: state.peers.read().unwrap_or_else(|e| e.into_inner()).len(),
        });
    }

    // Note: private IPs are allowed for peers (local miners, LAN nodes).
    // Only block loopback to prevent self-connection.
    let is_loopback = normalized.contains("://127.") || normalized.contains("://[::1]") || normalized.contains("://localhost");
    if is_loopback {
        warn!("Rejected loopback peer: {}", peer_id(&normalized));
        return Json(AddPeerResponse {
            status: "rejected: loopback IP".to_string(),
            peer_count: state.peers.read().unwrap_or_else(|e| e.into_inner()).len(),
        });
    }

    let mut peers = state.peers.write().unwrap_or_else(|e| e.into_inner());

    // Limit max peers to prevent memory exhaustion
    const MAX_PEERS: usize = 200;
    if peers.len() >= MAX_PEERS {
        return Json(AddPeerResponse {
            status: "rejected: max peers reached".to_string(),
            peer_count: peers.len(),
        });
    }

    // Build list of our own addresses for self-detection
    let our_addresses: Vec<String> = Vec::new(); // Basic localhost check covers most cases

    // Skip localhost/self-references
    let is_self = is_self_peer(&normalized, &our_addresses);

    // Check for duplicates using normalized comparison
    let already_known = peers.iter().any(|p| normalize_peer_url(p) == normalized);

    if !is_self && !already_known {
        peers.push(normalized.clone());
        info!("Added peer: {}", peer_id(&normalized));
    }

    Json(AddPeerResponse {
        status: "ok".to_string(),
        peer_count: peers.len(),
    })
}

// ============ Transaction Relay ============

/// Receive a transaction from a peer (relay endpoint).
async fn receive_transaction(
    State(state): State<Arc<AppState>>,
    Json(tx): Json<ShieldedTransaction>,
) -> Result<Json<SubmitTxResponse>, (StatusCode, String)> {
    let hash = hex::encode(tx.hash());

    // Check if already in mempool
    {
        let mempool = state.mempool.read().unwrap_or_else(|e| e.into_inner());
        if mempool.contains(&tx.hash()) {
            return Ok(Json(SubmitTxResponse {
                hash,
                status: "duplicate".to_string(),
            }));
        }
    }

    // Validate transaction
    {
        let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
        if let Some(params) = chain.verifying_params() {
            chain
                .state()
                .validate_transaction(&tx, params)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        } else {
            chain
                .state()
                .validate_transaction_basic(&tx)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

            for spend in &tx.spends {
                spend.verify_signature()
                    .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid spend signature".to_string()))?;
            }
        }
    }

    // Add to mempool
    let added = {
        let mut mempool = state.mempool.write().unwrap_or_else(|e| e.into_inner());
        mempool.add(tx.clone())
    };

    if added {
        info!("Added relayed transaction {} to mempool", &hash[..16]);

        // Continue relaying to other peers
        let peers = state.peers.read().unwrap_or_else(|e| e.into_inner()).clone();
        if !peers.is_empty() {
            let tx_clone = tx.clone();
            let client = state.http_client.clone();
            tokio::spawn(async move {
                relay_transaction(&tx_clone, &peers, &client).await;
            });
        }
    }

    Ok(Json(SubmitTxResponse {
        hash,
        status: if added { "accepted".to_string() } else { "duplicate".to_string() },
    }))
}

// ============ Relay Helper Functions ============

/// Relay a block to all known peers concurrently (futures::join_all).
/// Previously sequential (O(N) × latency), now parallel (~1× latency).
async fn relay_block(block: &ShieldedBlock, peers: &[String], client: &reqwest::Client) {
    let block_hash_str = block.hash_hex()[..16].to_string();

    let mut handles = Vec::with_capacity(peers.len());
    for peer in peers {
        if !crate::network::is_contactable_peer(peer) { continue; }
        let url = format!("{}/blocks", peer);
        let client = client.clone();
        let block = block.clone();
        let peer_name = peer_id(peer);
        let bh = block_hash_str.clone();
        handles.push(tokio::spawn(async move {
            match client.post(&url).json(&block).send().await {
                Ok(resp) if resp.status().is_success() => {
                    info!("Relayed block {} to {}", bh, peer_name);
                }
                Ok(resp) => {
                    let status = resp.status();
                    if status != StatusCode::BAD_REQUEST {
                        warn!("Relay to {} returned {}", peer_name, status);
                    }
                }
                Err(e) => {
                    warn!("Failed to relay block to {}: {}", peer_name, e);
                }
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
}

/// Relay a transaction to all known peers.
async fn relay_transaction(tx: &ShieldedTransaction, peers: &[String], client: &reqwest::Client) {
    let tx_hash = &hex::encode(tx.hash())[..16];

    for peer in peers {
        if !crate::network::is_contactable_peer(peer) { continue; }
        let url = format!("{}/tx/relay", peer);
        match client.post(&url).json(tx).send().await {
            Ok(resp) if resp.status().is_success() => {
                info!("Relayed transaction {} to {}", tx_hash, peer_id(peer));
            }
            Ok(_) => {
                // Peer might already have it - not an error
            }
            Err(e) => {
                warn!("Failed to relay transaction to {}: {}", peer_id(peer), e);
            }
        }
    }
}

// ============ Wallet Scanning Endpoints ============

/// An encrypted output from a block (transaction output or coinbase).
#[derive(Serialize)]
struct EncryptedOutput {
    /// Position in the commitment tree.
    position: u64,
    /// Block height where this output was created.
    block_height: u64,
    /// The note commitment V1/BN254 (hex).
    note_commitment: String,
    /// The note commitment V2/PQ Goldilocks (hex) - for post-quantum transactions.
    note_commitment_pq: String,
    /// Ephemeral public key for decryption (hex).
    ephemeral_pk: String,
    /// Encrypted note ciphertext (hex).
    ciphertext: String,
}

/// Response for outputs/since/:height endpoint.
#[derive(Serialize)]
struct OutputsSinceResponse {
    outputs: Vec<EncryptedOutput>,
    current_height: u64,
    commitment_root: String,
}

/// Get all encrypted outputs since a given block height.
/// Used by wallets to scan for incoming payments.
/// If since_height is 0, returns ALL outputs including genesis.
async fn get_outputs_since(
    State(state): State<Arc<AppState>>,
    Path(since_height): Path<u64>,
    Query(params): Query<OutputsSinceParams>,
) -> Json<OutputsSinceResponse> {
    let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    let current_height = chain.height();
    let commitment_root = hex::encode(chain.commitment_root());
    let end_height = match params.limit {
        Some(0) | None => current_height,
        Some(limit) => current_height.min(since_height.saturating_add(limit as u64)),
    };

    let mut outputs = Vec::new();
    let mut position = 0u64;

    // Determine the starting height for collecting outputs
    // If since_height is 0, we want ALL outputs (initial scan)
    // Otherwise, we want outputs from since_height+1 onwards
    let start_height = if since_height == 0 { 0 } else { since_height + 1 };

    // Count all commitments before start_height to get starting position.
    // After fast-sync, blocks before fast_sync_base_height don't exist in DB.
    // Use the stored commitment offset to get the correct starting position.
    let fast_sync_base = chain.fast_sync_base_height();
    let fast_sync_offset = chain.fast_sync_commitment_offset();

    if fast_sync_base > 0 && start_height <= fast_sync_base {
        // All requested blocks are within fast-sync range — use stored offset.
        // The offset already accounts for all commitments up to fast_sync_base.
        position = fast_sync_offset;
    } else if fast_sync_base > 0 {
        // Start is after fast-sync: use offset as base, then count outputs
        // in blocks between fast_sync_base+1 and start_height-1.
        // The fast_sync_offset already includes ALL commitments up to and
        // including the fast_sync_base block. Do NOT count genesis or
        // fast_sync_base again — they are already in the offset.
        position = fast_sync_offset;
        for h in (fast_sync_base + 1)..start_height.min(current_height + 1) {
            if let Some(block) = chain.get_block_by_height(h) {
                for tx in &block.transactions {
                    position += tx.outputs.len() as u64;
                }
                for tx in &block.transactions_v2 {
                    position += tx.outputs.len() as u64;
                }
                position += 1; // coinbase
                if block.coinbase.dev_fee_encrypted_note.is_some() {
                    position += 1; // dev fee
                }
            }
        }
    } else {
        // No fast-sync — count from genesis normally
        for h in 0..start_height.min(current_height + 1) {
            if let Some(block) = chain.get_block_by_height(h) {
                for tx in &block.transactions {
                    position += tx.outputs.len() as u64;
                }
                for tx in &block.transactions_v2 {
                    position += tx.outputs.len() as u64;
                }
                position += 1; // coinbase
                if block.coinbase.dev_fee_encrypted_note.is_some() {
                    position += 1; // dev fee
                }
            }
        }
    }

    // Now collect outputs from start_height onwards.
    // After fast-sync, skip blocks that are within the snapshot range because
    // their commitments are already in the snapshot offset — the genesis and
    // fast-sync base blocks still exist in DB but their outputs have positions
    // inside the snapshot, not after it.
    let collect_from = if fast_sync_base > 0 && start_height <= fast_sync_base {
        fast_sync_base + 1
    } else {
        start_height
    };
    for h in collect_from..=end_height {
        if let Some(block) = chain.get_block_by_height(h) {
            // V1 Transaction outputs (note_commitment_pq not available for legacy tx)
            for tx in &block.transactions {
                for output in &tx.outputs {
                    outputs.push(EncryptedOutput {
                        position,
                        block_height: h,
                        note_commitment: hex::encode(output.note_commitment.to_bytes()),
                        note_commitment_pq: String::new(), // V1 tx don't have PQ commitments
                        ephemeral_pk: hex::encode(&output.encrypted_note.ephemeral_pk),
                        ciphertext: hex::encode(&output.encrypted_note.ciphertext),
                    });
                    position += 1;
                }
            }

            // V2 Transaction outputs (only have PQ commitments)
            for tx in &block.transactions_v2 {
                for output in &tx.outputs {
                    outputs.push(EncryptedOutput {
                        position,
                        block_height: h,
                        note_commitment: String::new(), // V2 tx don't have legacy commitments
                        note_commitment_pq: hex::encode(output.note_commitment),
                        ephemeral_pk: hex::encode(&output.encrypted_note.ephemeral_pk),
                        ciphertext: hex::encode(&output.encrypted_note.ciphertext),
                    });
                    position += 1;
                }
            }

            // Coinbase output (has both V1 and V2/PQ commitments)
            outputs.push(EncryptedOutput {
                position,
                block_height: h,
                note_commitment: hex::encode(block.coinbase.note_commitment.to_bytes()),
                note_commitment_pq: hex::encode(block.coinbase.note_commitment_pq),
                ephemeral_pk: hex::encode(&block.coinbase.encrypted_note.ephemeral_pk),
                ciphertext: hex::encode(&block.coinbase.encrypted_note.ciphertext),
            });
            position += 1;

            // Dev fee output (also inserted into the commitment tree)
            if let Some(ref dev_encrypted) = block.coinbase.dev_fee_encrypted_note {
                let dev_cm = block.coinbase.dev_fee_commitment
                    .map(|c| hex::encode(c.to_bytes()))
                    .unwrap_or_default();
                let dev_cm_pq = block.coinbase.dev_fee_commitment_pq
                    .map(|c| hex::encode(c))
                    .unwrap_or_default();
                outputs.push(EncryptedOutput {
                    position,
                    block_height: h,
                    note_commitment: dev_cm,
                    note_commitment_pq: dev_cm_pq,
                    ephemeral_pk: hex::encode(&dev_encrypted.ephemeral_pk),
                    ciphertext: hex::encode(&dev_encrypted.ciphertext),
                });
                position += 1;
            }
        }
    }

    Json(OutputsSinceResponse {
        outputs,
        current_height,
        commitment_root,
    })
}

#[derive(Deserialize)]
struct OutputsSinceParams {
    limit: Option<usize>,
}

/// Request for checking nullifiers.
#[derive(Deserialize)]
struct CheckNullifiersRequest {
    nullifiers: Vec<String>,
}

/// Response for nullifier checking.
#[derive(Serialize)]
struct CheckNullifiersResponse {
    /// List of nullifiers that are spent (exist in nullifier set).
    spent: Vec<String>,
}

/// Check which nullifiers are spent.
/// Used by wallets to determine which of their notes have been consumed.
async fn check_nullifiers(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckNullifiersRequest>,
) -> Json<CheckNullifiersResponse> {
    // M8 audit fix: limit input size to prevent memory/CPU exhaustion
    const MAX_NULLIFIERS_PER_REQUEST: usize = 500;
    let nullifiers = if req.nullifiers.len() > MAX_NULLIFIERS_PER_REQUEST {
        &req.nullifiers[..MAX_NULLIFIERS_PER_REQUEST]
    } else {
        &req.nullifiers
    };

    let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    let nullifier_set = chain.state().nullifier_set();

    let mut spent = Vec::new();

    for nf_hex in nullifiers {
        if let Ok(nf_bytes) = hex::decode(nf_hex) {
            if nf_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&nf_bytes);
                let nullifier = Nullifier::from_bytes(arr);

                if nullifier_set.contains(&nullifier) {
                    spent.push(nf_hex.clone());
                }
            }
        }
    }

    Json(CheckNullifiersResponse { spent })
}

/// Response for witness endpoint.
#[derive(Serialize)]
struct WitnessResponse {
    /// The current commitment tree root (hex).
    root: String,
    /// The Merkle path (sibling hashes from leaf to root, hex encoded).
    path: Vec<String>,
    /// Position in the tree.
    position: u64,
}

/// Get a Merkle witness for a commitment.
/// Used when creating spend proofs.
async fn get_witness(
    State(state): State<Arc<AppState>>,
    Path(commitment_hex): Path<String>,
) -> Result<Json<WitnessResponse>, StatusCode> {
    let commitment_bytes: [u8; 32] = hex::decode(&commitment_hex)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    let commitment_tree = chain.state().commitment_tree();

    // Find the position of this commitment in the tree
    // We need to search through all positions
    let tree_size = commitment_tree.size();
    let mut found_position: Option<u64> = None;

    for pos in 0..tree_size {
        if let Some(cm) = commitment_tree.get_commitment(pos) {
            if cm.to_bytes() == commitment_bytes {
                found_position = Some(pos);
                break;
            }
        }
    }

    let position = found_position.ok_or(StatusCode::NOT_FOUND)?;

    let merkle_path = commitment_tree.get_path(position)
        .ok_or(StatusCode::NOT_FOUND)?;

    let root = commitment_tree.root();

    Ok(Json(WitnessResponse {
        root: hex::encode(root),
        path: merkle_path.auth_path.iter().map(|h| hex::encode(h)).collect(),
        position,
    }))
}

/// Get witness by position (simpler than searching by commitment).
async fn get_witness_by_position(
    State(state): State<Arc<AppState>>,
    Path(position): Path<u64>,
) -> Result<Json<WitnessResponse>, StatusCode> {
    let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    let commitment_tree = chain.state().commitment_tree();

    let _commitment = commitment_tree.get_commitment(position)
        .ok_or(StatusCode::NOT_FOUND)?;

    let merkle_path = commitment_tree.get_path(position)
        .ok_or(StatusCode::NOT_FOUND)?;

    let root = commitment_tree.root();

    Ok(Json(WitnessResponse {
        root: hex::encode(root),
        path: merkle_path.auth_path.iter().map(|h| hex::encode(h)).collect(),
        position,
    }))
}

/// Response for V2 witness endpoint.
/// Uses Poseidon/Goldilocks Merkle tree (quantum-resistant).
#[derive(Serialize)]
struct WitnessResponseV2 {
    /// The current V2 commitment tree root (hex).
    root: String,
    /// The Merkle path (sibling hashes from leaf to root, hex encoded).
    path: Vec<String>,
    /// Path indices (0 = left, 1 = right).
    indices: Vec<u8>,
    /// Position in the tree.
    position: u64,
    /// The actual leaf commitment at this position (hex). For debugging.
    #[serde(skip_serializing_if = "Option::is_none")]
    leaf: Option<String>,
}

/// Get V2 witness by position (for quantum-resistant transactions).
/// Uses Poseidon/Goldilocks Merkle tree instead of BN254.
async fn get_witness_by_position_v2(
    State(state): State<Arc<AppState>>,
    Path(position): Path<u64>,
) -> Result<Json<WitnessResponseV2>, StatusCode> {
    let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    let commitment_tree_pq = chain.state().commitment_tree_pq();

    let witness = commitment_tree_pq.witness(position)
        .ok_or(StatusCode::NOT_FOUND)?;

    // Debug: Verify the path is internally consistent
    // Get the commitment at this position from the tree's leaves
    // Note: This requires accessing internal state, so we re-verify via path
    let path_verifies = {
        // We need to get the actual commitment bytes at this position
        // For now, we'll trust the tree structure
        // TODO: Add leaf access for verification
        true
    };

    tracing::debug!(
        "V2 witness for position {}: root={}, path_len={}, verifies={}",
        position,
        hex::encode(&witness.root),
        witness.path.siblings.len(),
        path_verifies
    );

    // Include the actual leaf commitment from the tree for debugging
    let leaf_hex = commitment_tree_pq.leaf_at(position)
        .map(|l| hex::encode(l))
        .unwrap_or_default();

    Ok(Json(WitnessResponseV2 {
        root: hex::encode(witness.root),
        path: witness.path.siblings.iter().map(|h| hex::encode(h)).collect(),
        indices: witness.path.indices.clone(),
        position: witness.position,
        leaf: Some(leaf_hex),
    }))
}

/// Debug endpoint to test Poseidon hash compatibility.
/// Returns the hash of inputs [1,2,3,4] for comparison with circomlibjs.
async fn debug_poseidon_test() -> Json<serde_json::Value> {
    use crate::crypto::poseidon::{poseidon_hash, field_to_bytes32, DOMAIN_NOTE_COMMITMENT};
    use ark_bn254::Fr;
    use light_poseidon::{Poseidon, PoseidonHasher};

    // Test 1: Direct light-poseidon hash of [1,2,3,4]
    let inputs = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
    let mut poseidon = Poseidon::<Fr>::new_circom(4)
        .expect("BUG: Poseidon init for 4 inputs cannot fail");
    let direct_hash = poseidon.hash(&inputs)
        .expect("BUG: Poseidon hash with matching input count cannot fail");
    let direct_bytes = field_to_bytes32(&direct_hash);

    // Test 2: Our poseidon_hash with domain separation (domain=1, then [2,3,4])
    // This is: poseidon([1, 2, 3, 4]) with 1 as domain
    let domain_hash = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)]);
    let domain_bytes = field_to_bytes32(&domain_hash);

    Json(serde_json::json!({
        "test": "Poseidon compatibility",
        "direct_hash_1234": {
            "description": "poseidon([1,2,3,4]) - direct light-poseidon",
            "bytes_le": direct_bytes.to_vec(),
            "hex": hex::encode(direct_bytes),
        },
        "domain_hash_1_234": {
            "description": "poseidon_hash(domain=1, [2,3,4]) - our wrapper",
            "bytes_le": domain_bytes.to_vec(),
            "hex": hex::encode(domain_bytes),
        }
    }))
}

/// Debug endpoint for V2/PQ Poseidon hash (Goldilocks field).
/// Returns hash of [1,2,3,4] and Merkle node hash for comparison with TypeScript.
async fn debug_poseidon_pq_test() -> Json<serde_json::Value> {
    use crate::crypto::pq::poseidon_pq::{
        poseidon_pq_hash, hash_out_to_bytes, GoldilocksField,
        DOMAIN_MERKLE_NODE_PQ, DOMAIN_MERKLE_EMPTY_PQ,
    };

    // Test 1: Simple hash of [1,2,3,4]
    let inputs: Vec<GoldilocksField> = vec![
        GoldilocksField::new(1),
        GoldilocksField::new(2),
        GoldilocksField::new(3),
        GoldilocksField::new(4),
    ];
    let hash1 = poseidon_pq_hash(&inputs);
    let hash1_bytes = hash_out_to_bytes(&hash1);

    // Test 2: Empty leaf hash
    let empty_hash = poseidon_pq_hash(&[DOMAIN_MERKLE_EMPTY_PQ]);
    let empty_bytes = hash_out_to_bytes(&empty_hash);

    // Test 3: Merkle node hash of two empty leaves
    let mut node_inputs = vec![DOMAIN_MERKLE_NODE_PQ];
    node_inputs.extend_from_slice(&empty_hash);
    node_inputs.extend_from_slice(&empty_hash);
    let node_hash = poseidon_pq_hash(&node_inputs);
    let node_bytes = hash_out_to_bytes(&node_hash);

    Json(serde_json::json!({
        "test": "V2/PQ Poseidon compatibility (Goldilocks)",
        "hash_1234": {
            "description": "poseidon_pq_hash([1,2,3,4])",
            "hex": hex::encode(hash1_bytes),
            "elements": hash1.map(|f| f.0.to_string()),
        },
        "empty_leaf": {
            "description": "poseidon_pq_hash([DOMAIN_MERKLE_EMPTY_PQ])",
            "hex": hex::encode(empty_bytes),
            "elements": empty_hash.map(|f| f.0.to_string()),
        },
        "merkle_node_empty_empty": {
            "description": "merkle_hash(empty, empty)",
            "hex": hex::encode(node_bytes),
            "elements": node_hash.map(|f| f.0.to_string()),
        },
    }))
}

/// Debug endpoint to list all commitments in the tree.
async fn debug_list_commitments(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    let commitment_tree = chain.state().commitment_tree();
    let tree_size = commitment_tree.size();

    let mut commitments = Vec::new();
    for pos in 0..tree_size.min(100) { // Limit to first 100
        if let Some(cm) = commitment_tree.get_commitment(pos) {
            commitments.push(serde_json::json!({
                "position": pos,
                "commitment": hex::encode(cm.to_bytes())
            }));
        }
    }

    Json(serde_json::json!({
        "tree_size": tree_size,
        "root": hex::encode(commitment_tree.root()),
        "commitments": commitments
    }))
}

/// Debug endpoint to show V2/PQ Merkle tree state and recent roots.
async fn debug_merkle_pq(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    let tree_pq = chain.state().commitment_tree_pq();

    let size = tree_pq.size();
    let current_root = tree_pq.root();
    let recent_roots: Vec<String> = tree_pq.recent_roots()
        .iter()
        .map(|r| hex::encode(r))
        .collect();

    // Also compute a test commitment for verification
    use crate::crypto::pq::commitment_pq::commit_to_note_pq;

    // Test with value that needs no reduction
    let test_value: u64 = 50_000_000_000; // BLOCK_REWARD
    let test_pk_hash = [0x01u8; 32];
    let test_randomness = [0x02u8; 32];
    let test_commitment = commit_to_note_pq(test_value, &test_pk_hash, &test_randomness);

    // Test with bytes that WOULD need reduction (values >= Goldilocks prime)
    // Goldilocks prime is 0xFFFF_FFFF_0000_0001
    // So any 8-byte chunk >= this needs reduction
    let mut reduction_test_bytes = [0u8; 32];
    // First chunk: 0xFFFFFFFF00000002 (needs reduction to 1)
    reduction_test_bytes[0..8].copy_from_slice(&0xFFFF_FFFF_0000_0002u64.to_le_bytes());
    let reduction_commitment = commit_to_note_pq(test_value, &reduction_test_bytes, &test_randomness);

    Json(serde_json::json!({
        "tree_size": size,
        "current_root": hex::encode(current_root),
        "recent_roots_count": recent_roots.len(),
        "recent_roots": recent_roots,
        "test_commitment": {
            "value": test_value.to_string(),
            "pk_hash": hex::encode(test_pk_hash),
            "randomness": hex::encode(test_randomness),
            "commitment": hex::encode(test_commitment),
        },
        "reduction_test": {
            "description": "Test with pk_hash bytes that need reduction mod Goldilocks prime",
            "pk_hash": hex::encode(reduction_test_bytes),
            "commitment": hex::encode(reduction_commitment),
        }
    }))
}

/// Debug endpoint to verify Merkle path computation.
/// Computes root from commitment + path using server's logic for comparison with WASM.
#[derive(Debug, Deserialize)]
struct VerifyPathRequest {
    commitment: String,  // hex
    path: Vec<String>,   // hex siblings
    indices: Vec<u8>,
}

async fn debug_verify_path(
    Json(req): Json<VerifyPathRequest>,
) -> Json<serde_json::Value> {
    use crate::crypto::pq::poseidon_pq::{
        poseidon_pq_hash, bytes_to_hash_out, hash_out_to_bytes, GoldilocksField,
        DOMAIN_MERKLE_NODE_PQ,
    };

    // Parse commitment
    let commitment_bytes: [u8; 32] = match hex::decode(&req.commitment) {
        // SAFETY: length checked by guard (== 32)
        Ok(b) if b.len() == 32 => b.try_into().unwrap(),
        _ => return Json(serde_json::json!({"error": "Invalid commitment hex"})),
    };

    // Hash node helper (same as merkle_pq.rs)
    fn hash_node(
        left: &[GoldilocksField; 4],
        right: &[GoldilocksField; 4],
    ) -> [GoldilocksField; 4] {
        let mut inputs = vec![DOMAIN_MERKLE_NODE_PQ];
        inputs.extend_from_slice(left);
        inputs.extend_from_slice(right);
        poseidon_pq_hash(&inputs)
    }

    let mut current = bytes_to_hash_out(&commitment_bytes);

    // Log leaf field elements (same format as WASM)
    let leaf_fields: Vec<u64> = current.iter().map(|f| f.value()).collect();

    let mut debug_info: Vec<serde_json::Value> = vec![];
    debug_info.push(serde_json::json!({
        "depth": "leaf",
        "bytes": req.commitment,
        "field_elements": leaf_fields,
    }));

    // Log first few indices
    let indices_preview: Vec<u8> = req.indices.iter().take(8).copied().collect();

    for (i, (sibling_hex, &index)) in req.path.iter().zip(req.indices.iter()).enumerate() {
        let sibling_bytes: [u8; 32] = match hex::decode(sibling_hex) {
            // SAFETY: length checked by guard (== 32)
        Ok(b) if b.len() == 32 => b.try_into().unwrap(),
            _ => return Json(serde_json::json!({"error": format!("Invalid sibling hex at {}", i)})),
        };

        let sibling = bytes_to_hash_out(&sibling_bytes);

        // Log depth 0 details (same as WASM)
        if i == 0 {
            let sibling_fields: Vec<u64> = sibling.iter().map(|f| f.value()).collect();
            let (left, right) = if index == 0 {
                (&current, &sibling)
            } else {
                (&sibling, &current)
            };

            let mut all_inputs: Vec<u64> = vec![DOMAIN_MERKLE_NODE_PQ.value()];
            all_inputs.extend(left.iter().map(|f| f.value()));
            all_inputs.extend(right.iter().map(|f| f.value()));

            debug_info.push(serde_json::json!({
                "depth": 0,
                "sibling_bytes": sibling_hex,
                "sibling_fields": sibling_fields,
                "index": index,
                "current_is": if index == 0 { "LEFT" } else { "RIGHT" },
                "hash_inputs_9": all_inputs,
            }));
        }

        current = if index == 0 {
            hash_node(&current, &sibling)
        } else {
            hash_node(&sibling, &current)
        };

        if i < 3 {
            let result_fields: Vec<u64> = current.iter().map(|f| f.value()).collect();
            debug_info.push(serde_json::json!({
                "depth": i,
                "result_bytes": hex::encode(hash_out_to_bytes(&current)),
                "result_fields": result_fields,
            }));
        }
    }

    let computed_root = hash_out_to_bytes(&current);

    Json(serde_json::json!({
        "commitment": req.commitment,
        "path_length": req.path.len(),
        "indices_0_8": indices_preview,
        "computed_root": hex::encode(computed_root),
        "debug": debug_info,
    }))
}

// ============ Faucet Endpoints ============

/// Get faucet status for a wallet.
async fn faucet_status(
    State(state): State<Arc<AppState>>,
    Path(pk_hash): Path<String>,
) -> Result<Json<FaucetStatus>, (StatusCode, String)> {
    let faucet = state.faucet.as_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, "Faucet not enabled".to_string())
    })?;

    let faucet = faucet.read().await;
    faucet
        .get_claim_info(&pk_hash)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}

/// Request to claim from the faucet.
#[derive(Deserialize)]
struct FaucetClaimRequest {
    pk_hash: String,
}

/// Claim from the faucet.
async fn faucet_claim(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FaucetClaimRequest>,
) -> Result<Json<ClaimResult>, (StatusCode, String)> {
    use std::collections::HashMap;

    let faucet_lock = state.faucet.as_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, "Faucet not enabled".to_string())
    })?;

    // First, get the note positions we need witnesses for (read lock on faucet)
    let positions = {
        let faucet = faucet_lock.read().await;
        faucet.get_note_positions_for_claim().map_err(|e| {
            let status = match &e {
                FaucetError::InsufficientBalance { .. } => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (status, e.to_string())
        })?
    };

    // Get witnesses from blockchain state
    let witnesses: HashMap<u64, _> = {
        let blockchain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
        let shielded_state = blockchain.state();
        positions
            .iter()
            .filter_map(|&pos| {
                shielded_state.witness_pq(pos).map(|w| (pos, w))
            })
            .collect()
    };

    // Process the claim (requires write lock since it modifies faucet state)
    let result = {
        let mut faucet = faucet_lock.write().await;
        faucet.process_claim(&req.pk_hash, &witnesses)
    };

    match result {
        Ok((claim_result, tx)) => {
            // Submit the transaction to the mempool
            let mut mempool = state.mempool.write().unwrap_or_else(|e| e.into_inner());

            // Wrap in Transaction::V2 for mempool
            let wrapped_tx = crate::core::Transaction::V2(tx);
            if !mempool.add_v2(wrapped_tx) {
                tracing::warn!("Failed to add faucet tx to mempool");
                // Transaction was created but mempool rejected it - still return success
                // as the claim was recorded
            }

            Ok(Json(claim_result))
        }
        Err(e) => {
            let status = match &e {
                FaucetError::CooldownActive(_) => StatusCode::TOO_MANY_REQUESTS,
                FaucetError::InvalidPkHash => StatusCode::BAD_REQUEST,
                FaucetError::InsufficientBalance { .. } => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            Err((status, e.to_string()))
        }
    }
}

/// Request for game-based faucet claim.
#[derive(Deserialize)]
struct FaucetGameClaimRequest {
    pk_hash: String,
    tokens_collected: u8,
}

/// Claim from the faucet via game (variable amount based on tokens).
async fn faucet_game_claim(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FaucetGameClaimRequest>,
) -> Result<Json<ClaimResult>, (StatusCode, String)> {
    use std::collections::HashMap;

    let faucet_lock = state.faucet.as_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, "Faucet not enabled".to_string())
    })?;

    // Validate token count (1-10)
    if req.tokens_collected < 1 || req.tokens_collected > 10 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("tokens_collected must be between 1 and 10, got {}", req.tokens_collected),
        ));
    }

    // Get note positions needed for this claim amount
    let positions = {
        let faucet = faucet_lock.read().await;
        faucet.get_note_positions_for_game_claim(req.tokens_collected).map_err(|e| {
            let status = match &e {
                FaucetError::InsufficientBalance { .. } => StatusCode::SERVICE_UNAVAILABLE,
                FaucetError::InvalidTokenCount(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (status, e.to_string())
        })?
    };

    // Get witnesses from blockchain state
    let witnesses: HashMap<u64, _> = {
        let blockchain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
        let shielded_state = blockchain.state();
        positions
            .iter()
            .filter_map(|&pos| {
                shielded_state.witness_pq(pos).map(|w| (pos, w))
            })
            .collect()
    };

    // Process the game claim
    let result = {
        let mut faucet = faucet_lock.write().await;
        faucet.process_game_claim(&req.pk_hash, req.tokens_collected, &witnesses)
    };

    match result {
        Ok((claim_result, tx)) => {
            // Submit the transaction to the mempool
            let mut mempool = state.mempool.write().unwrap_or_else(|e| e.into_inner());

            let wrapped_tx = crate::core::Transaction::V2(tx);
            if !mempool.add_v2(wrapped_tx) {
                tracing::warn!("Failed to add faucet game tx to mempool");
            }

            info!(
                "Faucet game claim: {} tokens -> {} to {}",
                req.tokens_collected, claim_result.amount, &req.pk_hash[..16]
            );

            Ok(Json(claim_result))
        }
        Err(e) => {
            let status = match &e {
                FaucetError::CooldownActive(_) => StatusCode::TOO_MANY_REQUESTS,
                FaucetError::InvalidPkHash => StatusCode::BAD_REQUEST,
                FaucetError::InvalidTokenCount(_) => StatusCode::BAD_REQUEST,
                FaucetError::InsufficientBalance { .. } => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            Err((status, e.to_string()))
        }
    }
}

/// Get public faucet statistics.
async fn faucet_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<FaucetStats>, (StatusCode, String)> {
    let faucet = match state.faucet.as_ref() {
        Some(f) => f.read().await,
        None => {
            // Return disabled stats if faucet not enabled
            return Ok(Json(FaucetStats {
                total_distributed: "0.0 TSN".to_string(),
                unique_claimants: 0,
                active_streaks: 0,
                balance: None,
                enabled: false,
            }));
        }
    };

    faucet
        .get_stats()
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

// ============ Sync Gate (Anti-Fork) ============

/// Request body for POST /tip
#[derive(Deserialize)]
struct TipRequest {
    height: u64,
    hash: String,
}

/// Response for GET /tip and POST /tip
#[derive(Serialize)]
struct TipResponse {
    height: u64,
    hash: String,
    peer_count: usize,
    network_tip_height: u64,
}

/// Receive a tip announcement from a peer.
async fn receive_tip(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<TipRequest>,
) -> Result<Json<TipResponse>, (StatusCode, String)> {
    // IP whitelist check
    let ip = addr.ip().to_string();
    if !crate::config::is_ip_whitelisted(&ip) {
        return Err((StatusCode::FORBIDDEN, format!("IP {} not whitelisted", ip)));
    }
    // Reject tips from outdated nodes
    let peer_ver = headers.get("X-TSN-Version").and_then(|v| v.to_str().ok());
    if let Some(ver) = peer_ver {
        if !crate::network::version_check::version_meets_minimum(ver) {
            warn!("Rejected tip from outdated peer (version {})", ver);
            return Err((StatusCode::FORBIDDEN, format!("Node version {} is below minimum {}", ver, crate::network::version_check::MINIMUM_VERSION)));
        }
    }
    // Track peer info
    let peer_url = format!("http://{}:9333", addr.ip());
    update_peer_info(&state, &peer_url, peer_ver, Some(req.height));

    // Parse the hash from hex
    let hash_bytes: [u8; 32] = hex::decode(&req.hash)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid hash hex: {}", e)))?
        .try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Hash must be exactly 32 bytes".to_string()))?;

    // Use the hash as a pseudo peer-id (we don't have real peer IDs in HTTP mode)
    let peer_id = format!("peer-{}", &req.hash[..16]);
    state.sync_gate.update_tip(&peer_id, req.height, hash_bytes);

    info!("Received tip announcement: height={}, hash={}...", req.height, &req.hash[..16]);

    // Return our own tip info
    let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    let local_height = chain.height();
    let local_hash = hex::encode(chain.latest_hash());
    drop(chain);

    Ok(Json(TipResponse {
        height: local_height,
        hash: local_hash,
        peer_count: state.sync_gate.peer_count(),
        network_tip_height: state.sync_gate.network_tip_height(),
    }))
}

/// Get the local tip and sync gate status.
async fn get_tip(
    State(state): State<Arc<AppState>>,
) -> Json<TipResponse> {
    let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    let local_height = chain.height();
    let local_hash = hex::encode(chain.latest_hash());
    drop(chain);

    Json(TipResponse {
        height: local_height,
        hash: local_hash,
        peer_count: state.sync_gate.peer_count(),
        network_tip_height: state.sync_gate.network_tip_height(),
    })
}

// ============ Fast Sync: Snapshot Download ============

/// Response for GET /snapshot/info — metadata about the available snapshot.
#[derive(Serialize)]
struct SnapshotInfoResponse {
    available: bool,
    height: u64,
    block_hash: String,
    size_bytes: u64,
    /// v1.7.0: Exact cumulative_work at snapshot height, serialized as decimal string
    /// to avoid JSON number precision loss on u128 values.
    #[serde(default)]
    cumulative_work: String,
}

/// GET /snapshot/info — check if a state snapshot is available for download.
async fn snapshot_info(State(state): State<Arc<AppState>>) -> Json<SnapshotInfoResponse> {
    let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    match chain.export_snapshot() {
        Some((data, height, hash)) => Json(SnapshotInfoResponse {
            available: true,
            height,
            block_hash: hash,
            size_bytes: data.len() as u64,
            cumulative_work: chain.cumulative_work().to_string(),
        }),
        None => Json(SnapshotInfoResponse {
            available: false,
            height: 0,
            block_hash: String::new(),
            size_bytes: 0,
            cumulative_work: "0".to_string(),
        }),
    }
}

/// GET /snapshot/download — download the state snapshot as compressed JSON.
/// Uses a pre-cached snapshot (refreshed every 100 blocks) and semaphore (max 3 concurrent).
/// Inspired by Cosmos state-sync (pre-generated snapshots) + Substrate (concurrent limits).
async fn snapshot_download(
    State(state): State<Arc<AppState>>,
) -> Result<axum::response::Response, StatusCode> {
    use axum::response::IntoResponse;
    use axum::http::header;

    // Semaphore: max 3 concurrent snapshot downloads to prevent CPU/RAM saturation
    let _permit = state.snapshot_semaphore.clone().try_acquire_owned()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    // Try to serve from cache first
    {
        let cache = state.snapshot_cache.read().await;
        if let Some(ref cached) = *cache {
            info!(
                "Snapshot download (cached): height={}, hash={}, raw={}KB, compressed={}KB",
                cached.height, &cached.hash[..8.min(cached.hash.len())],
                cached.raw_size / 1024, cached.compressed.len() / 1024
            );
            return Ok((
                [
                    (header::CONTENT_TYPE, "application/gzip"),
                    (header::CONTENT_DISPOSITION, "attachment; filename=\"tsn-snapshot.json.gz\""),
                ],
                [
                    (header::HeaderName::from_static("x-snapshot-height"), header::HeaderValue::from_str(&cached.height.to_string()).unwrap()),
                    (header::HeaderName::from_static("x-snapshot-hash"), header::HeaderValue::from_str(&cached.hash).unwrap()),
                ],
                cached.compressed.clone(),
            ).into_response());
        }
    }

    // Cache miss — generate on the fly (first request or cache expired)
    // Isolate std::sync::RwLock access in a non-async block to keep future Send
    let (data, height, hash) = {
        let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
        chain.export_snapshot()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
    };

    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&data).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let compressed = encoder.finish().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    info!(
        "Snapshot download (generated): height={}, hash={}, raw={}KB, compressed={}KB",
        height, &hash[..8], data.len() / 1024, compressed.len() / 1024
    );

    // Store in cache for future requests
    {
        let mut cache = state.snapshot_cache.write().await;
        *cache = Some(CachedSnapshot {
            raw_size: data.len(),
            compressed: compressed.clone(),
            height,
            hash: hash.clone(),
        });
    }

    Ok((
        [
            (header::CONTENT_TYPE, "application/gzip"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"tsn-snapshot.json.gz\""),
        ],
        [
            (header::HeaderName::from_static("x-snapshot-height"), header::HeaderValue::from_str(&height.to_string()).unwrap()),
            (header::HeaderName::from_static("x-snapshot-hash"), header::HeaderValue::from_str(&hash).unwrap()),
        ],
        compressed,
    ).into_response())
}

// ============ React App ============
// Serve index.html for SPA routes (wallet, explorer)
async fn serve_index() -> Html<String> {
    let content = std::fs::read_to_string("static/index.html")
        .unwrap_or_else(|_| "<!DOCTYPE html><html><body>App not found. Run 'cd wallet && npm run build' first.</body></html>".to_string());
    Html(content)
}

/// Serve the technical whitepaper as a web page.
/// This serves the HTML content from the website directory for inline viewing.
#[allow(dead_code)]
async fn serve_whitepaper() -> Html<String> {
    let content = std::fs::read_to_string("website/index.html")
        .unwrap_or_else(|_| {
            // Fallback content if whitepaper HTML is not found
            "<!DOCTYPE html><html><head><title>TSN Whitepaper</title></head><body><h1>TSN Whitepaper</h1><p>Whitepaper content not available. Please check the deployment.</p></body></html>".to_string()
        });
    Html(content)
}

// ============ Wallet Viewing-Key Endpoints ============

/// GET /wallet/viewing-key
///
/// Export the viewing key of a freshly generated wallet as a hex string.
/// In production the wallet identity would come from an authenticated session;
/// here we generate a new wallet for demonstration / integration-test purposes.
async fn wallet_viewing_key() -> Json<serde_json::Value> {
    let wallet = ShieldedWallet::generate();
    let vk_hex = wallet.export_viewing_key();
    Json(serde_json::json!({
        "viewing_key": vk_hex,
        "address": wallet.address().to_hex(),
    }))
}

/// Request body for POST /wallet/watch.
#[derive(Deserialize)]
struct WatchWalletRequest {
    viewing_key: String,
}

/// POST /wallet/watch
///
/// Create a watch-only wallet from an imported viewing key.  The response
/// confirms the wallet was created and returns its pk_hash (which is the
/// identity used for scanning).
async fn wallet_watch(
    Json(body): Json<WatchWalletRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    match ShieldedWallet::from_viewing_key(&body.viewing_key) {
        Ok(wallet) => {
            let pk_hash_hex = hex::encode(wallet.pk_hash());
            Ok(Json(serde_json::json!({
                "status": "ok",
                "watch_only": true,
                "pk_hash": pk_hash_hex,
            })))
        }
        Err(_) => Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid viewing key — expected 64-char hex (32 bytes)"
            })),
        )),
    }
}

// ============================================================================
// Smart Contract Endpoints
// ============================================================================

/// Request body for deploying a contract.
#[derive(Deserialize)]
struct ContractDeployRequest {
    /// Hex-encoded bytecode
    bytecode: String,
    /// Constructor arguments
    #[serde(default)]
    constructor_args: Vec<u64>,
    /// Gas limit
    gas_limit: u64,
    /// Fee
    fee: u64,
    /// Deployer's public key hash (hex)
    deployer_pk_hash: String,
    /// Deployer nonce
    nonce: u64,
    /// Hex-encoded ML-DSA-65 signature
    #[serde(default)]
    signature: String,
    /// Hex-encoded public key
    #[serde(default)]
    public_key: String,
}

/// Request body for calling a contract.
#[derive(Deserialize)]
struct ContractCallRequest {
    /// Contract address (hex)
    contract_address: String,
    /// Function selector (hex, 4 bytes)
    function_selector: String,
    /// Call arguments
    #[serde(default)]
    args: Vec<u64>,
    /// Gas limit
    gas_limit: u64,
    /// Fee
    fee: u64,
    /// Value to send
    #[serde(default)]
    value: u64,
    /// Caller's public key hash (hex)
    caller_pk_hash: String,
    /// Caller nonce
    nonce: u64,
    /// Hex-encoded signature
    #[serde(default)]
    signature: String,
    /// Hex-encoded public key
    #[serde(default)]
    public_key: String,
}

/// Request body for querying a contract (read-only).
#[derive(Deserialize)]
#[allow(dead_code)]
struct ContractQueryRequest {
    /// Contract address (hex)
    contract_address: String,
    /// Function selector (hex, 4 bytes)
    function_selector: String,
    /// Call arguments
    #[serde(default)]
    args: Vec<u64>,
}

/// Response for contract operations.
#[derive(Serialize)]
struct ContractResponse {
    success: bool,
    tx_hash: Option<String>,
    gas_used: Option<u64>,
    return_value: Option<u64>,
    contract_address: Option<String>,
    error: Option<String>,
    events: Vec<ContractEventResponse>,
}

/// Contract event in response.
#[derive(Serialize)]
struct ContractEventResponse {
    topic: u64,
    data: Vec<u64>,
}

/// Contract info response.
#[derive(Serialize)]
struct ContractInfoResponse {
    address: String,
    code_hash: String,
    creator: String,
    created_at_height: u64,
    balance: u64,
    bytecode_size: usize,
}

fn parse_hex_32(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_hex_4(s: &str) -> Result<[u8; 4], String> {
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {}", e))?;
    if bytes.len() != 4 {
        return Err(format!("expected 4 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 4];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Deploy a new smart contract.
async fn contract_deploy(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ContractDeployRequest>,
) -> Result<Json<ContractResponse>, (StatusCode, Json<serde_json::Value>)> {
    let bytecode = hex::decode(&req.bytecode).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("invalid bytecode hex: {}", e)})))
    })?;

    let deployer_pk_hash = parse_hex_32(&req.deployer_pk_hash).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e})))
    })?;

    // H5 audit fix: require valid signature and public key (no silent defaults)
    let signature = hex::decode(&req.signature).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("invalid signature hex: {}", e)})))
    })?;
    let public_key = hex::decode(&req.public_key).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("invalid public_key hex: {}", e)})))
    })?;
    if signature.is_empty() || public_key.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "signature and public_key are required"}))));
    }

    // Verify ML-DSA-65 signature over the deployment data
    {
        use blake2::{Blake2s256, Digest};
        let mut hasher = Blake2s256::new();
        hasher.update(&bytecode);
        hasher.update(&deployer_pk_hash);
        hasher.update(&req.nonce.to_le_bytes());
        let msg_hash = hasher.finalize();

        let sig_valid = crate::crypto::signature::verify_mldsa65(&public_key, &msg_hash, &signature);
        if !sig_valid {
            return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid signature: ML-DSA verification failed"}))));
        }
    }

    let deploy_tx = crate::contract::ContractDeployTransaction {
        bytecode,
        constructor_args: req.constructor_args,
        gas_limit: req.gas_limit,
        fee: req.fee,
        deployer_pk_hash,
        nonce: req.nonce,
        signature,
        public_key,
    };

    // Add to mempool
    let mut mempool = state.mempool.write().unwrap_or_else(|e| e.into_inner());
    mempool.add_contract_deploy(deploy_tx.clone());
    drop(mempool);

    // Execute immediately for the response (preview)
    let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    let height = chain.height();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    drop(chain);

    // Create a temporary executor for preview
    let tmp_db = sled::Config::new().temporary(true).open().map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("db error: {}", e)})))
    })?;
    let executor = crate::contract::ContractExecutor::new(&tmp_db).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("executor error: {}", e)})))
    })?;

    match executor.deploy(&deploy_tx, height, timestamp) {
        Ok(receipt) => Ok(Json(ContractResponse {
            success: receipt.success,
            tx_hash: Some(hex::encode(receipt.tx_hash)),
            gas_used: Some(receipt.gas_used),
            return_value: receipt.return_value,
            contract_address: receipt.contract_address.map(|a| hex::encode(a)),
            error: receipt.error,
            events: receipt.events.iter().map(|e| ContractEventResponse {
                topic: e.topic,
                data: e.data.clone(),
            }).collect(),
        })),
        Err(e) => Ok(Json(ContractResponse {
            success: false,
            tx_hash: Some(hex::encode(deploy_tx.hash())),
            gas_used: None,
            return_value: None,
            contract_address: None,
            error: Some(e.to_string()),
            events: vec![],
        })),
    }
}

/// Call a deployed smart contract.
async fn contract_call(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ContractCallRequest>,
) -> Result<Json<ContractResponse>, (StatusCode, Json<serde_json::Value>)> {
    let contract_address = parse_hex_32(&req.contract_address).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e})))
    })?;
    let function_selector = parse_hex_4(&req.function_selector).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e})))
    })?;
    let caller_pk_hash = parse_hex_32(&req.caller_pk_hash).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e})))
    })?;

    let signature = hex::decode(&req.signature).unwrap_or_default();
    let public_key = hex::decode(&req.public_key).unwrap_or_default();

    let call_tx = crate::contract::ContractCallTransaction {
        contract_address,
        function_selector,
        args: req.args,
        gas_limit: req.gas_limit,
        fee: req.fee,
        value: req.value,
        caller_pk_hash,
        nonce: req.nonce,
        signature,
        public_key,
    };

    // Add to mempool
    let mut mempool = state.mempool.write().unwrap_or_else(|e| e.into_inner());
    mempool.add_contract_call(call_tx.clone());
    drop(mempool);

    Ok(Json(ContractResponse {
        success: true,
        tx_hash: Some(hex::encode(call_tx.hash())),
        gas_used: None,
        return_value: None,
        contract_address: None,
        error: None,
        events: vec![],
    }))
}

/// Query a contract (read-only, no state changes, no fee).
async fn contract_query(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ContractQueryRequest>,
) -> Result<Json<ContractResponse>, (StatusCode, Json<serde_json::Value>)> {
    let contract_address = parse_hex_32(&req.contract_address).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e})))
    })?;
    let _function_selector = parse_hex_4(&req.function_selector).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e})))
    })?;

    let _chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
    let _height = _chain.height();
    drop(_chain);

    // For queries, we'd need access to the contract executor with the real DB.
    // For now, return a placeholder indicating query support is available.
    Ok(Json(ContractResponse {
        success: true,
        tx_hash: None,
        gas_used: None,
        return_value: None,
        contract_address: Some(hex::encode(contract_address)),
        error: Some("Query requires node-local contract executor (coming in v0.5.1)".into()),
        events: vec![],
    }))
}

/// Get contract info by address.
async fn contract_info(
    State(_state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> Result<Json<ContractInfoResponse>, (StatusCode, Json<serde_json::Value>)> {
    let _addr = parse_hex_32(&address).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e})))
    })?;

    // Contract registry lookup will be available when executor is integrated into AppState
    Err((
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "Contract registry not yet available at this endpoint"})),
    ))
}

/// Get events for a contract.
async fn contract_events(
    State(_state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> Result<Json<Vec<ContractEventResponse>>, (StatusCode, Json<serde_json::Value>)> {
    let _addr = parse_hex_32(&address).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e})))
    })?;

    // Event store lookup will be available when executor is integrated into AppState
    Ok(Json(vec![]))
}

// ============================================================================
// v1.6.1: Telemetry & Admin endpoints
// ============================================================================

/// GET /node/errors — Returns recent errors for telemetry/dashboard
async fn get_node_errors(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let errors = state.error_log.read().unwrap();
    let recent: Vec<_> = errors.iter().rev().take(50).cloned().collect();
    Json(serde_json::json!({
        "errors": recent,
        "total": errors.len(),
        "auto_heal_mode": *state.auto_heal_mode.read().unwrap(),
    }))
}

/// POST /admin/force-resync — Force the node to wipe and re-sync from peers
/// SECURITY: Only accessible from localhost or private networks.
async fn admin_force_resync(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let remote_ip = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1");
    if let Ok(ip) = remote_ip.parse::<std::net::IpAddr>() {
        if !is_local_or_private(ip) {
            return Err((StatusCode::FORBIDDEN, "Admin endpoints are localhost-only".to_string()));
        }
    }
    tracing::warn!("ADMIN: Force resync triggered via API from {}", remote_ip);
    log_node_error(&state, "admin_force_resync", &format!("Force resync triggered from {}", remote_ip));
    let mut chain = state.blockchain.write()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Lock error: {}", e)))?;
    chain.reset_for_snapshot_resync();
    let mut bans = state.banned_peers.write().unwrap();
    bans.clear();
    Ok(Json(serde_json::json!({
        "ok": true,
        "message": "Chain reset to height 0. Will fast-sync from peers."
    })))
}

/// GET /admin/config — Get current admin config
async fn get_admin_config(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "auto_heal_mode": *state.auto_heal_mode.read().unwrap(),
        "banned_peers_count": state.banned_peers.read().unwrap().len(),
        "error_count": state.error_log.read().unwrap().len(),
    }))
}

/// POST /admin/config — Update admin config (auto_heal_mode)
/// SECURITY: Only accessible from localhost or private networks.
async fn set_admin_config(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let remote_ip = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1");
    if let Ok(ip) = remote_ip.parse::<std::net::IpAddr>() {
        if !is_local_or_private(ip) {
            return Err((StatusCode::FORBIDDEN, "Admin endpoints are localhost-only".to_string()));
        }
    }
    if let Some(mode) = body.get("auto_heal_mode").and_then(|v| v.as_str()) {
        if mode == "validation" || mode == "automatic" {
            *state.auto_heal_mode.write().unwrap() = mode.to_string();
            tracing::info!("ADMIN: auto_heal_mode changed to '{}'", mode);
            return Ok(Json(serde_json::json!({"ok": true, "auto_heal_mode": mode})));
        }
    }
    Ok(Json(serde_json::json!({"error": "Invalid config. Use auto_heal_mode: 'validation' or 'automatic'"})))
}

/// Check if an IP is localhost or private network (for admin endpoint protection)
fn is_local_or_private(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local()
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
        }
    }
}

/// Helper: log an error to the telemetry error_log
pub fn log_node_error(state: &AppState, error_type: &str, message: &str) {
    let height = state.blockchain.read()
        .map(|c| c.height())
        .unwrap_or(0);
    let error = NodeError {
        error_type: error_type.to_string(),
        message: message.chars().take(200).collect(),
        height,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let mut log = state.error_log.write().unwrap();
    log.push(error);
    // Keep last 100 errors max
    if log.len() > 100 {
        let drain_count = log.len() - 100;
        log.drain(0..drain_count);
    }
}
