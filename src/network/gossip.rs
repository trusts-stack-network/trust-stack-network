//! Gossip protocol for block and transaction propagation.
//! Epidemic broadcast with push/pull, rate limiting and peer scoring.

use crate::core::{ShieldedBlock, ShieldedTransaction};
use crate::network::{NetworkError, PeerId, NetworkMessage};
use bytes::Bytes;
use std::collections::{HashMap, HashSet, VecDeque};

type Hash = [u8; 32];
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio::time::interval;
use tracing::{debug, warn, info};

/// Max number of peers we gossip to for a single item.
const FANOUT: usize = 6;
/// Max age of an inventory item we keep track of.
const INVENTORY_TIMEOUT: Duration = Duration::from_secs(300);
/// How often to clean up internal caches.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
/// Max messages per second from a single peer.
const RATE_LIMIT_PER_SEC: u32 = 20;
/// Penalty for sending invalid data.
const INVALID_DATA_PENALTY: f64 = 10.0;
/// Reward for relaying valid data.
const VALID_RELAY_REWARD: f64 = 1.0;
/// Max items in a single GetData request.
const MAX_GETDATA_ITEMS: usize = 128;

#[derive(Debug, Clone)]
pub struct GossipConfig {
    pub fanout: usize,
    pub rate_limit_per_sec: u32,
    pub inventory_timeout: Duration,
    pub cleanup_interval: Duration,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            fanout: FANOUT,
            rate_limit_per_sec: RATE_LIMIT_PER_SEC,
            inventory_timeout: INVENTORY_TIMEOUT,
            cleanup_interval: CLEANUP_INTERVAL,
        }
    }
}

pub(crate) struct PeerState {
    /// Rate limiter: tokens available.
    tokens: f64,
    /// Last refill instant.
    last_refill: Instant,
    /// Score: higher is better.
    score: f64,
    /// Known inventory hashes.
    known: HashSet<Hash>,
}

impl PeerState {
    fn new() -> Self {
        Self {
            tokens: RATE_LIMIT_PER_SEC as f64,
            last_refill: Instant::now(),
            score: 0.0,
            known: HashSet::new(),
        }
    }

    /// Try to consume one token. Returns false if rate limited.
    fn try_consume(&mut self, config: &GossipConfig) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * config.rate_limit_per_sec as f64)
            .min(config.rate_limit_per_sec as f64);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn penalize(&mut self, amount: f64) {
        self.score -= amount;
    }

    fn reward(&mut self, amount: f64) {
        self.score += amount;
    }
}

/// Internal message for the gossip worker.
#[derive(Debug)]
enum GossipEvent {
    /// New block to gossip.
    Block(Arc<ShieldedBlock>),
    /// New transaction to gossip.
    Transaction(Arc<ShieldedTransaction>),
    /// Incoming network message.
    Network(PeerId, Bytes),
    /// Peer connected.
    PeerConnected(PeerId),
    /// Peer disconnected.
    PeerDisconnected(PeerId),
}

/// Outbound message to be sent by the transport layer.
#[derive(Debug, Clone)]
pub struct OutboundMessage {
    /// Target peer.
    pub peer: PeerId,
    /// Serialized network message.
    pub data: Bytes,
}

/// Gossip engine handles propagation of blocks and transactions.
pub struct GossipEngine {
    _config: GossipConfig,
    /// Connected peers.
    _peers: Arc<RwLock<HashMap<PeerId, PeerState>>>,
    /// Queue of items to advertise (inv messages).
    _inv_queue: Arc<RwLock<VecDeque<Hash>>>,
    /// Items we have already seen and relayed.
    _seen: Arc<RwLock<HashMap<Hash, Instant>>>,
    /// Sender to worker task.
    tx: mpsc::UnboundedSender<GossipEvent>,
    /// Receiver for outbound messages (consumed by transport layer).
    outbound_rx: Arc<RwLock<mpsc::UnboundedReceiver<OutboundMessage>>>,
}

impl GossipEngine {
    pub fn new(config: GossipConfig) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let inv_queue = Arc::new(RwLock::new(VecDeque::new()));
        let seen = Arc::new(RwLock::new(HashMap::new()));
        let data_store: Arc<RwLock<HashMap<Hash, StoredItem>>> =
            Arc::new(RwLock::new(HashMap::new()));

        let worker_config = config.clone();
        let engine = Self {
            _config: config,
            _peers: peers.clone(),
            _inv_queue: inv_queue.clone(),
            _seen: seen.clone(),
            tx,
            outbound_rx: Arc::new(RwLock::new(outbound_rx)),
        };

        tokio::spawn(run_worker(
            rx,
            peers,
            inv_queue,
            seen,
            data_store,
            outbound_tx,
            worker_config,
        ));

        engine
    }

    /// Announce a new block to the network.
    pub fn announce_block(&self, block: Arc<ShieldedBlock>) -> Result<(), NetworkError> {
        self.tx
            .send(GossipEvent::Block(block))
            .map_err(|_| NetworkError::Shutdown)
    }

    /// Announce a new transaction to the network.
    pub fn announce_transaction(&self, tx: Arc<ShieldedTransaction>) -> Result<(), NetworkError> {
        self.tx
            .send(GossipEvent::Transaction(tx))
            .map_err(|_| NetworkError::Shutdown)
    }

    /// Handle incoming network message from a peer.
    pub async fn on_message(&self, peer: PeerId, data: Bytes) -> Result<(), NetworkError> {
        self.tx
            .send(GossipEvent::Network(peer, data))
            .map_err(|_| NetworkError::Shutdown)
    }

    /// Notify that a peer connected.
    pub async fn on_peer_connected(&self, peer: PeerId) -> Result<(), NetworkError> {
        self.tx
            .send(GossipEvent::PeerConnected(peer))
            .map_err(|_| NetworkError::Shutdown)
    }

    /// Notify that a peer disconnected.
    pub async fn on_peer_disconnected(&self, peer: PeerId) -> Result<(), NetworkError> {
        self.tx
            .send(GossipEvent::PeerDisconnected(peer))
            .map_err(|_| NetworkError::Shutdown)
    }

    /// Receive the next outbound message to send to a peer.
    /// The transport layer should call this in a loop to drain outbound messages.
    pub async fn recv_outbound(&self) -> Option<OutboundMessage> {
        self.outbound_rx.write().await.recv().await
    }
}

/// Stored data item (block or transaction) by hash for serving GetData requests.
#[derive(Clone)]
enum StoredItem {
    Block(Vec<u8>),
    Transaction(Vec<u8>),
}

/// Background worker processing gossip events.
async fn run_worker(
    mut rx: mpsc::UnboundedReceiver<GossipEvent>,
    peers: Arc<RwLock<HashMap<PeerId, PeerState>>>,
    _inv_queue: Arc<RwLock<VecDeque<Hash>>>,
    seen: Arc<RwLock<HashMap<Hash, Instant>>>,
    data_store: Arc<RwLock<HashMap<Hash, StoredItem>>>,
    outbound_tx: mpsc::UnboundedSender<OutboundMessage>,
    config: GossipConfig,
) {
    let mut cleanup_tick = interval(config.cleanup_interval);

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                match event {
                    GossipEvent::Block(block) => {
                        handle_block(block, &peers, &seen, &data_store, &outbound_tx, &config).await;
                    }
                    GossipEvent::Transaction(tx) => {
                        handle_transaction(tx, &peers, &seen, &data_store, &outbound_tx, &config).await;
                    }
                    GossipEvent::Network(peer, data) => {
                        handle_network_message(peer, data, &peers, &seen, &data_store, &outbound_tx, &config).await;
                    }
                    GossipEvent::PeerConnected(peer) => {
                        handle_peer_connected(peer, &peers).await;
                    }
                    GossipEvent::PeerDisconnected(peer) => {
                        handle_peer_disconnected(peer, &peers).await;
                    }
                }
            }
            _ = cleanup_tick.tick() => {
                cleanup(&seen, &data_store, &peers, &config).await;
            }
            else => break,
        }
    }
    info!("Gossip worker shutdown");
}

async fn handle_block(
    block: Arc<ShieldedBlock>,
    peers: &Arc<RwLock<HashMap<PeerId, PeerState>>>,
    seen: &Arc<RwLock<HashMap<Hash, Instant>>>,
    data_store: &Arc<RwLock<HashMap<Hash, StoredItem>>>,
    outbound_tx: &mpsc::UnboundedSender<OutboundMessage>,
    config: &GossipConfig,
) {
    let hash = block.header.hash();
    {
        let mut s = seen.write().await;
        if s.contains_key(&hash) {
            return;
        }
        s.insert(hash, Instant::now());
    }

    // Store the serialized block for serving future GetData requests.
    if let Ok(serialized) = bincode::serialize(block.as_ref()) {
        data_store.write().await.insert(hash, StoredItem::Block(serialized));
    }

    debug!("Announcing block {}", hex::encode(hash));
    broadcast_inv(hash, peers, outbound_tx, config).await;
}

async fn handle_transaction(
    tx: Arc<ShieldedTransaction>,
    peers: &Arc<RwLock<HashMap<PeerId, PeerState>>>,
    seen: &Arc<RwLock<HashMap<Hash, Instant>>>,
    data_store: &Arc<RwLock<HashMap<Hash, StoredItem>>>,
    outbound_tx: &mpsc::UnboundedSender<OutboundMessage>,
    config: &GossipConfig,
) {
    let hash = tx.hash();
    {
        let mut s = seen.write().await;
        if s.contains_key(&hash) {
            return;
        }
        s.insert(hash, Instant::now());
    }

    // Store the serialized transaction for serving future GetData requests.
    if let Ok(serialized) = bincode::serialize(tx.as_ref()) {
        data_store.write().await.insert(hash, StoredItem::Transaction(serialized));
    }

    debug!("Announcing tx {}", hex::encode(hash));
    broadcast_inv(hash, peers, outbound_tx, config).await;
}

async fn handle_network_message(
    peer: PeerId,
    data: Bytes,
    peers: &Arc<RwLock<HashMap<PeerId, PeerState>>>,
    seen: &Arc<RwLock<HashMap<Hash, Instant>>>,
    data_store: &Arc<RwLock<HashMap<Hash, StoredItem>>>,
    outbound_tx: &mpsc::UnboundedSender<OutboundMessage>,
    config: &GossipConfig,
) {
    let msg: NetworkMessage = match bincode::deserialize(&data) {
        Ok(m) => m,
        Err(e) => {
            warn!("Invalid message from {}: {}", peer, e);
            penalize_peer(peer, INVALID_DATA_PENALTY, peers).await;
            return;
        }
    };

    let mut peers_guard = peers.write().await;
    let state = match peers_guard.get_mut(&peer) {
        Some(s) => s,
        None => {
            warn!("Message from unknown peer {}", peer);
            return;
        }
    };

    if !state.try_consume(config) {
        warn!("Rate limiting peer {}", peer);
        return;
    }

    match msg {
        NetworkMessage::Inv(hashes) => {
            // Collect unknown hashes that we need to request.
            let seen_guard = seen.read().await;
            let mut unknown: Vec<Hash> = Vec::new();
            for hash in &hashes {
                state.known.insert(*hash);
                if !seen_guard.contains_key(hash) {
                    unknown.push(*hash);
                }
            }
            drop(seen_guard);

            // Request unknown data via GetData (capped to avoid oversized messages).
            if !unknown.is_empty() {
                let to_request: Vec<Hash> = unknown.into_iter()
                    .take(MAX_GETDATA_ITEMS)
                    .collect();
                debug!(
                    "Requesting {} items from peer {}",
                    to_request.len(),
                    peer
                );
                let getdata_msg = NetworkMessage::GetData(to_request);
                if let Ok(serialized) = bincode::serialize(&getdata_msg) {
                    let _ = outbound_tx.send(OutboundMessage {
                        peer,
                        data: Bytes::from(serialized),
                    });
                }
            }

            reward_peer(peer, VALID_RELAY_REWARD, &mut peers_guard).await;
        }
        NetworkMessage::GetData(requested_hashes) => {
            // Serve requested data from our local store.
            let store = data_store.read().await;
            for hash in &requested_hashes {
                if let Some(item) = store.get(hash) {
                    let payload = match item {
                        StoredItem::Block(data) => data.clone(),
                        StoredItem::Transaction(data) => data.clone(),
                    };
                    let response = NetworkMessage::Payload(payload);
                    if let Ok(serialized) = bincode::serialize(&response) {
                        let _ = outbound_tx.send(OutboundMessage {
                            peer,
                            data: Bytes::from(serialized),
                        });
                    }
                } else {
                    debug!(
                        "Data not found for hash {} requested by peer {}",
                        hex::encode(hash),
                        peer
                    );
                }
            }
            reward_peer(peer, VALID_RELAY_REWARD, &mut peers_guard).await;
        }
        _ => {}
    }
}

async fn handle_peer_connected(peer: PeerId, peers: &Arc<RwLock<HashMap<PeerId, PeerState>>>) {
    peers.write().await.insert(peer, PeerState::new());
    info!("Peer {} connected to gossip", peer);
}

async fn handle_peer_disconnected(peer: PeerId, peers: &Arc<RwLock<HashMap<PeerId, PeerState>>>) {
    peers.write().await.remove(&peer);
    info!("Peer {} disconnected from gossip", peer);
}

/// Broadcast inventory announcement to a random fanout subset of peers.
async fn broadcast_inv(
    hash: Hash,
    peers: &Arc<RwLock<HashMap<PeerId, PeerState>>>,
    outbound_tx: &mpsc::UnboundedSender<OutboundMessage>,
    config: &GossipConfig,
) {
    let mut peers_guard = peers.write().await;

    // Filter out peers that already know this hash.
    let mut candidates: Vec<PeerId> = peers_guard
        .iter()
        .filter(|(_, state)| !state.known.contains(&hash))
        .map(|(id, _)| *id)
        .collect();

    if candidates.is_empty() {
        return;
    }

    use rand::seq::SliceRandom;
    candidates.shuffle(&mut rand::thread_rng());
    let count = candidates.len().min(config.fanout);

    let inv_msg = NetworkMessage::Inv(vec![hash]);
    let serialized = match bincode::serialize(&inv_msg) {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to serialize Inv message: {}", e);
            return;
        }
    };

    for peer_id in candidates.into_iter().take(count) {
        // Mark hash as known for this peer to avoid re-sending.
        if let Some(state) = peers_guard.get_mut(&peer_id) {
            state.known.insert(hash);
        }

        let _ = outbound_tx.send(OutboundMessage {
            peer: peer_id,
            data: Bytes::from(serialized.clone()),
        });
        debug!("Sent inv {} to {}", hex::encode(hash), peer_id);
    }
}

/// Penalize a peer for bad behavior.
async fn penalize_peer(
    peer: PeerId,
    amount: f64,
    peers: &Arc<RwLock<HashMap<PeerId, PeerState>>>,
) {
    let mut peers_guard = peers.write().await;
    if let Some(state) = peers_guard.get_mut(&peer) {
        state.penalize(amount);
        debug!("Penalized peer {} by {}, new score: {}", peer, amount, state.score);

        // Ban peer if score drops too low
        if state.score < -50.0 {
            warn!("Banning peer {} due to low score: {}", peer, state.score);
            peers_guard.remove(&peer);
        }
    }
}

/// Reward a peer for good behavior.
async fn reward_peer(
    peer: PeerId,
    amount: f64,
    peers_guard: &mut tokio::sync::RwLockWriteGuard<'_, HashMap<PeerId, PeerState>>,
) {
    if let Some(state) = peers_guard.get_mut(&peer) {
        state.reward(amount);
        debug!("Rewarded peer {} by {}, new score: {}", peer, amount, state.score);
    }
}

/// Cleanup old entries from the seen cache and data store.
async fn cleanup(
    seen: &Arc<RwLock<HashMap<Hash, Instant>>>,
    data_store: &Arc<RwLock<HashMap<Hash, StoredItem>>>,
    peers: &Arc<RwLock<HashMap<PeerId, PeerState>>>,
    config: &GossipConfig,
) {
    let now = Instant::now();

    // Purge expired seen entries.
    let mut seen_guard = seen.write().await;
    let before = seen_guard.len();
    seen_guard.retain(|_, timestamp| {
        now.duration_since(*timestamp) < config.inventory_timeout
    });
    let after = seen_guard.len();

    if before != after {
        debug!("Cleaned up {} old inventory entries", before - after);
    }

    // Collect surviving hashes so we can prune the data store in sync.
    let surviving: HashSet<Hash> = seen_guard.keys().copied().collect();
    drop(seen_guard);

    // Remove data items whose hashes have expired from seen.
    let mut store = data_store.write().await;
    let store_before = store.len();
    store.retain(|hash, _| surviving.contains(hash));
    let store_after = store.len();
    if store_before != store_after {
        debug!("Cleaned up {} expired data items", store_before - store_after);
    }
    drop(store);

    // Cleanup peer known sets to avoid unbounded growth.
    let mut peers_guard = peers.write().await;
    for (_, state) in peers_guard.iter_mut() {
        state.known.retain(|h| surviving.contains(h));
    }
    let peer_count = peers_guard.len();
    drop(peers_guard);

    if peer_count > 0 {
        debug!("Active peers: {}", peer_count);
    }
}

/// Check if a hash has been seen recently.
pub async fn has_seen(seen: &Arc<RwLock<HashMap<Hash, Instant>>>, hash: &Hash) -> bool {
    seen.read().await.contains_key(hash)
}

/// Get the number of connected peers.
#[allow(dead_code)]
pub(crate) async fn peer_count(peers: &Arc<RwLock<HashMap<PeerId, PeerState>>>) -> usize {
    peers.read().await.len()
}

/// Get peer scores for monitoring.
#[allow(dead_code)]
pub(crate) async fn get_peer_scores(
    peers: &Arc<RwLock<HashMap<PeerId, PeerState>>>,
) -> HashMap<PeerId, f64> {
    let peers_guard = peers.read().await;
    peers_guard
        .iter()
        .map(|(id, state)| (*id, state.score))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_gossip_config_default() {
        let config = GossipConfig::default();
        assert_eq!(config.fanout, FANOUT);
        assert_eq!(config.rate_limit_per_sec, RATE_LIMIT_PER_SEC);
    }

    #[tokio::test]
    async fn test_peer_state_rate_limiting() {
        let mut state = PeerState::new();
        let config = GossipConfig::default();

        // Should allow initial burst
        for _ in 0..RATE_LIMIT_PER_SEC {
            assert!(state.try_consume(&config));
        }

        // Should rate limit after burst
        assert!(!state.try_consume(&config));
    }

    #[tokio::test]
    async fn test_peer_scoring() {
        let mut state = PeerState::new();
        assert_eq!(state.score, 0.0);

        state.reward(5.0);
        assert_eq!(state.score, 5.0);

        state.penalize(3.0);
        assert_eq!(state.score, 2.0);
    }
}
