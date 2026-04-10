//! TSN P2P Network Module
//!
//! Handles peer discovery, block sync, mempool, and JSON-RPC API.

pub mod alerts;
pub mod anti_dos;
pub mod api;
pub mod p2p;
pub mod discovery;
pub mod eclipse_protection;
pub mod gossip;
pub mod mempool;
pub mod message_limits;
pub mod metrics;
pub mod monitoring_config;
pub mod peer;
pub mod protocol;
pub mod rate_limiter;
pub mod scoring;
pub mod sync;
pub mod sync_gate;
pub mod transport;
pub mod auto_update;
pub mod version_check;

pub use api::{AppState, CachedSnapshot, MinerStats, NodeError, create_router, log_node_error};
pub use sync_gate::SyncGate;
pub use mempool::Mempool;
pub use discovery::discovery_loop;
pub use sync::{sync_from_peer, sync_loop, broadcast_block};
pub use protocol::{TsnMessage, HandshakeData, ProtocolVersion};
pub use peer::{PeerHandle, PeerManager};
pub use rate_limiter::{RateLimiter, RateLimitConfig};
pub use scoring::{PeerScoring, ScoringConfig, PeerScore};
pub use metrics::{NetworkMetrics, MetricsCollector};
pub use monitoring_config::{MonitoringConfig, DashboardConfig, MetricsConfig, AlertConfig};
pub use anti_dos::{AntiDoSProtection, AntiDoSConfig};
pub use transport::{NetworkTransport, TransportConfig};
pub use eclipse_protection::{EclipseProtection, EclipseProtectionConfig, EclipseProtectionStats, NetworkAnomaly, AnomalyType};
pub use message_limits::{
    MessageLimitsConfig, MessageSizeTracker, SizeValidationResult,
    validate_message_size, check_tsn_message_size, validate_framed_message_size,
    check_buffer_size, GLOBAL_MAX_MESSAGE_SIZE, HANDSHAKE_MAX_SIZE,
    HEARTBEAT_MAX_SIZE, PEER_EXCHANGE_MAX_SIZE, DATA_MAX_SIZE,
    DISCONNECT_MAX_SIZE, MAX_READ_BUFFER_SIZE, FRAMING_HEADER_SIZE,
    MESSAGE_READ_TIMEOUT, MAX_MESSAGES_PER_SECOND,
};

use std::net::SocketAddr;
use thiserror::Error;
use tokio::time::Duration;

/// Masque une URL de peer en identifiant court pour les logs.
///
/// - Seeds connus (seed1-4.tsnchain.com) → "seed1", "seed2", etc.
/// - Autres URLs → "peer:" + 8 premiers hex d'un hash SHA-256
///
/// L'URL originale reste utilisée en interne ; seul l'affichage change.
///
/// Returns true if this peer string is a contactable HTTP URL (not a hashed peer ID).
/// Hashed peer IDs like "peer:a1b2c3d4" are display-only and must never be used for HTTP requests.
pub fn is_contactable_peer(peer: &str) -> bool {
    peer.starts_with("http://") || peer.starts_with("https://")
}

pub fn peer_id(url: &str) -> String {
    // Détection des seeds connus
    for i in 1..=4 {
        let seed_domain = format!("seed{}.tsnchain.com", i);
        if url.contains(&seed_domain) {
            return format!("seed{}", i);
        }
    }

    // Hash SHA-256 de l'URL → 8 premiers caractères hex
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(url.as_bytes());
    let result = hasher.finalize();
    format!("peer:{}", hex::encode(&result[..4]))
}

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Handshake timeout")]
    HandshakeTimeout,

    #[error("Peer disconnected: {0}")]
    PeerDisconnected(SocketAddr),

    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
    
    #[error("Connection closed")]
    ConnectionClosed,
    
    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Network shutdown")]
    Shutdown,
    
    #[error("Message too large: {0}")]
    MessageTooLarge(String),

    #[error("Eclipse attack detected: {0}")]
    EclipseAttack(String),
}

impl From<Box<bincode::ErrorKind>> for NetworkError {
    fn from(e: Box<bincode::ErrorKind>) -> Self {
        NetworkError::Serialization(e.to_string())
    }
}

impl From<protocol::ProtocolError> for NetworkError {
    fn from(e: protocol::ProtocolError) -> Self {
        NetworkError::Protocol(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, NetworkError>;

/// Peer identifier (socket address)
pub type PeerId = SocketAddr;

/// Network message types for gossip protocol
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum NetworkMessage {
    Inv(Vec<[u8; 32]>),
    GetData(Vec<[u8; 32]>),
    Payload(Vec<u8>),
}

/// Configuration globale du réseau
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub listen_addr: SocketAddr,
    pub rate_limit: RateLimitConfig,
    pub max_peers: usize,
    pub handshake_timeout: Duration,
    pub heartbeat_interval: Duration,
    pub eclipse_protection: EclipseProtectionConfig,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:0".parse().unwrap(),
            rate_limit: RateLimitConfig::default(),
            max_peers: 50,
            handshake_timeout: Duration::from_secs(10),
            heartbeat_interval: Duration::from_secs(30),
            eclipse_protection: EclipseProtectionConfig::default(),
        }
    }
}

/// Network API handle
pub struct NetworkApi {
    pub config: NetworkConfig,
}

impl NetworkApi {
    pub fn new(config: NetworkConfig) -> Self {
        Self { config }
    }
}

/// Peer discovery handle
pub struct PeerDiscovery {
    pub config: NetworkConfig,
}

impl PeerDiscovery {
    pub fn new(config: NetworkConfig) -> Self {
        Self { config }
    }
}

/// Peer information
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub node_id: [u8; 32],
    pub capabilities: Vec<String>,
    pub last_seen: Duration,
}

/// Block synchronization handle
pub struct BlockSync {
    pub config: NetworkConfig,
}

impl BlockSync {
    pub fn new(config: NetworkConfig) -> Self {
        Self { config }
    }
}

/// Sync configuration
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

/// Mempool configuration
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    pub max_size: usize,
    pub max_tx_size: usize,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_size: 10000,
            max_tx_size: 1024 * 1024, // 1MB
        }
    }
}

/// Anti-DoS protection handle
pub struct AntiDos {
    pub config: AntiDoSConfig,
}

impl AntiDos {
    pub fn new(config: AntiDoSConfig) -> Self {
        Self { config }
    }
}