use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub type PeerId = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TsnHandshake {
    pub protocol_version: u16,
    pub network_id: [u8; 32],
    pub node_id: PeerId,
    pub timestamp: u64,
    pub capabilities: Vec<Capability>,
    pub nonce: [u8; 32],
    pub signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Capability {
    BlockPropagation,
    TransactionRelay,
    ConsensusParticipation,
    ArchiveNode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TsnMessage {
    Handshake(TsnHandshake),
    HandshakeAck {
        node_id: PeerId,
        timestamp: u64,
        signature: Option<Vec<u8>>,
    },
    Ping {
        nonce: u64,
        timestamp: u64,
    },
    Pong {
        nonce: u64,
        timestamp: u64,
    },
    PeerExchange {
        peers: Vec<PeerInfo>,
    },
    Disconnect {
        reason: DisconnectReason,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub node_id: PeerId,
    pub capabilities: Vec<Capability>,
    pub last_seen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DisconnectReason {
    ProtocolViolation,
    TooManyPeers,
    InvalidHandshake,
    RateLimited,
    Shutdown,
}

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    
    #[error("Invalid handshake: {0}")]
    InvalidHandshake(String),
    
    #[error("Protocol version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u16, actual: u16 },
    
    #[error("Network ID mismatch")]
    NetworkIdMismatch,
    
    #[error("Timestamp too old or future: {0}")]
    InvalidTimestamp(u64),
    
    #[error("Rate limited")]
    RateLimited,
    
    #[error("Peer banned")]
    PeerBanned,
    
    #[error("Connection timeout")]
    Timeout,
    
    #[error("Invalid message size: {size}, max: {max}")]
    InvalidMessageSize { size: usize, max: usize },
}

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_MESSAGE_SIZE: usize = 2 * 1024 * 1024; // 2MB
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const MESSAGE_TIMEOUT: Duration = Duration::from_secs(30);
pub const TIMESTAMP_TOLERANCE: Duration = Duration::from_secs(120);

/// Encode un message avec un header de taille (4 bytes little-endian)
pub async fn write_message(stream: &mut TcpStream, msg: &TsnMessage) -> Result<(), NetworkError> {
    let encoded = bincode::serialize(msg)?;
    let len = encoded.len() as u32;
    
    if encoded.len() > MAX_MESSAGE_SIZE {
        return Err(NetworkError::InvalidMessageSize {
            size: encoded.len(),
            max: MAX_MESSAGE_SIZE,
        });
    }
    
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&encoded).await?;
    Ok(())
}

/// Lit un message avec vérification de taille
pub async fn read_message(stream: &mut TcpStream) -> Result<TsnMessage, NetworkError> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    
    if len > MAX_MESSAGE_SIZE {
        return Err(NetworkError::InvalidMessageSize {
            size: len,
            max: MAX_MESSAGE_SIZE,
        });
    }
    
    let mut buffer = BytesMut::with_capacity(len);
    buffer.resize(len, 0);
    stream.read_exact(&mut buffer).await?;
    
    let msg: TsnMessage = bincode::deserialize(&buffer)?;
    Ok(msg)
}

pub fn generate_peer_id() -> PeerId {
    use rand::Rng;
    let mut id = [0u8; 32];
    rand::thread_rng().fill(&mut id);
    id
}

pub fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}