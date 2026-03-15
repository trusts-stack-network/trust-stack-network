//! Error types for TSN networking

use thiserror::Error;
use tokio::time::error::Elapsed;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    
    #[error("Invalid message: {0}")]
    InvalidMessage(String),
    
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),
    
    #[error("Rate limited: {0}")]
    RateLimited(String),
    
    #[error("Peer disconnected: {0}")]
    PeerDisconnected(String),
    
    #[error("Timeout")]
    Timeout(#[from] Elapsed),
    
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    
    #[error("Discovery error: {0}")]
    Discovery(String),
    
    #[error("Invalid state: {0}")]
    InvalidState(String),
    
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),
}

#[derive(Error, Debug, Clone)]
pub enum ProtocolError {
    #[error("Message too large: {0} > {1}")]
    MessageTooLarge(usize, usize),
    #[error("Invalid magic bytes")]
    InvalidMagic,
    #[error("Deserialization failed: {0}")]
    Deserialization(String),
    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(String),
    #[error("Incomplete message: need {needed} more bytes")]
    IncompleteMessage { needed: usize },
    #[error("Invalid payload length: {0}")]
    InvalidPayloadLength(usize),
}

pub type Result<T> = std::result::Result<T, NetworkError>;
pub type NetworkResult<T> = std::result::Result<T, NetworkError>;
