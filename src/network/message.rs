use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::error::{NetworkError, Result};

const MAX_MESSAGE_SIZE: usize = 65536;
const HEADER_SIZE: usize = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsnMessage {
    pub version: u8,
    pub timestamp_ns: u64,
    pub priority: u8, // 0-7, TSN priority classes
    pub payload: MessagePayload,
    pub signature: Option<[u8; 64]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessagePayload {
    Discovery(DiscoveryMessage),
    Handshake(HandshakeMessage),
    Data(DataMessage),
    KeepAlive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryMessage {
    pub node_id: [u8; 32],
    pub listen_addr: String,
    pub capabilities: Vec<String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakeMessage {
    Hello {
        nonce: [u8; 32],
        public_key: [u8; 32],
        timestamp: u64,
        tsn_params: TsnParams,
    },
    Challenge {
        nonce_signature: [u8; 64],
        echo_timestamp: u64,
        timestamp: u64,
    },
    Ack {
        session_id: [u8; 16],
        bandwidth_alloc: u32, // kbps
        max_latency_us: u32,
    },
    Reject {
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsnParams {
    pub priority_classes: Vec<u8>,
    pub max_bandwidth: u32,
    pub clock_accuracy_ns: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataMessage {
    pub stream_id: u64,
    pub sequence: u64,
    pub data: Vec<u8>,
    pub deadline_ns: Option<u64>,
}

impl TsnMessage {
    pub fn new(payload: MessagePayload, priority: u8) -> Self {
        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
            
        Self {
            version: 1,
            timestamp_ns,
            priority: priority.min(7),
            payload,
            signature: None,
        }
    }
    
    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<()> {
        let bytes = bincode::serialize(&self.payload)?;
        let signature = signing_key.sign(&bytes);
        self.signature = Some(signature.to_bytes());
        Ok(())
    }
    
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<()> {
        let signature = self.signature.ok_or_else(|| {
            NetworkError::ValidationFailed("Missing signature".to_string())
        })?;
        
        let sig = Signature::from_bytes(&signature);
        let bytes = bincode::serialize(&self.payload)?;
        
        verifying_key
            .verify(&bytes, &sig)
            .map_err(|e| NetworkError::Crypto(e.to_string()))?;
            
        Ok(())
    }
    
    pub fn validate_timestamp(&self, max_drift_ms: u64) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
            
        let drift = if now > self.timestamp_ns {
            now - self.timestamp_ns
        } else {
            self.timestamp_ns - now
        };
        
        if drift > max_drift_ms * 1_000_000 {
            return Err(NetworkError::ValidationFailed(
                format!("Timestamp drift too large: {}ms", drift / 1_000_000)
            ));
        }
        
        Ok(())
    }
}

pub async fn read_message<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<TsnMessage> {
    // Read length header (4 bytes, big-endian)
    let mut len_bytes = [0u8; HEADER_SIZE];
    reader.read_exact(&mut len_bytes).await.map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            NetworkError::ConnectionClosed
        } else {
            NetworkError::Io(e)
        }
    })?;
    
    let len = u32::from_be_bytes(len_bytes) as usize;
    
    if len > MAX_MESSAGE_SIZE {
        return Err(NetworkError::ValidationFailed(
            format!("Message too large: {} > {}", len, MAX_MESSAGE_SIZE)
        ));
    }
    
    if len == 0 {
        return