//! Protocole de communication TSN
//! Définition des messages et validation

use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

use super::Result;

const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024; // 4MB max
const PROTOCOL_MAGIC: &[u8] = b"TSN1";
#[allow(dead_code)]
const CURRENT_VERSION: ProtocolVersion = ProtocolVersion(1, 0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion(pub u8, pub u8);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeData {
    pub version: ProtocolVersion,
    pub timestamp_ns: u64,
    pub capabilities: Vec<Capability>,
    pub node_id: [u8; 32],
    pub listen_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Capability {
    HighBandwidth,
    LowLatency,
    TimeSynchronization,
    Forwarding,
    MaxPeers(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TsnMessage {
    /// Handshake initial
    Handshake(HandshakeData),
    /// Acknowledgement du handshake
    HandshakeAck {
        accepted: bool,
        timestamp_ns: u64,
        your_node_id: [u8; 32],
    },
    /// Heartbeat avec timestamp TSN
    Heartbeat {
        timestamp_ns: u64,
        sequence: u64,
    },
    /// Déconnexion gracieuse
    Disconnect {
        reason: String,
        timestamp_ns: u64,
    },
    /// Échange de pairs (peer discovery)
    PeerExchange {
        peers: Vec<PeerInfo>,
        timestamp_ns: u64,
    },
    /// Données applicatives avec priorité TSN
    Data {
        priority: u8,
        timestamp_ns: u64,
        payload: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub addr: std::net::SocketAddr,
    pub node_id: [u8; 32],
    pub capabilities: Vec<Capability>,
    pub last_seen: u64,
}

#[derive(Error, Debug)]
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

/// Encode un message TSN avec framing (length-prefixed)
pub fn encode_message(msg: &TsnMessage) -> Result<Bytes> {
    let payload = bincode::serialize(msg)?;
    
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(ProtocolError::MessageTooLarge(payload.len(), MAX_MESSAGE_SIZE).into());
    }
    
    let mut buf = BytesMut::with_capacity(PROTOCOL_MAGIC.len() + 4 + payload.len());
    buf.put_slice(PROTOCOL_MAGIC);
    buf.put_u32_le(payload.len() as u32);
    buf.put_slice(&payload);
    
    Ok(buf.freeze())
}

/// Décode un message TSN depuis un buffer
/// Retourne Ok(Some(msg, consumed_bytes)) si un message complet est présent
/// Retourne Ok(None) si besoin de plus de données
pub fn decode_message(buf: &mut BytesMut) -> Result<Option<(TsnMessage, usize)>> {
    if buf.len() < PROTOCOL_MAGIC.len() + 4 {
        return Ok(None);
    }
    
    // Vérification magic
    let magic = &buf[..PROTOCOL_MAGIC.len()];
    if magic != PROTOCOL_MAGIC {
        buf.clear();
        return Err(ProtocolError::InvalidMagic.into());
    }

    // Lecture de la taille du payload
    let payload_len_bytes = &buf[PROTOCOL_MAGIC.len()..PROTOCOL_MAGIC.len() + 4];
    let payload_len = u32::from_le_bytes([payload_len_bytes[0], payload_len_bytes[1], payload_len_bytes[2], payload_len_bytes[3]]) as usize;
    
    // Validation de la taille du payload
    if payload_len > MAX_MESSAGE_SIZE {
        buf.clear();
        return Err(ProtocolError::MessageTooLarge(payload_len, MAX_MESSAGE_SIZE).into());
    }
    
    if payload_len == 0 {
        buf.clear();
        return Err(ProtocolError::InvalidPayloadLength(0).into());
    }
    
    // Vérification que nous avons assez de données
    let total_message_len = PROTOCOL_MAGIC.len() + 4 + payload_len;
    if buf.len() < total_message_len {
        return Ok(None);
    }
    
    // Extraction du payload
    let payload_start = PROTOCOL_MAGIC.len() + 4;
    let payload_end = payload_start + payload_len;
    let payload = &buf[payload_start..payload_end];
    
    // Désérialisation du message
    let message = bincode::deserialize::<TsnMessage>(payload)
        .map_err(|e| ProtocolError::Deserialization(e.to_string()))?;
    
    // Validation du timestamp (optionnelle mais recommandée)
    validate_message_timestamp(&message)?;
    
    // Suppression des bytes consommés du buffer
    buf.advance(total_message_len);
    
    Ok(Some((message, total_message_len)))
}

/// Valide le timestamp d'un message pour éviter les attaques par replay
fn validate_message_timestamp(msg: &TsnMessage) -> Result<()> {
    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    
    let message_timestamp = match msg {
        TsnMessage::Handshake(data) => data.timestamp_ns,
        TsnMessage::HandshakeAck { timestamp_ns, .. } => *timestamp_ns,
        TsnMessage::Heartbeat { timestamp_ns, .. } => *timestamp_ns,
        TsnMessage::Disconnect { timestamp_ns, .. } => *timestamp_ns,
        TsnMessage::PeerExchange { timestamp_ns, .. } => *timestamp_ns,
        TsnMessage::Data { timestamp_ns, .. } => *timestamp_ns,
    };
    
    // Tolérance de 5 minutes pour tenir compte de la dérive d'horloge réseau
    const MAX_DRIFT_NS: u64 = 5 * 60 * 1_000_000_000;
    
    let drift = if current_timestamp > message_timestamp {
        current_timestamp - message_timestamp
    } else {
        message_timestamp - current_timestamp
    };
    
    if drift > MAX_DRIFT_NS {
        return Err(ProtocolError::InvalidTimestamp(format!(
            "Timestamp drift too large: {} seconds", 
            drift / 1_000_000_000
        )).into());
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encode_decode_roundtrip() {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let original_msg = TsnMessage::Heartbeat {
            timestamp_ns: now_ns,
            sequence: 42,
        };
        
        let encoded = encode_message(&original_msg).unwrap();
        let mut buf = BytesMut::from(encoded.as_ref());
        
        let (decoded_msg, consumed) = decode_message(&mut buf).unwrap().unwrap();
        
        assert_eq!(consumed, encoded.len());
        match decoded_msg {
            TsnMessage::Heartbeat { timestamp_ns: dec_ts, sequence: dec_seq } => {
                assert_eq!(now_ns, dec_ts);
                assert_eq!(42, dec_seq);
            }
            _ => panic!("Message type mismatch"),
        }
    }
    
    #[test]
    fn test_invalid_magic() {
        let mut buf = BytesMut::from(&b"XXXX\x05\x00\x00\x00hello"[..]);
        let result = decode_message(&mut buf);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), crate::network::NetworkError::Protocol(ref msg) if msg.contains("magic")));
    }

    #[test]
    fn test_message_too_large() {
        let mut buf = BytesMut::from(&b"TSN1\xFF\xFF\xFF\xFF"[..]);
        let result = decode_message(&mut buf);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), crate::network::NetworkError::Protocol(ref msg) if msg.contains("large") || msg.contains("Large")));
    }
    
    #[test]
    fn test_incomplete_message() {
        let mut buf = BytesMut::from(&b"TSN1\x05\x00\x00\x00hel"[..]);
        let result = decode_message(&mut buf);
        assert!(result.unwrap().is_none());
    }
}