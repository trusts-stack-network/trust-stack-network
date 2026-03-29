//! Tests unitaires pour le handshake TSN
//! 
//! Tests isolés utilisant des mocks de transport.

use std::time::Duration;
use tokio::time::timeout;
use bytes::BytesMut;

use crate::network::protocol::{
    TsnMessage, HandshakeData, ProtocolVersion, Capability, 
    encode_message, decode_message
};
use crate::network::NetworkError;

/// Test: encodage/décodage d'un handshake basique
#[test]
fn test_handshake_encode_decode() {
    let handshake = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: 1234567890,
        capabilities: vec![Capability::HighBandwidth, Capability::Forwarding],
        node_id: [1u8; 32],
        listen_port: 9333,
    };

    let msg = TsnMessage::Handshake(handshake);
    let encoded = encode_message(&msg).expect("Encoding should succeed");
    
    let mut buf = BytesMut::from(encoded.as_ref());
    let (decoded, consumed) = decode_message(&mut buf).expect("Decoding should succeed").expect("Should have message");
    
    assert_eq!(consumed, encoded.len(), "Should consume all bytes");
    
    match decoded {
        TsnMessage::Handshake(data) => {
            assert_eq!(data.version.0, 1);
            assert_eq!(data.version.1, 0);
            assert_eq!(data.timestamp_ns, 1234567890);
            assert_eq!(data.listen_port, 9333);
            assert_eq!(data.node_id, [1u8; 32]);
            assert_eq!(data.capabilities.len(), 2);
        }
        _ => panic!("Expected Handshake message"),
    }
}

/// Test: handshake avec toutes les capabilities
#[test]
fn test_handshake_all_capabilities() {
    let handshake = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: 1234567890,
        capabilities: vec![
            Capability::HighBandwidth,
            Capability::LowLatency,
            Capability::TimeSynchronization,
            Capability::Forwarding,
            Capability::MaxPeers(100),
        ],
        node_id: [2u8; 32],
        listen_port: 9334,
    };

    let msg = TsnMessage::Handshake(handshake);
    let encoded = encode_message(&msg).expect("Encoding should succeed");
    
    let mut buf = BytesMut::from(encoded.as_ref());
    let (decoded, _) = decode_message(&mut buf).expect("Decoding should succeed").expect("Should have message");
    
    match decoded {
        TsnMessage::Handshake(data) => {
            assert_eq!(data.capabilities.len(), 5);
        }
        _ => panic!("Expected Handshake message"),
    }
}

/// Test: handshake sans capabilities
#[test]
fn test_handshake_no_capabilities() {
    let handshake = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: 1234567890,
        capabilities: vec![],
        node_id: [3u8; 32],
        listen_port: 9335,
    };

    let msg = TsnMessage::Handshake(handshake);
    let encoded = encode_message(&msg).expect("Encoding should succeed");
    
    let mut buf = BytesMut::from(encoded.as_ref());
    let (decoded, _) = decode_message(&mut buf).expect("Decoding should succeed").expect("Should have message");
    
    match decoded {
        TsnMessage::Handshake(data) => {
            assert!(data.capabilities.is_empty());
        }
        _ => panic!("Expected Handshake message"),
    }
}

/// Test: handshake ack encode/decode
#[test]
fn test_handshake_ack() {
    let msg = TsnMessage::HandshakeAck {
        accepted: true,
        timestamp_ns: 1234567890,
        your_node_id: [4u8; 32],
    };

    let encoded = encode_message(&msg).expect("Encoding should succeed");
    
    let mut buf = BytesMut::from(encoded.as_ref());
    let (decoded, _) = decode_message(&mut buf).expect("Decoding should succeed").expect("Should have message");
    
    match decoded {
        TsnMessage::HandshakeAck { accepted, timestamp_ns, your_node_id } => {
            assert!(accepted);
            assert_eq!(timestamp_ns, 1234567890);
            assert_eq!(your_node_id, [4u8; 32]);
        }
        _ => panic!("Expected HandshakeAck message"),
    }
}

/// Test: handshake ack rejeté
#[test]
fn test_handshake_ack_rejected() {
    let msg = TsnMessage::HandshakeAck {
        accepted: false,
        timestamp_ns: 1234567891,
        your_node_id: [5u8; 32],
    };

    let encoded = encode_message(&msg).expect("Encoding should succeed");
    
    let mut buf = BytesMut::from(encoded.as_ref());
    let (decoded, _) = decode_message(&mut buf).expect("Decoding should succeed").expect("Should have message");
    
    match decoded {
        TsnMessage::HandshakeAck { accepted, .. } => {
            assert!(!accepted);
        }
        _ => panic!("Expected HandshakeAck message"),
    }
}

/// Test: timeout sur handshake (simulation)
#[tokio::test]
async fn test_handshake_timeout() {
    // Simule un handshake qui timeout
    let result = timeout(Duration::from_millis(50), async {
        // Simule un délai plus long que le timeout
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok::<(), NetworkError>(())
    }).await;

    assert!(result.is_err(), "Should timeout");
}

/// Test: handshake avec node_id aléatoire
#[test]
fn test_handshake_random_node_id() {
    let mut node_id = [0u8; 32];
    for i in 0..32 {
        node_id[i] = i as u8;
    }

    let handshake = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: 1234567890,
        capabilities: vec![Capability::Forwarding],
        node_id,
        listen_port: 9336,
    };

    let msg = TsnMessage::Handshake(handshake);
    let encoded = encode_message(&msg).expect("Encoding should succeed");
    
    let mut buf = BytesMut::from(encoded.as_ref());
    let (decoded, _) = decode_message(&mut buf).expect("Decoding should succeed").expect("Should have message");
    
    match decoded {
        TsnMessage::Handshake(data) => {
            assert_eq!(data.node_id, node_id);
        }
        _ => panic!("Expected Handshake message"),
    }
}

/// Test: port d'écoute 0 (ephemeral)
#[test]
fn test_handshake_ephemeral_port() {
    let handshake = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: 1234567890,
        capabilities: vec![],
        node_id: [6u8; 32],
        listen_port: 0,
    };

    let msg = TsnMessage::Handshake(handshake);
    let encoded = encode_message(&msg).expect("Encoding should succeed");
    
    let mut buf = BytesMut::from(encoded.as_ref());
    let (decoded, _) = decode_message(&mut buf).expect("Decoding should succeed").expect("Should have message");
    
    match decoded {
        TsnMessage::Handshake(data) => {
            assert_eq!(data.listen_port, 0);
        }
        _ => panic!("Expected Handshake message"),
    }
}

/// Test: port d'écoute maximum (65535)
#[test]
fn test_handshake_max_port() {
    let handshake = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: 1234567890,
        capabilities: vec![],
        node_id: [7u8; 32],
        listen_port: 65535,
    };

    let msg = TsnMessage::Handshake(handshake);
    let encoded = encode_message(&msg).expect("Encoding should succeed");
    
    let mut buf = BytesMut::from(encoded.as_ref());
    let (decoded, _) = decode_message(&mut buf).expect("Decoding should succeed").expect("Should have message");
    
    match decoded {
        TsnMessage::Handshake(data) => {
            assert_eq!(data.listen_port, 65535);
        }
        _ => panic!("Expected Handshake message"),
    }
}

/// Test: version du protocole
#[test]
fn test_protocol_version() {
    let v1 = ProtocolVersion(1, 0);
    let v2 = ProtocolVersion(1, 1);
    let v3 = ProtocolVersion(2, 0);

    assert_eq!(v1.0, 1);
    assert_eq!(v1.1, 0);
    assert_eq!(v2.1, 1);
    assert_eq!(v3.0, 2);
}

/// Test: handshake avec timestamp très grand
#[test]
fn test_handshake_large_timestamp() {
    let handshake = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: u64::MAX,
        capabilities: vec![],
        node_id: [8u8; 32],
        listen_port: 9337,
    };

    let msg = TsnMessage::Handshake(handshake);
    let encoded = encode_message(&msg).expect("Encoding should succeed");
    
    let mut buf = BytesMut::from(encoded.as_ref());
    let (decoded, _) = decode_message(&mut buf).expect("Decoding should succeed").expect("Should have message");
    
    match decoded {
        TsnMessage::Handshake(data) => {
            assert_eq!(data.timestamp_ns, u64::MAX);
        }
        _ => panic!("Expected Handshake message"),
    }
}

/// Test: handshake avec timestamp 0
#[test]
fn test_handshake_zero_timestamp() {
    let handshake = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: 0,
        capabilities: vec![],
        node_id: [9u8; 32],
        listen_port: 9338,
    };

    let msg = TsnMessage::Handshake(handshake);
    let encoded = encode_message(&msg).expect("Encoding should succeed");
    
    let mut buf = BytesMut::from(encoded.as_ref());
    let (decoded, _) = decode_message(&mut buf).expect("Decoding should succeed").expect("Should have message");
    
    match decoded {
        TsnMessage::Handshake(data) => {
            assert_eq!(data.timestamp_ns, 0);
        }
        _ => panic!("Expected Handshake message"),
    }
}
