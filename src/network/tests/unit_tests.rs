//! Tests unitaires isolés pour le module réseau TSN
//! 
//! Tests sans dépendances externes, avec mocks et timeouts appropriés.

use std::time::Duration;
use tokio::time::timeout;
use bytes::BytesMut;

use crate::network::protocol::{
    TsnMessage, HandshakeData, ProtocolVersion, Capability, 
    encode_message, decode_message, ProtocolError
};
use crate::network::NetworkError;

/// Test: encodage/décodage basique de HandshakeData
#[test]
fn test_basic_handshake_encode_decode() {
    let handshake = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: 1234567890,
        capabilities: vec![Capability::Forwarding],
        node_id: [42u8; 32],
        listen_port: 9333,
    };

    let msg = TsnMessage::Handshake(handshake);
    
    // Encode
    let encoded = encode_message(&msg).expect("Encoding should succeed");
    assert!(!encoded.is_empty(), "Encoded message should not be empty");
    
    // Decode
    let mut buf = BytesMut::from(encoded.as_ref());
    let (decoded, consumed) = decode_message(&mut buf)
        .expect("Decoding should succeed")
        .expect("Should have a message");
    
    assert!(consumed > 0, "Should consume some bytes");
    
    match decoded {
        TsnMessage::Handshake(data) => {
            assert_eq!(data.version.0, 1);
            assert_eq!(data.version.1, 0);
            assert_eq!(data.timestamp_ns, 1234567890);
            assert_eq!(data.node_id, [42u8; 32]);
            assert_eq!(data.listen_port, 9333);
            assert_eq!(data.capabilities.len(), 1);
            assert!(matches!(data.capabilities[0], Capability::Forwarding));
        }
        _ => panic!("Expected Handshake message"),
    }
}

/// Test: encodage/décodage de HandshakeAck
#[test]
fn test_handshake_ack_encode_decode() {
    let msg = TsnMessage::HandshakeAck {
        accepted: true,
        timestamp_ns: 9876543210,
        your_node_id: [99u8; 32],
    };
    
    let encoded = encode_message(&msg).expect("Encoding should succeed");
    
    let mut buf = BytesMut::from(encoded.as_ref());
    let (decoded, _) = decode_message(&mut buf)
        .expect("Decoding should succeed")
        .expect("Should have a message");
    
    match decoded {
        TsnMessage::HandshakeAck { accepted, timestamp_ns, your_node_id } => {
            assert!(accepted);
            assert_eq!(timestamp_ns, 9876543210);
            assert_eq!(your_node_id, [99u8; 32]);
        }
        _ => panic!("Expected HandshakeAck message"),
    }
}

/// Test: toutes les capabilities
#[test]
fn test_all_capabilities() {
    let capabilities = vec![
        Capability::HighBandwidth,
        Capability::LowLatency,
        Capability::TimeSynchronization,
        Capability::Forwarding,
        Capability::MaxPeers(1000),
    ];
    
    let handshake = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: 1234567890,
        capabilities: capabilities.clone(),
        node_id: [1u8; 32],
        listen_port: 9333,
    };

    let msg = TsnMessage::Handshake(handshake);
    let encoded = encode_message(&msg).expect("Encoding should succeed");
    
    let mut buf = BytesMut::from(encoded.as_ref());
    let (decoded, _) = decode_message(&mut buf)
        .expect("Decoding should succeed")
        .expect("Should have a message");
    
    match decoded {
        TsnMessage::Handshake(data) => {
            assert_eq!(data.capabilities.len(), 5);
            assert!(data.capabilities.contains(&Capability::HighBandwidth));
            assert!(data.capabilities.contains(&Capability::LowLatency));
            assert!(data.capabilities.contains(&Capability::TimeSynchronization));
            assert!(data.capabilities.contains(&Capability::Forwarding));
            
            let has_max_peers = data.capabilities.iter().any(|cap| {
                matches!(cap, Capability::MaxPeers(1000))
            });
            assert!(has_max_peers);
        }
        _ => panic!("Expected Handshake message"),
    }
}

/// Test: handshake avec capabilities vides
#[test]
fn test_empty_capabilities() {
    let handshake = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: 1234567890,
        capabilities: vec![], // Pas de capabilities
        node_id: [2u8; 32],
        listen_port: 9333,
    };

    let msg = TsnMessage::Handshake(handshake);
    let encoded = encode_message(&msg).expect("Encoding should succeed");
    
    let mut buf = BytesMut::from(encoded.as_ref());
    let (decoded, _) = decode_message(&mut buf)
        .expect("Decoding should succeed")
        .expect("Should have a message");
    
    match decoded {
        TsnMessage::Handshake(data) => {
            assert_eq!(data.capabilities.len(), 0);
        }
        _ => panic!("Expected Handshake message"),
    }
}

/// Test: différentes versions de protocole
#[test]
fn test_protocol_versions() {
    let versions = vec![
        ProtocolVersion(0, 1),
        ProtocolVersion(1, 0),
        ProtocolVersion(1, 5),
        ProtocolVersion(2, 0),
        ProtocolVersion(255, 255),
    ];
    
    for version in versions {
        let handshake = HandshakeData {
            version,
            timestamp_ns: 1234567890,
            capabilities: vec![],
            node_id: [3u8; 32],
            listen_port: 9333,
        };

        let msg = TsnMessage::Handshake(handshake);
        let encoded = encode_message(&msg).expect("Encoding should succeed");
        
        let mut buf = BytesMut::from(encoded.as_ref());
        let (decoded, _) = decode_message(&mut buf)
            .expect("Decoding should succeed")
            .expect("Should have a message");
        
        match decoded {
            TsnMessage::Handshake(data) => {
                assert_eq!(data.version.0, version.0);
                assert_eq!(data.version.1, version.1);
            }
            _ => panic!("Expected Handshake message"),
        }
    }
}

/// Test: différents ports d'écoute
#[test]
fn test_listen_ports() {
    let ports = vec![1, 80, 443, 8080, 9333, 65535];
    
    for port in ports {
        let handshake = HandshakeData {
            version: ProtocolVersion(1, 0),
            timestamp_ns: 1234567890,
            capabilities: vec![],
            node_id: [4u8; 32],
            listen_port: port,
        };

        let msg = TsnMessage::Handshake(handshake);
        let encoded = encode_message(&msg).expect("Encoding should succeed");
        
        let mut buf = BytesMut::from(encoded.as_ref());
        let (decoded, _) = decode_message(&mut buf)
            .expect("Decoding should succeed")
            .expect("Should have a message");
        
        match decoded {
            TsnMessage::Handshake(data) => {
                assert_eq!(data.listen_port, port);
            }
            _ => panic!("Expected Handshake message"),
        }
    }
}

/// Test: différents node_id
#[test]
fn test_node_ids() {
    let node_ids = vec![
        [0u8; 32],
        [255u8; 32],
        {
            let mut id = [0u8; 32];
            for i in 0..32 {
                id[i] = i as u8;
            }
            id
        },
        {
            let mut id = [0u8; 32];
            id[0] = 1;
            id[31] = 255;
            id
        },
    ];
    
    for node_id in node_ids {
        let handshake = HandshakeData {
            version: ProtocolVersion(1, 0),
            timestamp_ns: 1234567890,
            capabilities: vec![],
            node_id,
            listen_port: 9333,
        };

        let msg = TsnMessage::Handshake(handshake);
        let encoded = encode_message(&msg).expect("Encoding should succeed");
        
        let mut buf = BytesMut::from(encoded.as_ref());
        let (decoded, _) = decode_message(&mut buf)
            .expect("Decoding should succeed")
            .expect("Should have a message");
        
        match decoded {
            TsnMessage::Handshake(data) => {
                assert_eq!(data.node_id, node_id);
            }
            _ => panic!("Expected Handshake message"),
        }
    }
}

/// Test: timestamps extrêmes
#[test]
fn test_extreme_timestamps() {
    let timestamps = vec![0, 1, u64::MAX - 1, u64::MAX];
    
    for timestamp in timestamps {
        let handshake = HandshakeData {
            version: ProtocolVersion(1, 0),
            timestamp_ns: timestamp,
            capabilities: vec![],
            node_id: [5u8; 32],
            listen_port: 9333,
        };

        let msg = TsnMessage::Handshake(handshake);
        let encoded = encode_message(&msg).expect("Encoding should succeed");
        
        let mut buf = BytesMut::from(encoded.as_ref());
        let (decoded, _) = decode_message(&mut buf)
            .expect("Decoding should succeed")
            .expect("Should have a message");
        
        match decoded {
            TsnMessage::Handshake(data) => {
                assert_eq!(data.timestamp_ns, timestamp);
            }
            _ => panic!("Expected Handshake message"),
        }
    }
}

/// Test: HandshakeAck avec différents états
#[test]
fn test_handshake_ack_states() {
    let states = vec![true, false];
    
    for accepted in states {
        let msg = TsnMessage::HandshakeAck {
            accepted,
            timestamp_ns: 1234567890,
            your_node_id: [6u8; 32],
        };
        
        let encoded = encode_message(&msg).expect("Encoding should succeed");
        
        let mut buf = BytesMut::from(encoded.as_ref());
        let (decoded, _) = decode_message(&mut buf)
            .expect("Decoding should succeed")
            .expect("Should have a message");
        
        match decoded {
            TsnMessage::HandshakeAck { accepted: decoded_accepted, .. } => {
                assert_eq!(decoded_accepted, accepted);
            }
            _ => panic!("Expected HandshakeAck message"),
        }
    }
}

/// Test: buffer insuffisant pour un message complet
#[test]
fn test_insufficient_buffer() {
    let handshake = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: 1234567890,
        capabilities: vec![Capability::Forwarding],
        node_id: [7u8; 32],
        listen_port: 9333,
    };

    let msg = TsnMessage::Handshake(handshake);
    let encoded = encode_message(&msg).expect("Encoding should succeed");
    
    // Prend seulement les premiers bytes
    let partial = &encoded[..encoded.len().min(10)];
    let mut buf = BytesMut::from(partial);
    
    let result = decode_message(&mut buf);
    
    match result {
        Ok(None) => {
            // Comportement attendu : pas assez de données
        }
        Ok(Some(_)) => {
            panic!("Ne devrait pas décoder avec un buffer insuffisant");
        }
        Err(_) => {
            // Erreur acceptable
        }
    }
}

/// Test: buffer vide
#[test]
fn test_empty_buffer() {
    let mut buf = BytesMut::new();
    
    let result = decode_message(&mut buf);
    
    match result {
        Ok(None) => {
            // Comportement attendu
        }
        Ok(Some(_)) => {
            panic!("Ne devrait pas décoder un buffer vide");
        }
        Err(_) => {
            // Erreur acceptable
        }
    }
}

/// Test: round-trip de tous les types de messages
#[test]
fn test_all_message_types_roundtrip() {
    let messages = vec![
        TsnMessage::Handshake(HandshakeData {
            version: ProtocolVersion(1, 0),
            timestamp_ns: 1234567890,
            capabilities: vec![Capability::HighBandwidth],
            node_id: [8u8; 32],
            listen_port: 9333,
        }),
        TsnMessage::HandshakeAck {
            accepted: true,
            timestamp_ns: 1234567891,
            your_node_id: [9u8; 32],
        },
        TsnMessage::HandshakeAck {
            accepted: false,
            timestamp_ns: 1234567892,
            your_node_id: [10u8; 32],
        },
    ];
    
    for (i, original_msg) in messages.into_iter().enumerate() {
        let encoded = encode_message(&original_msg)
            .expect(&format!("Encoding should succeed for message {}", i));
        
        let mut buf = BytesMut::from(encoded.as_ref());
        let (decoded_msg, consumed) = decode_message(&mut buf)
            .expect(&format!("Decoding should succeed for message {}", i))
            .expect(&format!("Should have a message {}", i));
        
        assert!(consumed > 0, "Should consume bytes for message {}", i);
        
        // Vérifie que le message décodé correspond à l'original
        match (&original_msg, &decoded_msg) {
            (TsnMessage::Handshake(orig), TsnMessage::Handshake(dec)) => {
                assert_eq!(orig.version.0, dec.version.0);
                assert_eq!(orig.version.1, dec.version.1);
                assert_eq!(orig.timestamp_ns, dec.timestamp_ns);
                assert_eq!(orig.node_id, dec.node_id);
                assert_eq!(orig.listen_port, dec.listen_port);
                assert_eq!(orig.capabilities, dec.capabilities);
            }
            (TsnMessage::HandshakeAck { accepted: orig_acc, timestamp_ns: orig_ts, your_node_id: orig_id }, 
             TsnMessage::HandshakeAck { accepted: dec_acc, timestamp_ns: dec_ts, your_node_id: dec_id }) => {
                assert_eq!(orig_acc, dec_acc);
                assert_eq!(orig_ts, dec_ts);
                assert_eq!(orig_id, dec_id);
            }
            _ => panic!("Message types don't match for message {}", i),
        }
    }
}

/// Test: timeout avec opération async mock
#[tokio::test]
async fn test_timeout_with_mock_operation() {
    // Opération qui réussit dans les temps
    let result = timeout(Duration::from_millis(100), async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok::<i32, NetworkError>(42)
    }).await;
    
    assert!(result.is_ok());
    let inner_result = result.unwrap();
    assert!(inner_result.is_ok());
    assert_eq!(inner_result.unwrap(), 42);
    
    // Opération qui timeout
    let result = timeout(Duration::from_millis(50), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok::<i32, NetworkError>(42)
    }).await;
    
    assert!(result.is_err()); // Timeout
}

/// Test: gestion d'erreur avec NetworkError
#[tokio::test]
async fn test_network_error_handling() {
    // Simule différents types d'erreurs réseau
    let errors = vec![
        NetworkError::ConnectionFailed,
        NetworkError::Timeout,
        NetworkError::InvalidMessage,
        NetworkError::PeerNotFound,
        NetworkError::EncodingError,
        NetworkError::DecodingError,
        NetworkError::NotConnected,
    ];
    
    for error in errors {
        let result = timeout(Duration::from_millis(10), async {
            Err::<(), NetworkError>(error)
        }).await;
        
        assert!(result.is_ok()); // Pas de timeout
        let inner_result = result.unwrap();
        assert!(inner_result.is_err()); // Mais erreur réseau
    }
}

/// Test: validation des capabilities MaxPeers
#[test]
fn test_max_peers_capability_values() {
    let max_peers_values = vec![0, 1, 10, 100, 1000, 10000, u32::MAX];
    
    for max_peers in max_peers_values {
        let handshake = HandshakeData {
            version: ProtocolVersion(1, 0),
            timestamp_ns: 1234567890,
            capabilities: vec![Capability::MaxPeers(max_peers)],
            node_id: [11u8; 32],
            listen_port: 9333,
        };

        let msg = TsnMessage::Handshake(handshake);
        let encoded = encode_message(&msg).expect("Encoding should succeed");
        
        let mut buf = BytesMut::from(encoded.as_ref());
        let (decoded, _) = decode_message(&mut buf)
            .expect("Decoding should succeed")
            .expect("Should have a message");
        
        match decoded {
            TsnMessage::Handshake(data) => {
                assert_eq!(data.capabilities.len(), 1);
                match &data.capabilities[0] {
                    Capability::MaxPeers(decoded_max) => {
                        assert_eq!(*decoded_max, max_peers);
                    }
                    _ => panic!("Expected MaxPeers capability"),
                }
            }
            _ => panic!("Expected Handshake message"),
        }
    }
}