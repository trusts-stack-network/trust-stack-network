//! Tests de performance pour le module réseau TSN
//! 
//! Tests de charge, latence et throughput avec métriques.

use std::time::{Duration, Instant};
use bytes::BytesMut;

use crate::network::protocol::{
    TsnMessage, HandshakeData, ProtocolVersion, Capability, 
    encode_message, decode_message
};

/// Test: performance d'encodage de handshakes
#[test]
fn test_handshake_encoding_performance() {
    let handshake = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: 1234567890,
        capabilities: vec![
            Capability::HighBandwidth,
            Capability::LowLatency,
            Capability::TimeSynchronization,
            Capability::Forwarding,
            Capability::MaxPeers(1000),
        ],
        node_id: [42u8; 32],
        listen_port: 9333,
    };

    let msg = TsnMessage::Handshake(handshake);
    
    let iterations = 10_000;
    let start = Instant::now();
    
    for _ in 0..iterations {
        let _encoded = encode_message(&msg).expect("Encoding should succeed");
    }
    
    let duration = start.elapsed();
    let ops_per_sec = iterations as f64 / duration.as_secs_f64();
    
    println!("Handshake encoding: {:.0} ops/sec", ops_per_sec);
    
    // Performance baseline : au moins 10k ops/sec
    assert!(ops_per_sec > 10_000.0, "Encoding too slow: {:.0} ops/sec", ops_per_sec);
}

/// Test: performance de décodage de handshakes
#[test]
fn test_handshake_decoding_performance() {
    let handshake = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: 1234567890,
        capabilities: vec![
            Capability::HighBandwidth,
            Capability::LowLatency,
            Capability::TimeSynchronization,
            Capability::Forwarding,
            Capability::MaxPeers(1000),
        ],
        node_id: [42u8; 32],
        listen_port: 9333,
    };

    let msg = TsnMessage::Handshake(handshake);
    let encoded = encode_message(&msg).expect("Encoding should succeed");
    
    let iterations = 10_000;
    let start = Instant::now();
    
    for _ in 0..iterations {
        let mut buf = BytesMut::from(encoded.as_ref());
        let _decoded = decode_message(&mut buf)
            .expect("Decoding should succeed")
            .expect("Should have a message");
    }
    
    let duration = start.elapsed();
    let ops_per_sec = iterations as f64 / duration.as_secs_f64();
    
    println!("Handshake decoding: {:.0} ops/sec", ops_per_sec);
    
    // Performance baseline : au moins 10k ops/sec
    assert!(ops_per_sec > 10_000.0, "Decoding too slow: {:.0} ops/sec", ops_per_sec);
}

/// Test: performance d'encodage de HandshakeAck
#[test]
fn test_handshake_ack_encoding_performance() {
    let msg = TsnMessage::HandshakeAck {
        accepted: true,
        timestamp_ns: 1234567890,
        your_node_id: [42u8; 32],
    };
    
    let iterations = 50_000;
    let start = Instant::now();
    
    for _ in 0..iterations {
        let _encoded = encode_message(&msg).expect("Encoding should succeed");
    }
    
    let duration = start.elapsed();
    let ops_per_sec = iterations as f64 / duration.as_secs_f64();
    
    println!("HandshakeAck encoding: {:.0} ops/sec", ops_per_sec);
    
    // HandshakeAck est plus simple, devrait être plus rapide
    assert!(ops_per_sec > 20_000.0, "HandshakeAck encoding too slow: {:.0} ops/sec", ops_per_sec);
}

/// Test: performance de décodage de HandshakeAck
#[test]
fn test_handshake_ack_decoding_performance() {
    let msg = TsnMessage::HandshakeAck {
        accepted: true,
        timestamp_ns: 1234567890,
        your_node_id: [42u8; 32],
    };
    
    let encoded = encode_message(&msg).expect("Encoding should succeed");
    
    let iterations = 50_000;
    let start = Instant::now();
    
    for _ in 0..iterations {
        let mut buf = BytesMut::from(encoded.as_ref());
        let _decoded = decode_message(&mut buf)
            .expect("Decoding should succeed")
            .expect("Should have a message");
    }
    
    let duration = start.elapsed();
    let ops_per_sec = iterations as f64 / duration.as_secs_f64();
    
    println!("HandshakeAck decoding: {:.0} ops/sec", ops_per_sec);
    
    assert!(ops_per_sec > 20_000.0, "HandshakeAck decoding too slow: {:.0} ops/sec", ops_per_sec);
}

/// Test: performance avec différentes tailles de capabilities
#[test]
fn test_capabilities_size_performance() {
    let capability_counts = vec![0, 1, 5, 10, 50, 100];
    
    for cap_count in capability_counts {
        let mut capabilities = Vec::new();
        for i in 0..cap_count {
            match i % 5 {
                0 => capabilities.push(Capability::HighBandwidth),
                1 => capabilities.push(Capability::LowLatency),
                2 => capabilities.push(Capability::TimeSynchronization),
                3 => capabilities.push(Capability::Forwarding),
                4 => capabilities.push(Capability::MaxPeers(i as u32)),
                _ => unreachable!(),
            }
        }
        
        let handshake = HandshakeData {
            version: ProtocolVersion(1, 0),
            timestamp_ns: 1234567890,
            capabilities,
            node_id: [42u8; 32],
            listen_port: 9333,
        };

        let msg = TsnMessage::Handshake(handshake);
        
        let iterations = 1_000;
        let start = Instant::now();
        
        for _ in 0..iterations {
            let encoded = encode_message(&msg).expect("Encoding should succeed");
            let mut buf = BytesMut::from(encoded.as_ref());
            let _decoded = decode_message(&mut buf)
                .expect("Decoding should succeed")
                .expect("Should have a message");
        }
        
        let duration = start.elapsed();
        let ops_per_sec = iterations as f64 / duration.as_secs_f64();
        
        println!("Capabilities count {}: {:.0} roundtrips/sec", cap_count, ops_per_sec);
        
        // Performance devrait rester raisonnable même avec beaucoup de capabilities
        assert!(ops_per_sec > 100.0, "Too slow with {} capabilities: {:.0} ops/sec", cap_count, ops_per_sec);
    }
}

/// Test: performance de traitement de messages en lot
#[test]
fn test_batch_message_processing() {
    let messages = vec![
        TsnMessage::Handshake(HandshakeData {
            version: ProtocolVersion(1, 0),
            timestamp_ns: 1234567890,
            capabilities: vec![Capability::Forwarding],
            node_id: [1u8; 32],
            listen_port: 9333,
        }),
        TsnMessage::HandshakeAck {
            accepted: true,
            timestamp_ns: 1234567891,
            your_node_id: [2u8; 32],
        },
        TsnMessage::HandshakeAck {
            accepted: false,
            timestamp_ns: 1234567892,
            your_node_id: [3u8; 32],
        },
    ];
    
    // Encode tous les messages
    let mut encoded_messages = Vec::new();
    for msg in &messages {
        let encoded = encode_message(msg).expect("Encoding should succeed");
        encoded_messages.push(encoded);
    }
    
    let iterations = 1_000;
    let start = Instant::now();
    
    for _ in 0..iterations {
        for encoded in &encoded_messages {
            let mut buf = BytesMut::from(encoded.as_ref());
            let _decoded = decode_message(&mut buf)
                .expect("Decoding should succeed")
                .expect("Should have a message");
        }
    }
    
    let duration = start.elapsed();
    let total_messages = iterations * messages.len();
    let msgs_per_sec = total_messages as f64 / duration.as_secs_f64();
    
    println!("Batch processing: {:.0} messages/sec", msgs_per_sec);
    
    assert!(msgs_per_sec > 10_000.0, "Batch processing too slow: {:.0} msgs/sec", msgs_per_sec);
}

/// Test: performance avec buffers de différentes tailles
#[test]
fn test_buffer_size_performance() {
    let handshake = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: 1234567890,
        capabilities: vec![Capability::Forwarding],
        node_id: [42u8; 32],
        listen_port: 9333,
    };

    let msg = TsnMessage::Handshake(handshake);
    let encoded = encode_message(&msg).expect("Encoding should succeed");
    
    // Test avec différentes tailles de buffer initial
    let buffer_sizes = vec![64, 256, 1024, 4096];
    
    for buffer_size in buffer_sizes {
        let iterations = 5_000;
        let start = Instant::now();
        
        for _ in 0..iterations {
            let mut buf = BytesMut::with_capacity(buffer_size);
            buf.extend_from_slice(&encoded);
            
            let _decoded = decode_message(&mut buf)
                .expect("Decoding should succeed")
                .expect("Should have a message");
        }
        
        let duration = start.elapsed();
        let ops_per_sec = iterations as f64 / duration.as_secs_f64();
        
        println!("Buffer size {}: {:.0} ops/sec", buffer_size, ops_per_sec);
        
        assert!(ops_per_sec > 1_000.0, "Too slow with buffer size {}: {:.0} ops/sec", buffer_size, ops_per_sec);
    }
}

/// Test: performance de création de node_id uniques
#[test]
fn test_node_id_generation_performance() {
    let iterations = 100_000;
    let start = Instant::now();
    
    let mut node_ids = Vec::with_capacity(iterations);
    
    for i in 0..iterations {
        let mut node_id = [0u8; 32];
        // Simule une génération de node_id (ici simplifiée)
        node_id[0..4].copy_from_slice(&(i as u32).to_be_bytes());
        node_id[4..8].copy_from_slice(&(i as u32).to_le_bytes());
        node_ids.push(node_id);
    }
    
    let duration = start.elapsed();
    let ops_per_sec = iterations as f64 / duration.as_secs_f64();
    
    println!("Node ID generation: {:.0} ops/sec", ops_per_sec);
    
    // Vérification d'unicité (échantillon)
    let sample_size = 1000.min(iterations);
    let mut unique_ids = std::collections::HashSet::new();
    for i in 0..sample_size {
        unique_ids.insert(node_ids[i]);
    }
    
    assert_eq!(unique_ids.len(), sample_size, "Node IDs should be unique");
    assert!(ops_per_sec > 50_000.0, "Node ID generation too slow: {:.0} ops/sec", ops_per_sec);
}

/// Test: performance de validation de timestamps
#[test]
fn test_timestamp_validation_performance() {
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    
    let timestamps = vec![
        current_time - 1_000_000_000, // 1 seconde dans le passé
        current_time,
        current_time + 1_000_000_000, // 1 seconde dans le futur
        current_time + 10_000_000_000, // 10 secondes dans le futur (invalide)
    ];
    
    let iterations = 100_000;
    let start = Instant::now();
    
    let mut valid_count = 0;
    
    for _ in 0..iterations {
        for &timestamp in &timestamps {
            // Simule une validation de timestamp
            let time_diff = if timestamp > current_time {
                timestamp - current_time
            } else {
                current_time - timestamp
            };
            
            // Accepte les timestamps dans une fenêtre de 5 secondes
            if time_diff <= 5_000_000_000 {
                valid_count += 1;
            }
        }
    }
    
    let duration = start.elapsed();
    let validations_per_sec = (iterations * timestamps.len()) as f64 / duration.as_secs_f64();
    
    println!("Timestamp validation: {:.0} validations/sec", validations_per_sec);
    println!("Valid timestamps: {}/{}", valid_count, iterations * timestamps.len());
    
    assert!(validations_per_sec > 1_000_000.0, "Timestamp validation too slow: {:.0} validations/sec", validations_per_sec);
}

/// Test: performance de sérialisation avec différents types de capabilities
#[test]
fn test_capability_serialization_performance() {
    let capability_types = vec![
        Capability::HighBandwidth,
        Capability::LowLatency,
        Capability::TimeSynchronization,
        Capability::Forwarding,
        Capability::MaxPeers(0),
        Capability::MaxPeers(1000),
        Capability::MaxPeers(u32::MAX),
    ];
    
    for capability in capability_types {
        let handshake = HandshakeData {
            version: ProtocolVersion(1, 0),
            timestamp_ns: 1234567890,
            capabilities: vec![capability.clone()],
            node_id: [42u8; 32],
            listen_port: 9333,
        };

        let msg = TsnMessage::Handshake(handshake);
        
        let iterations = 10_000;
        let start = Instant::now();
        
        for _ in 0..iterations {
            let encoded = encode_message(&msg).expect("Encoding should succeed");
            let mut buf = BytesMut::from(encoded.as_ref());
            let _decoded = decode_message(&mut buf)
                .expect("Decoding should succeed")
                .expect("Should have a message");
        }
        
        let duration = start.elapsed();
        let ops_per_sec = iterations as f64 / duration.as_secs_f64();
        
        println!("Capability {:?}: {:.0} roundtrips/sec", capability, ops_per_sec);
        
        assert!(ops_per_sec > 5_000.0, "Too slow for capability {:?}: {:.0} ops/sec", capability, ops_per_sec);
    }
}

/// Benchmark: comparaison des performances entre types de messages
#[test]
fn test_message_type_performance_comparison() {
    let handshake_msg = TsnMessage::Handshake(HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: 1234567890,
        capabilities: vec![Capability::Forwarding],
        node_id: [42u8; 32],
        listen_port: 9333,
    });
    
    let ack_msg = TsnMessage::HandshakeAck {
        accepted: true,
        timestamp_ns: 1234567890,
        your_node_id: [42u8; 32],
    };
    
    let messages = vec![
        ("Handshake", handshake_msg),
        ("HandshakeAck", ack_msg),
    ];
    
    for (name, msg) in messages {
        let iterations = 10_000;
        let start = Instant::now();
        
        for _ in 0..iterations {
            let encoded = encode_message(&msg).expect("Encoding should succeed");
            let mut buf = BytesMut::from(encoded.as_ref());
            let _decoded = decode_message(&mut buf)
                .expect("Decoding should succeed")
                .expect("Should have a message");
        }
        
        let duration = start.elapsed();
        let ops_per_sec = iterations as f64 / duration.as_secs_f64();
        
        println!("{} roundtrip: {:.0} ops/sec", name, ops_per_sec);
        
        assert!(ops_per_sec > 5_000.0, "{} too slow: {:.0} ops/sec", name, ops_per_sec);
    }
}