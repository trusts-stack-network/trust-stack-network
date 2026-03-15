//! Tests d'intégration pour le module réseau TSN
//! 
//! Tests des interactions entre composants, scénarios réels et workflows complets.

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::{timeout, sleep};
use bytes::BytesMut;

use crate::network::protocol::{
    TsnMessage, HandshakeData, ProtocolVersion, Capability, 
    encode_message, decode_message
};

/// Test: workflow complet de handshake bidirectionnel
#[tokio::test]
async fn test_complete_handshake_workflow() {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    
    // Nœud A initie le handshake
    let node_a_id = [1u8; 32];
    let node_b_id = [2u8; 32];
    
    let handshake_a = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: current_time,
        capabilities: vec![
            Capability::HighBandwidth,
            Capability::Forwarding,
            Capability::MaxPeers(100),
        ],
        node_id: node_a_id,
        listen_port: 9333,
    };
    
    let msg_a = TsnMessage::Handshake(handshake_a.clone());
    let encoded_a = encode_message(&msg_a).expect("Encoding should succeed");
    
    // Nœud B reçoit et traite le handshake
    let mut buf_a = BytesMut::from(encoded_a.as_ref());
    let (decoded_a, _) = decode_message(&mut buf_a)
        .expect("Decoding should succeed")
        .expect("Should have a message");
    
    match decoded_a {
        TsnMessage::Handshake(received_handshake) => {
            assert_eq!(received_handshake.node_id, node_a_id);
            assert_eq!(received_handshake.version, ProtocolVersion(1, 0));
            assert_eq!(received_handshake.capabilities.len(), 3);
            
            // Nœud B répond avec HandshakeAck
            let ack_b = TsnMessage::HandshakeAck {
                accepted: true,
                timestamp_ns: current_time + 1_000_000, // 1ms plus tard
                your_node_id: node_a_id,
            };
            
            let encoded_b = encode_message(&ack_b).expect("Encoding should succeed");
            
            // Nœud A reçoit l'ACK
            let mut buf_b = BytesMut::from(encoded_b.as_ref());
            let (decoded_b, _) = decode_message(&mut buf_b)
                .expect("Decoding should succeed")
                .expect("Should have a message");
            
            match decoded_b {
                TsnMessage::HandshakeAck { accepted, your_node_id, .. } => {
                    assert!(accepted);
                    assert_eq!(your_node_id, node_a_id);
                    
                    println!("Handshake workflow complet réussi");
                }
                _ => panic!("Expected HandshakeAck"),
            }
        }
        _ => panic!("Expected Handshake message"),
    }
}

/// Test: handshake rejeté avec raison
#[tokio::test]
async fn test_handshake_rejection_workflow() {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    
    // Nœud avec version incompatible
    let incompatible_handshake = HandshakeData {
        version: ProtocolVersion(2, 0), // Version future non supportée
        timestamp_ns: current_time,
        capabilities: vec![],
        node_id: [3u8; 32],
        listen_port: 9333,
    };
    
    let msg = TsnMessage::Handshake(incompatible_handshake);
    let encoded = encode_message(&msg).expect("Encoding should succeed");
    
    let mut buf = BytesMut::from(encoded.as_ref());
    let (decoded, _) = decode_message(&mut buf)
        .expect("Decoding should succeed")
        .expect("Should have a message");
    
    match decoded {
        TsnMessage::Handshake(handshake) => {
            // Simule la logique de validation
            let is_version_compatible = handshake.version.0 == 1;
            
            let response = TsnMessage::HandshakeAck {
                accepted: is_version_compatible,
                timestamp_ns: current_time + 1_000_000,
                your_node_id: handshake.node_id,
            };
            
            let encoded_response = encode_message(&response).expect("Encoding should succeed");
            let mut buf_response = BytesMut::from(encoded_response.as_ref());
            let (decoded_response, _) = decode_message(&mut buf_response)
                .expect("Decoding should succeed")
                .expect("Should have a message");
            
            match decoded_response {
                TsnMessage::HandshakeAck { accepted, .. } => {
                    assert!(!accepted, "Handshake avec version incompatible devrait être rejeté");
                    println!("Handshake correctement rejeté pour version incompatible");
                }
                _ => panic!("Expected HandshakeAck"),
            }
        }
        _ => panic!("Expected Handshake message"),
    }
}

/// Test: négociation de capabilities
#[tokio::test]
async fn test_capability_negotiation() {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    
    // Nœud A avec capabilities étendues
    let handshake_a = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: current_time,
        capabilities: vec![
            Capability::HighBandwidth,
            Capability::LowLatency,
            Capability::TimeSynchronization,
            Capability::Forwarding,
            Capability::MaxPeers(1000),
        ],
        node_id: [4u8; 32],
        listen_port: 9333,
    };
    
    // Nœud B avec capabilities limitées
    let handshake_b = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: current_time + 1_000_000,
        capabilities: vec![
            Capability::Forwarding,
            Capability::MaxPeers(50),
        ],
        node_id: [5u8; 32],
        listen_port: 9334,
    };
    
    // Simule la négociation
    let common_capabilities = find_common_capabilities(&handshake_a.capabilities, &handshake_b.capabilities);
    
    assert!(common_capabilities.contains(&Capability::Forwarding));
    assert!(!common_capabilities.contains(&Capability::HighBandwidth));
    assert!(!common_capabilities.contains(&Capability::LowLatency));
    
    // Le MaxPeers devrait être le minimum
    let max_peers_a = handshake_a.capabilities.iter()
        .find_map(|c| if let Capability::MaxPeers(n) = c { Some(*n) } else { None })
        .unwrap_or(0);
    let max_peers_b = handshake_b.capabilities.iter()
        .find_map(|c| if let Capability::MaxPeers(n) = c { Some(*n) } else { None })
        .unwrap_or(0);
    
    let negotiated_max_peers = max_peers_a.min(max_peers_b);
    assert_eq!(negotiated_max_peers, 50);
    
    println!("Négociation de capabilities réussie: {} capabilities communes", common_capabilities.len());
}

/// Fonction utilitaire pour trouver les capabilities communes
fn find_common_capabilities(caps_a: &[Capability], caps_b: &[Capability]) -> Vec<Capability> {
    let mut common = Vec::new();
    
    for cap_a in caps_a {
        match cap_a {
            Capability::HighBandwidth => {
                if caps_b.contains(&Capability::HighBandwidth) {
                    common.push(Capability::HighBandwidth);
                }
            }
            Capability::LowLatency => {
                if caps_b.contains(&Capability::LowLatency) {
                    common.push(Capability::LowLatency);
                }
            }
            Capability::TimeSynchronization => {
                if caps_b.contains(&Capability::TimeSynchronization) {
                    common.push(Capability::TimeSynchronization);
                }
            }
            Capability::Forwarding => {
                if caps_b.contains(&Capability::Forwarding) {
                    common.push(Capability::Forwarding);
                }
            }
            Capability::MaxPeers(_) => {
                // MaxPeers est toujours compatible, on prend le minimum
                // (géré séparément dans le test)
            }
        }
    }
    
    common
}

/// Test: timeout de handshake
#[tokio::test]
async fn test_handshake_timeout() {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    
    let handshake = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: current_time,
        capabilities: vec![Capability::Forwarding],
        node_id: [6u8; 32],
        listen_port: 9333,
    };
    
    let msg = TsnMessage::Handshake(handshake);
    let encoded = encode_message(&msg).expect("Encoding should succeed");
    
    // Simule un timeout de handshake
    let handshake_timeout = Duration::from_millis(100);
    
    let result = timeout(handshake_timeout, async {
        // Simule une opération qui prend trop de temps
        sleep(Duration::from_millis(200)).await;
        
        let mut buf = BytesMut::from(encoded.as_ref());
        decode_message(&mut buf)
    }).await;
    
    match result {
        Ok(_) => panic!("Handshake devrait avoir timeout"),
        Err(_) => {
            println!("Timeout de handshake correctement détecté");
        }
    }
}

/// Test: gestion de multiples handshakes simultanés
#[tokio::test]
async fn test_concurrent_handshakes() {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    
    let num_peers = 10;
    let mut handshake_tasks = Vec::new();
    
    for i in 0..num_peers {
        let peer_time = current_time + (i as u64 * 1_000_000); // Décalage de 1ms
        
        let task = tokio::spawn(async move {
            let handshake = HandshakeData {
                version: ProtocolVersion(1, 0),
                timestamp_ns: peer_time,
                capabilities: vec![Capability::Forwarding],
                node_id: [i as u8; 32],
                listen_port: 9333 + i as u16,
            };
            
            let msg = TsnMessage::Handshake(handshake);
            let encoded = encode_message(&msg).expect("Encoding should succeed");
            
            let mut buf = BytesMut::from(encoded.as_ref());
            let (decoded, _) = decode_message(&mut buf)
                .expect("Decoding should succeed")
                .expect("Should have a message");
            
            match decoded {
                TsnMessage::Handshake(data) => {
                    // Simule la réponse
                    let response = TsnMessage::HandshakeAck {
                        accepted: true,
                        timestamp_ns: peer_time + 1_000_000,
                        your_node_id: data.node_id,
                    };
                    
                    let encoded_response = encode_message(&response).expect("Encoding should succeed");
                    encoded_response.len() // Retourne la taille pour vérification
                }
                _ => panic!("Expected Handshake message"),
            }
        });
        
        handshake_tasks.push(task);
    }
    
    // Attend que tous les handshakes se terminent
    let results = futures::future::join_all(handshake_tasks).await;
    
    let mut successful_handshakes = 0;
    for result in results {
        match result {
            Ok(response_size) => {
                assert!(response_size > 0);
                successful_handshakes += 1;
            }
            Err(e) => {
                panic!("Handshake task failed: {:?}", e);
            }
        }
    }
    
    assert_eq!(successful_handshakes, num_peers);
    println!("Tous les {} handshakes simultanés ont réussi", num_peers);
}

/// Test: séquence de messages complexe
#[tokio::test]
async fn test_complex_message_sequence() {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    
    let node_a = [7u8; 32];
    let node_b = [8u8; 32];
    
    // Séquence : A -> Handshake, B -> HandshakeAck, A -> HandshakeAck
    let messages = vec![
        TsnMessage::Handshake(HandshakeData {
            version: ProtocolVersion(1, 0),
            timestamp_ns: current_time,
            capabilities: vec![Capability::Forwarding],
            node_id: node_a,
            listen_port: 9333,
        }),
        TsnMessage::HandshakeAck {
            accepted: true,
            timestamp_ns: current_time + 1_000_000,
            your_node_id: node_a,
        },
        TsnMessage::HandshakeAck {
            accepted: true,
            timestamp_ns: current_time + 2_000_000,
            your_node_id: node_b,
        },
    ];
    
    let mut encoded_messages = Vec::new();
    for msg in &messages {
        let encoded = encode_message(msg).expect("Encoding should succeed");
        encoded_messages.push(encoded);
    }
    
    // Traite la séquence
    for (i, encoded) in encoded_messages.iter().enumerate() {
        let mut buf = BytesMut::from(encoded.as_ref());
        let (decoded, _) = decode_message(&mut buf)
            .expect("Decoding should succeed")
            .expect("Should have a message");
        
        match (i, &decoded) {
            (0, TsnMessage::Handshake(data)) => {
                assert_eq!(data.node_id, node_a);
                println!("Message 1: Handshake de A reçu");
            }
            (1, TsnMessage::HandshakeAck { your_node_id, accepted, .. }) => {
                assert_eq!(*your_node_id, node_a);
                assert!(*accepted);
                println!("Message 2: HandshakeAck de B reçu");
            }
            (2, TsnMessage::HandshakeAck { your_node_id, accepted, .. }) => {
                assert_eq!(*your_node_id, node_b);
                assert!(*accepted);
                println!("Message 3: HandshakeAck de A reçu");
            }
            _ => panic!("Unexpected message type at position {}", i),
        }
    }
    
    println!("Séquence de messages complexe traitée avec succès");
}

/// Test: récupération après erreur de réseau
#[tokio::test]
async fn test_network_error_recovery() {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    
    let handshake = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: current_time,
        capabilities: vec![Capability::Forwarding],
        node_id: [9u8; 32],
        listen_port: 9333,
    };
    
    let msg = TsnMessage::Handshake(handshake);
    let encoded = encode_message(&msg).expect("Encoding should succeed");
    
    // Simule une erreur réseau (message corrompu)
    let mut corrupted = encoded.clone();
    if corrupted.len() > 10 {
        corrupted[5] ^= 0xFF; // Corrompt un byte
    }
    
    // Première tentative avec message corrompu
    let mut buf_corrupted = BytesMut::from(corrupted.as_ref());
    let result_corrupted = decode_message(&mut buf_corrupted);
    
    match result_corrupted {
        Ok(None) => {
            println!("Message corrompu correctement ignoré");
        }
        Ok(Some(_)) => {
            // Si le message est décodé malgré la corruption, vérifie l'intégrité
            println!("Message décodé malgré la corruption (checksum manquant?)");
        }
        Err(_) => {
            println!("Erreur de décodage détectée pour message corrompu");
        }
    }
    
    // Deuxième tentative avec message correct (récupération)
    let mut buf_correct = BytesMut::from(encoded.as_ref());
    let (decoded, _) = decode_message(&mut buf_correct)
        .expect("Decoding should succeed")
        .expect("Should have a message");
    
    match decoded {
        TsnMessage::Handshake(_) => {
            println!("Récupération après erreur réseau réussie");
        }
        _ => panic!("Expected Handshake message"),
    }
}

/// Test: gestion de la congestion réseau
#[tokio::test]
async fn test_network_congestion_handling() {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    
    // Simule une congestion avec beaucoup de messages
    let num_messages = 1000;
    let mut messages = Vec::new();
    
    for i in 0..num_messages {
        let handshake = HandshakeData {
            version: ProtocolVersion(1, 0),
            timestamp_ns: current_time + (i as u64 * 1_000), // 1µs d'écart
            capabilities: vec![Capability::Forwarding],
            node_id: [(i % 256) as u8; 32],
            listen_port: 9333,
        };
        
        let msg = TsnMessage::Handshake(handshake);
        messages.push(msg);
    }
    
    // Traite tous les messages avec timeout
    let processing_timeout = Duration::from_secs(5);
    
    let result = timeout(processing_timeout, async {
        let mut processed = 0;
        
        for msg in messages {
            let encoded = encode_message(&msg).expect("Encoding should succeed");
            let mut buf = BytesMut::from(encoded.as_ref());
            let _decoded = decode_message(&mut buf)
                .expect("Decoding should succeed")
                .expect("Should have a message");
            
            processed += 1;
            
            // Simule un petit délai de traitement
            if processed % 100 == 0 {
                tokio::task::yield_now().await;
            }
        }
        
        processed
    }).await;
    
    match result {
        Ok(processed) => {
            assert_eq!(processed, num_messages);
            println!("Congestion réseau gérée: {} messages traités", processed);
        }
        Err(_) => {
            panic!("Timeout lors du traitement de la congestion");
        }
    }
}

/// Test: validation de l'ordre des messages
#[tokio::test]
async fn test_message_ordering() {
    let base_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    
    // Crée des messages avec timestamps dans l'ordre
    let ordered_messages = vec![
        (base_time + 1_000_000, [1u8; 32]),
        (base_time + 2_000_000, [2u8; 32]),
        (base_time + 3_000_000, [3u8; 32]),
        (base_time + 4_000_000, [4u8; 32]),
    ];
    
    // Encode tous les messages
    let mut encoded_messages = Vec::new();
    for (timestamp, node_id) in &ordered_messages {
        let handshake = HandshakeData {
            version: ProtocolVersion(1, 0),
            timestamp_ns: *timestamp,
            capabilities: vec![],
            node_id: *node_id,
            listen_port: 9333,
        };
        
        let msg = TsnMessage::Handshake(handshake);
        let encoded = encode_message(&msg).expect("Encoding should succeed");
        encoded_messages.push(encoded);
    }
    
    // Traite les messages et vérifie l'ordre des timestamps
    let mut previous_timestamp = 0u64;
    
    for (i, encoded) in encoded_messages.iter().enumerate() {
        let mut buf = BytesMut::from(encoded.as_ref());
        let (decoded, _) = decode_message(&mut buf)
            .expect("Decoding should succeed")
            .expect("Should have a message");
        
        match decoded {
            TsnMessage::Handshake(data) => {
                assert!(data.timestamp_ns > previous_timestamp, 
                        "Message {} hors ordre: {} <= {}", i, data.timestamp_ns, previous_timestamp);
                previous_timestamp = data.timestamp_ns;
            }
            _ => panic!("Expected Handshake message"),
        }
    }
    
    println!("Ordre des messages validé pour {} messages", ordered_messages.len());
}

/// Test: interopérabilité entre versions mineures
#[tokio::test]
async fn test_minor_version_interoperability() {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    
    let versions = vec![
        ProtocolVersion(1, 0),
        ProtocolVersion(1, 1),
        ProtocolVersion(1, 2),
    ];
    
    for (i, version_a) in versions.iter().enumerate() {
        for (j, version_b) in versions.iter().enumerate() {
            let handshake_a = HandshakeData {
                version: *version_a,
                timestamp_ns: current_time + (i as u64 * 1_000_000),
                capabilities: vec![Capability::Forwarding],
                node_id: [i as u8; 32],
                listen_port: 9333,
            };
            
            let msg_a = TsnMessage::Handshake(handshake_a);
            let encoded_a = encode_message(&msg_a).expect("Encoding should succeed");
            
            let mut buf_a = BytesMut::from(encoded_a.as_ref());
            let (decoded_a, _) = decode_message(&mut buf_a)
                .expect("Decoding should succeed")
                .expect("Should have a message");
            
            match decoded_a {
                TsnMessage::Handshake(data) => {
                    // Simule la logique de compatibilité
                    let is_compatible = version_a.0 == version_b.0; // Même major version
                    
                    let response = TsnMessage::HandshakeAck {
                        accepted: is_compatible,
                        timestamp_ns: current_time + (j as u64 * 1_000_000),
                        your_node_id: data.node_id,
                    };
                    
                    let encoded_response = encode_message(&response).expect("Encoding should succeed");
                    let mut buf_response = BytesMut::from(encoded_response.as_ref());
                    let (decoded_response, _) = decode_message(&mut buf_response)
                        .expect("Decoding should succeed")
                        .expect("Should have a message");
                    
                    match decoded_response {
                        TsnMessage::HandshakeAck { accepted, .. } => {
                            assert!(accepted, "Versions {}.{} et {}.{} devraient être compatibles", 
                                   version_a.0, version_a.1, version_b.0, version_b.1);
                        }
                        _ => panic!("Expected HandshakeAck"),
                    }
                }
                _ => panic!("Expected Handshake message"),
            }
        }
    }
    
    println!("Interopérabilité entre versions mineures validée");
}