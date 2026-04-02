#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use tsn::network::message::{TsnMessage, MessagePayload, HandshakeMessage, DiscoveryMessage, DataMessage, TsnParams};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::collections::HashSet;

#[derive(Arbitrary, Debug)]
struct FuzzNetworkInput {
    data: Vec<u8>,
    test_handshake_attacks: bool,
    test_discovery_dos: bool,
    test_signature_bypass: bool,
    test_priority_abuse: bool,
    test_oversized_data: bool,
}

fuzz_target!(|input: FuzzNetworkInput| {
    // Test 1: Désérialisation basique - ne doit jamais crasher
    if let Ok(msg) = bincode::deserialize::<TsnMessage>(&input.data) {
        // INVARIANT CRITIQUE: Priorité doit être 0-7
        if msg.priority > 7 {
            panic!("Invalid priority detected: {} (max: 7)", msg.priority);
        }
        
        // INVARIANT CRITIQUE: Version supportée
        if msg.version == 0 || msg.version > 10 {
            panic!("Suspicious protocol version: {}", msg.version);
        }
        
        // Test 2: Attaques handshake
        if input.test_handshake_attacks {
            if let MessagePayload::Handshake(handshake) = &msg.payload {
                match handshake {
                    HandshakeMessage::Hello { nonce, public_key, timestamp, tsn_params } => {
                        // SECURITE: Nonce ne doit jamais être nul (replay attack)
                        if nonce == &[0u8; 32] {
                            panic!("Zero nonce detected - potential replay attack");
                        }
                        
                        // SECURITE: Public key ne doit pas être zero
                        if public_key == &[0u8; 32] {
                            panic!("Zero public key detected");
                        }
                        
                        // SECURITE: Timestamp raisonnable (pas plus de 1h dans le futur)
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        if *timestamp > now + 3600 {
                            panic!("Timestamp too far in future: {} vs {}", timestamp, now);
                        }
                        
                        // SECURITE: TSN params valides
                        for &priority in &tsn_params.priority_classes {
                            if priority > 7 {
                                panic!("Invalid TSN priority class: {}", priority);
                            }
                        }
                        
                        // SECURITE: Bandwidth raisonnable (max 100 Gbps)
                        if tsn_params.max_bandwidth > 100_000_000 {
                            panic!("Bandwidth too high: {} kbps", tsn_params.max_bandwidth);
                        }
                    },
                    HandshakeMessage::Challenge { nonce_signature, echo_timestamp, timestamp } => {
                        // SECURITE: Signature ne doit pas être nulle
                        if nonce_signature == &[0u8; 64] {
                            panic!("Zero signature in challenge");
                        }
                        
                        // SECURITE: Echo timestamp doit être cohérent
                        if echo_timestamp > timestamp {
                            panic!("Echo timestamp after current timestamp");
                        }
                    },
                    HandshakeMessage::Ack { session_id, bandwidth_alloc, max_latency_us } => {
                        // SECURITE: Session ID ne doit pas être nul
                        if session_id == &[0u8; 16] {
                            panic!("Zero session ID");
                        }
                        
                        // SECURITE: Bandwidth allocation raisonnable
                        if *bandwidth_alloc > 100_000_000 {
                            panic!("Bandwidth allocation too high: {} kbps", bandwidth_alloc);
                        }
                        
                        // SECURITE: Latency raisonnable (max 1 seconde)
                        if *max_latency_us > 1_000_000 {
                            panic!("Max latency too high: {} μs", max_latency_us);
                        }
                    },
                    HandshakeMessage::Reject { reason } => {
                        // SECURITE: Reason ne doit pas être trop longue (DoS)
                        if reason.len() > 1024 {
                            panic!("Reject reason too long: {} bytes", reason.len());
                        }
                    }
                }
            }
        }
        
        // Test 3: Attaques discovery DoS
        if input.test_discovery_dos {
            if let MessagePayload::Discovery(discovery) = &msg.payload {
                // SECURITE: Node ID ne doit pas être nul
                if discovery.node_id == [0u8; 32] {
                    panic!("Zero node ID detected");
                }
                
                // SECURITE: Listen addr ne doit pas être trop long
                if discovery.listen_addr.len() > 255 {
                    panic!("Listen address too long: {} bytes", discovery.listen_addr.len());
                }
                
                // SECURITE: Capabilities ne doit pas être trop nombreuses (DoS)
                if discovery.capabilities.len() > 100 {
                    panic!("Too many capabilities: {}", discovery.capabilities.len());
                }
                
                // SECURITE: Chaque capability ne doit pas être trop longue
                for cap in &discovery.capabilities {
                    if cap.len() > 64 {
                        panic!("Capability string too long: {} bytes", cap.len());
                    }
                }
                
                // SECURITE: Timestamp cohérent
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if discovery.timestamp > now + 300 {
                    panic!("Discovery timestamp too far in future");
                }
            }
        }
        
        // Test 4: Attaques signature bypass
        if input.test_signature_bypass {
            if let Some(signature) = &msg.signature {
                // SECURITE: Signature ne doit pas être nulle
                if signature == &[0u8; 64] {
                    panic!("Zero signature detected");
                }
                
                // SECURITE: Tenter verification avec clé aléatoire (doit échouer)
                let random_key_bytes = [1u8; 32];
                if let Ok(verifying_key) = VerifyingKey::from_bytes(&random_key_bytes) {
                    if msg.verify(&verifying_key).is_ok() {
                        panic!("Signature verification passed with wrong key!");
                    }
                }
            }
        }
        
        // Test 5: Attaques data stream
        if input.test_oversized_data {
            if let MessagePayload::Data(data) = &msg.payload {
                // SECURITE: Data ne doit pas être trop large (DoS)
                if data.data.len() > 65536 {
                    panic!("Data message too large: {} bytes", data.data.len());
                }
                
                // SECURITE: Stream ID raisonnable
                if data.stream_id == 0 {
                    panic!("Zero stream ID detected");
                }
                
                // SECURITE: Deadline cohérente si présente
                if let Some(deadline) = data.deadline_ns {
                    let now_ns = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64;
                    
                    // Deadline ne doit pas être dans le passé lointain
                    if deadline < now_ns.saturating_sub(60_000_000_000) { // -60s
                        panic!("Data deadline too far in past");
                    }
                    
                    // Deadline ne doit pas être dans le futur lointain
                    if deadline > now_ns + 3600_000_000_000 { // +1h
                        panic!("Data deadline too far in future");
                    }
                }
            }
        }
    }
    
    // Test 6: Attaque par message tronqué
    if input.data.len() > 8 && input.data.len() < 100 {
        // Les messages tronqués ne doivent jamais causer de panic
        let _ = bincode::deserialize::<TsnMessage>(&input.data);
    }
    
    // Test 7: Attaque par message surdimensionné 
    if input.data.len() > 100_000 {
        // DoS protection: parsing doit échouer rapidement
        let start = std::time::Instant::now();
        let _ = bincode::deserialize::<TsnMessage>(&input.data);
        let elapsed = start.elapsed();
        
        if elapsed.as_millis() > 50 {
            panic!("Oversized message parsing too slow: {}ms", elapsed.as_millis());
        }
    }
});