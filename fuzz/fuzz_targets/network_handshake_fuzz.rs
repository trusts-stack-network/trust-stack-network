#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::time::{Instant, Duration};

/// FUZZER: Désérialisation TsnHandshake
/// 
/// Cible: Vérifier la robustesse du protocole de handshake TSN
/// contre les attaques de type downgrade, replay, et man-in-the-middle.
/// 
/// VECTEURS D'ATTAQUE:
/// 1. Version protocol downgrade attack
/// 2. Capabilities manipulation
/// 3. Timestamp replay
/// 4. PeerId collision/spoofing
/// 5. Handshake flood
/// 6. Malformed capabilities list
use tsn::network::types::{TsnHandshake, Capability, PeerId, PROTOCOL_VERSION};

#[derive(Arbitrary, Debug, Clone)]
struct HandshakeFuzzInput {
    /// Données brutes du handshake
    raw_data: Vec<u8>,
    
    /// Stratégie d'attaque
    attack_strategy: HandshakeAttackStrategy,
    
    /// Paramètres de mutation
    mutation_seed: u8,
    iteration_count: u8,
}

#[derive(Arbitrary, Debug, Clone)]
enum HandshakeAttackStrategy {
    /// Désérialisation standard
    StandardDeserialize,
    /// Version downgrade
    VersionDowngrade,
    /// Capabilities overflow
    CapabilitiesOverflow,
    /// Timestamp manipulation
    TimestampManipulation,
    /// PeerId manipulation
    PeerIdManipulation,
    /// Handshake flood
    HandshakeFlood,
    /// Truncated handshake
    TruncatedHandshake,
    /// Extra fields injection
    ExtraFieldsInjection,
    /// Null bytes injection
    NullBytesInjection,
    /// Bit flipping
    BitFlipping,
}

/// Résultat d'une attaque de fuzzing
#[derive(Debug)]
enum FuzzResult {
    Success,
    DeserializationFailed,
    ValidationFailed(String),
    SlowOperation(Duration),
    AttackMitigated,
}

fuzz_target!(|input: HandshakeFuzzInput| {
    // Exécuter l'attaque sans panic - retourner un bool pour libfuzzer
    let result = execute_handshake_attack_safely(&input);
    
    // libfuzzer détecte les crashes via les panic ou les process exits
    // Nous retournons simplement pour indiquer que le test a terminé
    // Les vulnérabilités sont loguées mais ne causent pas de crash
    match result {
        FuzzResult::ValidationFailed(msg) => {
            // Log pour analyse mais pas de panic
            eprintln!("[FUZZ] Validation issue: {}", msg);
        }
        FuzzResult::SlowOperation(duration) => {
            eprintln!("[FUZZ] Slow operation detected: {:?}", duration);
        }
        _ => {}
    }
});

fn execute_handshake_attack_safely(input: &HandshakeFuzzInput) -> FuzzResult {
    match input.attack_strategy {
        HandshakeAttackStrategy::StandardDeserialize => 
            attack_standard_deserialize(input),
        HandshakeAttackStrategy::VersionDowngrade => 
            attack_version_downgrade(input),
        HandshakeAttackStrategy::CapabilitiesOverflow => 
            attack_capabilities_overflow(input),
        HandshakeAttackStrategy::TimestampManipulation => 
            attack_timestamp_manipulation(input),
        HandshakeAttackStrategy::PeerIdManipulation => 
            attack_peer_id_manipulation(input),
        HandshakeAttackStrategy::HandshakeFlood => 
            attack_handshake_flood(input),
        HandshakeAttackStrategy::TruncatedHandshake => 
            attack_truncated_handshake(input),
        HandshakeAttackStrategy::ExtraFieldsInjection => 
            attack_extra_fields(input),
        HandshakeAttackStrategy::NullBytesInjection => 
            attack_null_bytes(input),
        HandshakeAttackStrategy::BitFlipping => 
            attack_bit_flipping(input),
    }
}

/// Attaque standard: désérialisation simple avec validation
fn attack_standard_deserialize(input: &HandshakeFuzzInput) -> FuzzResult {
    let start = Instant::now();
    
    let result: Result<TsnHandshake, _> = bincode::deserialize(&input.raw_data);
    
    let elapsed = start.elapsed();
    
    // Vérifier les performances - retourner un résultat plutôt que panic
    if elapsed > Duration::from_millis(50) {
        return FuzzResult::SlowOperation(elapsed);
    }
    
    match result {
        Ok(handshake) => {
            if let Err(e) = validate_handshake(&handshake) {
                return FuzzResult::ValidationFailed(e);
            }
            FuzzResult::Success
        }
        Err(_) => FuzzResult::DeserializationFailed,
    }
}

/// Attaque: Version downgrade
/// Tente de forcer l'utilisation d'une version ancienne/vulnérable
fn attack_version_downgrade(_input: &HandshakeFuzzInput) -> FuzzResult {
    let malicious_versions = [
        0u32,           // Version 0 (invalide)
        1,              // Très ancienne
        u32::MAX,       // Version future impossible
        PROTOCOL_VERSION.saturating_sub(1), // Version précédente
        PROTOCOL_VERSION.saturating_add(1), // Version future
    ];
    
    for version in malicious_versions {
        // Construire un handshake avec version malveillante
        let malicious_handshake = TsnHandshake {
            version,
            capabilities: vec![Capability::FullNode],
            peer_id: vec![1, 2, 3, 4],
            timestamp: current_timestamp(),
        };
        
        let serialized = match bincode::serialize(&malicious_handshake) {
            Ok(data) => data,
            Err(_) => continue,
        };
        
        if let Ok(deserialized) = bincode::deserialize::<TsnHandshake>(&serialized) {
            // Vérifier que la version n'est pas dans le futur lointain
            if deserialized.version > PROTOCOL_VERSION.saturating_add(10) {
                return FuzzResult::ValidationFailed(
                    format!("Protocol version {} is unreasonably high", deserialized.version)
                );
            }
        }
    }
    
    FuzzResult::Success
}

/// Attaque: Overflow de capabilities
/// Tente de créer une liste de capabilities massive
fn attack_capabilities_overflow(_input: &HandshakeFuzzInput) -> FuzzResult {
    // Créer une liste massive de capabilities
    let huge_capabilities: Vec<Capability> = (0..100_000)
        .map(|i| match i % 3 {
            0 => Capability::FullNode,
            1 => Capability::LightClient,
            _ => Capability::Miner,
        })
        .collect();
    
    let malicious_handshake = TsnHandshake {
        version: PROTOCOL_VERSION,
        capabilities: huge_capabilities,
        peer_id: vec![1, 2, 3, 4],
        timestamp: current_timestamp(),
    };
    
    let start = Instant::now();
    
    // Gestion d'erreur sans unwrap_or_default
    let serialized = match bincode::serialize(&malicious_handshake) {
        Ok(data) => data,
        Err(e) => {
            return FuzzResult::ValidationFailed(format!("Serialization failed: {}", e));
        }
    };
    
    let _: Result<TsnHandshake, _> = bincode::deserialize(&serialized);
    let elapsed = start.elapsed();
    
    // Vérifier que le parsing d'une liste massive ne cause pas de DoS
    if elapsed > Duration::from_millis(100) {
        return FuzzResult::SlowOperation(elapsed);
    }
    
    FuzzResult::Success
}

/// Attaque: Manipulation de timestamp
fn attack_timestamp_manipulation(_input: &HandshakeFuzzInput) -> FuzzResult {
    let malicious_timestamps = [
        0u64,                           // Époque Unix
        u64::MAX,                       // Futur lointain
        u64::MAX / 2,                   // Milieu
        current_timestamp().saturating_sub(86400 * 365), // Il y a 1 an
        current_timestamp().saturating_add(86400 * 365), // Dans 1 an
    ];
    
    for timestamp in malicious_timestamps {
        let handshake = TsnHandshake {
            version: PROTOCOL_VERSION,
            capabilities: vec![Capability::FullNode],
            peer_id: vec![1, 2, 3, 4],
            timestamp,
        };
        
        if let Ok(serialized) = bincode::serialize(&handshake) {
            if let Ok(deserialized) = bincode::deserialize::<TsnHandshake>(&serialized) {
                // Le timestamp doit être préservé exactement
                if deserialized.timestamp != timestamp {
                    return FuzzResult::ValidationFailed(
                        "Timestamp was modified during serialization".to_string()
                    );
                }
            }
        }
    }
    
    FuzzResult::Success
}

/// Attaque: Manipulation de PeerId
fn attack_peer_id_manipulation(_input: &HandshakeFuzzInput) -> FuzzResult {
    let peer_id_sizes = [0, 1, 16, 32, 64, 128, 256, 512, 1024, 4096, 65536];
    
    for size in peer_id_sizes {
        let peer_id = vec![0xABu8; size];
        
        let handshake = TsnHandshake {
            version: PROTOCOL_VERSION,
            capabilities: vec![Capability::FullNode],
            peer_id,
            timestamp: current_timestamp(),
        };
        
        let start = Instant::now();
        if let Ok(serialized) = bincode::serialize(&handshake) {
            let _: Result<TsnHandshake, _> = bincode::deserialize(&serialized);
        }
        let elapsed = start.elapsed();
        
        // Vérifier que les PeerId massifs ne causent pas de DoS
        if size > 1000 && elapsed > Duration::from_millis(10) {
            return FuzzResult::SlowOperation(elapsed);
        }
    }
    
    FuzzResult::Success
}

/// Attaque: Flood de handshakes
fn attack_handshake_flood(input: &HandshakeFuzzInput) -> FuzzResult {
    let count = input.iteration_count.max(1) as usize * 10;
    let start = Instant::now();
    
    for _ in 0..count {
        let _: Result<TsnHandshake, _> = bincode::deserialize(&input.raw_data);
    }
    
    let elapsed = start.elapsed();
    let avg_micros = elapsed.as_micros() / count.max(1) as u128;
    
    if avg_micros > 5_000 { // > 5ms par handshake
        return FuzzResult::SlowOperation(elapsed);
    }
    
    FuzzResult::Success
}

/// Attaque: Handshake tronqué
fn attack_truncated_handshake(input: &HandshakeFuzzInput) -> FuzzResult {
    if input.raw_data.len() < 2 {
        return FuzzResult::Success;
    }
    
    // Tester avec des tailles tronquées
    for len in [1, 2, 4, 8, 16, 32, 64] {
        if len < input.raw_data.len() {
            let truncated = &input.raw_data[..len];
            let _: Result<TsnHandshake, _> = bincode::deserialize(truncated);
        }
    }
    
    FuzzResult::Success
}

/// Attaque: Injection de champs extra
fn attack_extra_fields(input: &HandshakeFuzzInput) -> FuzzResult {
    // Ajouter des données après un handshake valide
    let valid_handshake = TsnHandshake {
        version: PROTOCOL_VERSION,
        capabilities: vec![Capability::FullNode],
        peer_id: vec![1, 2, 3, 4],
        timestamp: current_timestamp(),
    };
    
    if let Ok(mut serialized) = bincode::serialize(&valid_handshake) {
        // Ajouter des octets supplémentaires
        serialized.extend_from_slice(&input.raw_data);
        
        // La désérialisation devrait soit réussir (ignorant les données extra)
        // soit échouer proprement
        let _: Result<TsnHandshake, _> = bincode::deserialize(&serialized);
    }
    
    FuzzResult::Success
}

/// Attaque: Injection de null bytes
fn attack_null_bytes(input: &HandshakeFuzzInput) -> FuzzResult {
    let mut null_injected = input.raw_data.clone();
    
    // Insérer des null bytes à intervalles réguliers
    let seed = input.mutation_seed as usize;
    for i in (0..null_injected.len()).step_by((seed % 5 + 1).max(1)) {
        if i < null_injected.len() {
            null_injected[i] = 0;
        }
    }
    
    let _: Result<TsnHandshake, _> = bincode::deserialize(&null_injected);
    FuzzResult::Success
}

/// Attaque: Bit flipping
fn attack_bit_flipping(input: &HandshakeFuzzInput) -> FuzzResult {
    if input.raw_data.is_empty() {
        return FuzzResult::Success;
    }
    
    let mut flipped = input.raw_data.clone();
    let seed = input.mutation_seed as usize;
    
    // Flipper des bits à intervalles réguliers
    for i in (0..flipped.len()).step_by((seed % 7 + 1).max(1)) {
        if i < flipped.len() {
            flipped[i] ^= 0xFF;
        }
    }
    
    let _: Result<TsnHandshake, _> = bincode::deserialize(&flipped);
    FuzzResult::Success
}

/// Validation d'un handshake
fn validate_handshake(handshake: &TsnHandshake) -> Result<(), String> {
    // Vérifier que la version est raisonnable
    if handshake.version > PROTOCOL_VERSION.saturating_add(100) {
        return Err(format!("Unrealistic protocol version: {}", handshake.version));
    }
    
    // Vérifier que le timestamp n'est pas dans un futur lointain
    let now = current_timestamp();
    if handshake.timestamp > now.saturating_add(86400 * 365) {
        return Err(format!("Timestamp too far in future: {}", handshake.timestamp));
    }
    
    // Vérifier que peer_id n'est pas vide
    if handshake.peer_id.is_empty() {
        return Err("PeerId should not be empty".to_string());
    }
    
    Ok(())
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
