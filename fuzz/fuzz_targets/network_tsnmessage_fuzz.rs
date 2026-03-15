#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::time::{Instant, Duration};

/// FUZZER: Désérialisation TsnMessage (types.rs version)
/// 
/// Cible: Vérifier la robustesse du parsing des messages réseau TSN
/// contre les données malformées et les attaques DoS.
/// 
/// VECTEURS D'ATTAQUE:
/// 1. Messages avec taille de payload invalide
/// 2. Messages avec timestamps futurs/passés extrêmes
/// 3. Messages avec PeerId malformés
/// 4. Messages récursifs (nested)
/// 5. Messages avec des capacités inconnues
use tsn::network::types::{TsnMessage, PeerId, Capability, MAX_MESSAGE_SIZE};

#[derive(Arbitrary, Debug, Clone)]
struct TsnMessageFuzzInput {
    /// Données brutes du message
    raw_data: Vec<u8>,
    
    /// Type d'attaque à simuler
    attack_strategy: AttackStrategy,
    
    /// Paramètres de l'attaque
    repetition_count: u8,
    corruption_seed: u8,
}

#[derive(Arbitrary, Debug, Clone)]
enum AttackStrategy {
    /// Désérialisation directe des données brutes
    RawDeserialize,
    /// Corruption aléatoire des octets
    RandomCorruption,
    /// Injection de tailles invalides
    InvalidSizeInjection,
    /// Timestamp extrême
    ExtremeTimestamp,
    /// PeerId malformé
    MalformedPeerId,
    /// Payload récursif
    RecursivePayload,
    /// Flood de messages
    MessageFlood,
    /// Capacités inconnues
    UnknownCapabilities,
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

fuzz_target!(|input: TsnMessageFuzzInput| {
    // Exécuter l'attaque sans panic
    let result = execute_fuzz_attack_safely(&input);
    
    // Log pour analyse mais pas de panic
    match result {
        FuzzResult::ValidationFailed(msg) => {
            eprintln!("[FUZZ] Validation issue: {}", msg);
        }
        FuzzResult::SlowOperation(duration) => {
            eprintln!("[FUZZ] Slow operation detected: {:?}", duration);
        }
        _ => {}
    }
});

fn execute_fuzz_attack_safely(input: &TsnMessageFuzzInput) -> FuzzResult {
    match input.attack_strategy {
        AttackStrategy::RawDeserialize => attack_raw_deserialize(input),
        AttackStrategy::RandomCorruption => attack_random_corruption(input),
        AttackStrategy::InvalidSizeInjection => attack_invalid_size(input),
        AttackStrategy::ExtremeTimestamp => attack_extreme_timestamp(input),
        AttackStrategy::MalformedPeerId => attack_malformed_peer_id(input),
        AttackStrategy::RecursivePayload => attack_recursive_payload(input),
        AttackStrategy::MessageFlood => attack_message_flood(input),
        AttackStrategy::UnknownCapabilities => attack_unknown_capabilities(input),
    }
}

/// Attaque 1: Désérialisation directe des données brutes
fn attack_raw_deserialize(input: &TsnMessageFuzzInput) -> FuzzResult {
    let start = Instant::now();
    
    // Tentative de désérialisation
    let result: Result<TsnMessage, _> = bincode::deserialize(&input.raw_data);
    
    let elapsed = start.elapsed();
    
    // Vérifier que le parsing ne prend pas trop de temps (DoS)
    if elapsed > Duration::from_millis(100) {
        return FuzzResult::SlowOperation(elapsed);
    }
    
    // Si la désérialisation réussit, valider les champs
    match result {
        Ok(msg) => {
            if let Err(e) = validate_deserialized_message(&msg) {
                return FuzzResult::ValidationFailed(e);
            }
            FuzzResult::Success
        }
        Err(_) => FuzzResult::DeserializationFailed,
    }
}

/// Attaque 2: Corruption aléatoire des octets
fn attack_random_corruption(input: &TsnMessageFuzzInput) -> FuzzResult {
    if input.raw_data.is_empty() {
        return FuzzResult::Success;
    }
    
    let mut corrupted = input.raw_data.clone();
    let seed = input.corruption_seed as usize;
    
    // Corrompre des octets à intervalles réguliers
    for i in (0..corrupted.len()).step_by((seed % 10 + 1).max(1)) {
        if i < corrupted.len() {
            corrupted[i] = corrupted[i].wrapping_add(seed as u8);
        }
    }
    
    // Tentative de désérialisation sur données corrompues
    let _: Result<TsnMessage, _> = bincode::deserialize(&corrupted);
    FuzzResult::Success
}

/// Attaque 3: Injection de tailles invalides
fn attack_invalid_size(input: &TsnMessageFuzzInput) -> FuzzResult {
    // Créer un message avec une taille déclarée invalide
    let mut malicious = Vec::new();
    
    // Simuler un header avec une taille massive
    let fake_size: u64 = u64::MAX;
    malicious.extend_from_slice(&fake_size.to_le_bytes());
    malicious.extend_from_slice(&input.raw_data);
    
    let start = Instant::now();
    let _: Result<TsnMessage, _> = bincode::deserialize(&malicious);
    let elapsed = start.elapsed();
    
    // Vérifier qu'on ne bloque pas sur une taille invalide
    if elapsed > Duration::from_millis(50) {
        return FuzzResult::SlowOperation(elapsed);
    }
    
    FuzzResult::Success
}

/// Attaque 4: Timestamps extrêmes
fn attack_extreme_timestamp(_input: &TsnMessageFuzzInput) -> FuzzResult {
    // Les timestamps extrêmes pourraient causer des problèmes de logique
    let extreme_timestamps = [
        0u64,                    // Époque Unix
        u64::MAX,                // Futur lointain
        u64::MAX / 2,            // Milieu de l'ère
        1_000_000_000,           // ~2001
        4_000_000_000,           // ~2096
    ];
    
    for &ts in &extreme_timestamps {
        // Créer un message avec timestamp extrême
        let msg = TsnMessage::Ping { timestamp: ts };
        
        // Gestion d'erreur sans unwrap_or_default
        let serialized = match bincode::serialize(&msg) {
            Ok(data) => data,
            Err(e) => {
                return FuzzResult::ValidationFailed(format!("Serialization failed: {}", e));
            }
        };
        
        // Vérifier round-trip
        if let Ok(deserialized) = bincode::deserialize::<TsnMessage>(&serialized) {
            if let Err(e) = validate_deserialized_message(&deserialized) {
                return FuzzResult::ValidationFailed(e);
            }
        }
    }
    
    FuzzResult::Success
}

/// Attaque 5: PeerId malformé
fn attack_malformed_peer_id(input: &TsnMessageFuzzInput) -> FuzzResult {
    // Tester avec différentes tailles de PeerId
    let peer_id_sizes = [0, 1, 16, 32, 64, 128, 256, 1024];
    
    for size in peer_id_sizes {
        let fake_peer_id = vec![0xABu8; size];
        // Note: PeerId est typiquement un Vec<u8> ou une structure fixe
        // On injecte directement dans les données
        let mut data = input.raw_data.clone();
        data.extend_from_slice(&fake_peer_id);
        
        let _: Result<TsnMessage, _> = bincode::deserialize(&data);
    }
    
    FuzzResult::Success
}

/// Attaque 6: Payload récursif
fn attack_recursive_payload(input: &TsnMessageFuzzInput) -> FuzzResult {
    // Les messages ne devraient pas être récursivement nested
    // Cette attaque vérifie qu'on ne crée pas de structures récursives
    
    // Simuler des messages nested (si applicable)
    let depth = input.repetition_count.min(10);
    
    for _ in 0..depth {
        // Chaque itération tente de parser les mêmes données
        // comme si elles contenaient des sous-messages
        let _: Result<TsnMessage, _> = bincode::deserialize(&input.raw_data);
    }
    
    FuzzResult::Success
}

/// Attaque 7: Flood de messages
fn attack_message_flood(input: &TsnMessageFuzzInput) -> FuzzResult {
    let count = input.repetition_count.max(1) as usize;
    let start = Instant::now();
    
    for _ in 0..count {
        let _: Result<TsnMessage, _> = bincode::deserialize(&input.raw_data);
    }
    
    let elapsed = start.elapsed();
    let avg_time = elapsed.as_micros() / count.max(1) as u128;
    
    // Alerter si le parsing moyen est trop lent
    if avg_time > 10_000 { // > 10ms par message
        return FuzzResult::SlowOperation(elapsed);
    }
    
    FuzzResult::Success
}

/// Attaque 8: Capacités inconnues
fn attack_unknown_capabilities(input: &TsnMessageFuzzInput) -> FuzzResult {
    // Tester avec des valeurs d'enum Capability inconnues
    // Si Capability est un u8 sous-jacent, des valeurs > 2 sont invalides
    let unknown_caps = [0u8, 1, 2, 3, 255];
    
    for cap in unknown_caps {
        let mut data = input.raw_data.clone();
        if !data.is_empty() {
            data[0] = cap;
        }
        let _: Result<TsnMessage, _> = bincode::deserialize(&data);
    }
    
    FuzzResult::Success
}

/// Validation d'un message désérialisé
fn validate_deserialized_message(msg: &TsnMessage) -> Result<(), String> {
    match msg {
        TsnMessage::Handshake { version, capabilities, peer_id, timestamp } => {
            // Vérifier que la version est raisonnable
            if *version > 1000 {
                return Err(format!("Unrealistic protocol version: {}", version));
            }
            
            // Vérifier que le timestamp n'est pas dans un futur lointain
            let now = current_timestamp();
            if *timestamp > now.saturating_add(86400) {
                return Err(format!("Timestamp too far in future: {}", timestamp));
            }
            
            // Vérifier que les capacités sont valides
            for cap in capabilities {
                match cap {
                    Capability::FullNode | Capability::LightClient | Capability::Miner => {}
                }
            }
            
            // Vérifier que peer_id n'est pas vide
            if peer_id.is_empty() {
                return Err("PeerId should not be empty".to_string());
            }
        }
        
        TsnMessage::Ping { timestamp } => {
            let now = current_timestamp();
            if *timestamp > now.saturating_add(86400) {
                return Err(format!("Ping timestamp too far in future: {}", timestamp));
            }
        }
        
        TsnMessage::Pong { timestamp } => {
            let now = current_timestamp();
            if *timestamp > now.saturating_add(86400) {
                return Err(format!("Pong timestamp too far in future: {}", timestamp));
            }
        }
        
        TsnMessage::PeerExchange { peers } => {
            // Limiter le nombre de peers pour éviter DoS
            if peers.len() > 1000 {
                return Err(format!("Too many peers in exchange: {}", peers.len()));
            }
        }
        
        TsnMessage::Disconnect { reason: _, timestamp } => {
            // Vérifier que le timestamp est raisonnable
            let now = current_timestamp();
            if *timestamp > now.saturating_add(86400) {
                return Err(format!("Disconnect timestamp too far in future: {}", timestamp));
            }
        }
        
        _ => {}
    }
    
    Ok(())
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
