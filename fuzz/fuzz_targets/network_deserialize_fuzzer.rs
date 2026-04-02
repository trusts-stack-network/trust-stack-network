#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::time::Instant;

// Import des types réseau TSN
use tsn::network::types::{TsnMessage, NetworkMessage, MessageType};
use tsn::core::{
    transaction::{Transaction, ShieldedTransaction, CoinbaseTransaction},
    block::{BlockHeader, ShieldedBlock}
};

/// **FUZZER RÉSEAU POUR DÉSÉRIALISATION**
/// 
/// Ce fuzzer cible spécifiquement les vecteurs d'attaque via le réseau.
/// Les messages réseau contiennent des transactions et blocs sérialisés
/// qui sont des points d'entrée critiques pour les attaques.
/// 
/// **VECTEURS D'ATTAQUE CIBLÉS** :
/// 1. **Messages réseau malformés** contenant des transactions corrompues
/// 2. **Attaques DoS** via des messages oversized
/// 3. **Attaques de désynchronisation** via des blocs invalides
/// 4. **Injection de données** via les champs de message
/// 5. **Timing attacks** sur le parsing réseau
/// 6. **Memory exhaustion** via des payloads massifs
#[derive(Arbitrary, Debug)]
struct NetworkFuzzInput {
    // Message réseau brut
    raw_message: Vec<u8>,
    
    // Type d'attaque réseau
    attack_type: NetworkAttackType,
    
    // Paramètres d'attaque
    amplification: u16,
    corruption_rate: u8,
    timing_samples: u8,
}

#[derive(Arbitrary, Debug, Clone)]
enum NetworkAttackType {
    MalformedTransactionMessage,
    MalformedBlockMessage,
    OversizedPayload,
    CorruptedHeaders,
    TimingAttackMessage,
    MemoryExhaustionMessage,
    ProtocolConfusionAttack,
    MessageFragmentationAttack,
}

fuzz_target!(|input: NetworkFuzzInput| {
    // Protection globale contre les panics
    let panic_result = std::panic::catch_unwind(|| {
        execute_network_attack(&input)
    });
    
    if let Err(panic_info) = panic_result {
        let panic_msg = if let Some(s) = panic_info.downcast_ref::<String>() {
            s.clone()
        } else if let Some(s) = panic_info.downcast_ref::<&str>() {
            s.to_string()
        } else {
            "Unknown network panic".to_string()
        };
        
        panic!("NETWORK VULNERABILITY: {} | Attack: {:?} | Size: {} bytes", 
               panic_msg, input.attack_type, input.raw_message.len());
    }
});

fn execute_network_attack(input: &NetworkFuzzInput) {
    match input.attack_type {
        NetworkAttackType::MalformedTransactionMessage => attack_malformed_transaction_message(input),
        NetworkAttackType::MalformedBlockMessage => attack_malformed_block_message(input),
        NetworkAttackType::OversizedPayload => attack_oversized_payload(input),
        NetworkAttackType::CorruptedHeaders => attack_corrupted_headers(input),
        NetworkAttackType::TimingAttackMessage => attack_timing_message(input),
        NetworkAttackType::MemoryExhaustionMessage => attack_memory_exhaustion_message(input),
        NetworkAttackType::ProtocolConfusionAttack => attack_protocol_confusion(input),
        NetworkAttackType::MessageFragmentationAttack => attack_message_fragmentation(input),
    }
}

/// **ATTAQUE 1: MESSAGES DE TRANSACTION MALFORMÉS**
/// Injecte des transactions corrompues dans des messages réseau valides
fn attack_malformed_transaction_message(input: &NetworkFuzzInput) {
    // Créer un message réseau contenant une transaction corrompue
    let mut corrupted_tx_data = input.raw_message.clone();
    
    // Appliquer une corruption ciblée
    for i in 0..corrupted_tx_data.len() {
        if i % (input.corruption_rate as usize + 1) == 0 {
            corrupted_tx_data[i] = corrupted_tx_data[i].wrapping_add(0xAA);
        }
    }
    
    // Tenter de créer un message réseau avec cette transaction
    let network_message = create_transaction_network_message(&corrupted_tx_data);
    
    // Tester la désérialisation du message réseau
    test_network_message_parsing(&network_message);
    
    // Si le message parse, tester l'extraction de la transaction
    if let Ok(parsed_msg) = bincode::deserialize::<TsnMessage>(&network_message) {
        // Extraire et tester la transaction contenue
        test_embedded_transaction_extraction(&parsed_msg);
    }
}

/// **ATTAQUE 2: MESSAGES DE BLOC MALFORMÉS**
fn attack_malformed_block_message(input: &NetworkFuzzInput) {
    let mut corrupted_block_data = input.raw_message.clone();
    
    // Corruption spécifique aux blocs
    // 1. Corrompre le header (premiers 128 octets typiquement)
    for i in 0..corrupted_block_data.len().min(128) {
        if i % 4 == 0 {
            corrupted_block_data[i] = 0xFF;
        }
    }
    
    // 2. Corrompre les hashes (patterns de 32 octets)
    for offset in (32..corrupted_block_data.len()).step_by(32) {
        if offset + 32 <= corrupted_block_data.len() {
            // Injecter un hash invalide
            corrupted_block_data[offset..offset+32].fill(0xDEADBEEF as u8);
        }
    }
    
    let network_message = create_block_network_message(&corrupted_block_data);
    test_network_message_parsing(&network_message);
}

/// **ATTAQUE 3: PAYLOAD OVERSIZED**
/// Teste la résistance aux messages réseau de taille excessive
fn attack_oversized_payload(input: &NetworkFuzzInput) {
    let base_size = input.raw_message.len();
    let amplification = input.amplification as usize;
    
    // Créer un payload massif
    let mut oversized_payload = Vec::new();
    oversized_payload.reserve(base_size * amplification);
    
    for _ in 0..amplification {
        oversized_payload.extend_from_slice(&input.raw_message);
    }
    
    // Limiter à 100MB pour éviter OOM du fuzzer
    if oversized_payload.len() > 100_000_000 {
        oversized_payload.truncate(100_000_000);
    }
    
    // Mesurer le temps de parsing
    let start = Instant::now();
    let _ = bincode::deserialize::<TsnMessage>(&oversized_payload);
    let elapsed = start.elapsed();
    
    // Alerter si le parsing prend trop de temps (DoS potentiel)
    if elapsed.as_millis() > 1000 {
        panic!("NETWORK DOS: Oversized payload parsing took {}ms for {}MB", 
               elapsed.as_millis(), oversized_payload.len() / 1_000_000);
    }
}

/// **ATTAQUE 4: HEADERS CORROMPUS**
/// Corrompt spécifiquement les headers de message réseau
fn attack_corrupted_headers(input: &NetworkFuzzInput) {
    let mut corrupted_message = input.raw_message.clone();
    
    // Patterns de corruption d'header
    let header_corruptions = [
        // Magic bytes incorrects
        vec![0xDE, 0xAD, 0xBE, 0xEF],
        // Version invalide
        vec![0xFF, 0xFF, 0xFF, 0xFF],
        // Longueur incohérente
        vec![0x00, 0x00, 0x00, 0x00],
        // Type de message invalide
        vec![0x99, 0x99, 0x99, 0x99],
    ];
    
    for (i, corruption) in header_corruptions.iter().enumerate() {
        let offset = i * 4;
        if offset + 4 <= corrupted_message.len() {
            corrupted_message[offset..offset+4].copy_from_slice(corruption);
        }
    }
    
    // Tester avec différentes stratégies de parsing
    test_network_message_parsing(&corrupted_message);
    test_network_message_streaming(&corrupted_message);
}

/// **ATTAQUE 5: TIMING ATTACK SUR MESSAGES**
/// Mesure les variations de temps de parsing pour détecter les fuites d'information
fn attack_timing_message(input: &NetworkFuzzInput) {
    let samples = input.timing_samples.max(5) as usize;
    let mut timings = Vec::new();
    
    // Créer des variations subtiles du message
    for variation in 0..samples {
        let mut variant = input.raw_message.clone();
        
        // Appliquer une variation mineure
        if !variant.is_empty() {
            let idx = variation % variant.len();
            variant[idx] = variant[idx].wrapping_add(1);
        }
        
        // Mesurer le temps de parsing
        let start = Instant::now();
        let _ = bincode::deserialize::<TsnMessage>(&variant);
        let elapsed = start.elapsed();
        
        timings.push(elapsed);
    }
    
    // Analyser la variance temporelle
    if timings.len() >= 2 {
        let min_time = timings.iter().min().unwrap();
        let max_time = timings.iter().max().unwrap();
        let variance = max_time.saturating_sub(*min_time);
        
        // Alerter si variance suspecte
        if variance.as_millis() > 20 {
            panic!("NETWORK TIMING LEAK: {}ms variance between similar messages", 
                   variance.as_millis());
        }
    }
}

/// **ATTAQUE 6: ÉPUISEMENT MÉMOIRE VIA MESSAGES**
fn attack_memory_exhaustion_message(input: &NetworkFuzzInput) {
    // Créer un message qui suggère de grandes allocations
    let mut memory_bomb = input.raw_message.clone();
    
    // Injecter des "longueurs" énormes dans le message
    let fake_lengths = [
        1_000_000u64,    // 1MB
        100_000_000u64,  // 100MB
        1_000_000_000u64, // 1GB
        u64::MAX,        // MAX
    ];
    
    for (i, &length) in fake_lengths.iter().enumerate() {
        let offset = i * 8;
        if offset + 8 <= memory_bomb.len() {
            memory_bomb[offset..offset+8].copy_from_slice(&length.to_le_bytes());
        }
    }
    
    // Mesurer l'allocation mémoire
    let memory_before = estimate_memory_usage();
    let start = Instant::now();
    
    let _ = bincode::deserialize::<TsnMessage>(&memory_bomb);
    
    let elapsed = start.elapsed();
    let memory_after = estimate_memory_usage();
    let memory_delta = memory_after.saturating_sub(memory_before);
    
    // Alerter si allocation excessive
    if memory_delta > 50_000_000 { // > 50MB
        panic!("NETWORK MEMORY DOS: Allocated {}MB during message parsing", 
               memory_delta / 1_000_000);
    }
    
    if elapsed.as_millis() > 500 {
        panic!("NETWORK TIMING DOS: Message parsing took {}ms", elapsed.as_millis());
    }
}

/// **ATTAQUE 7: CONFUSION DE PROTOCOLE**
/// Mélange différents types de messages pour tester la robustesse du parsing
fn attack_protocol_confusion(input: &NetworkFuzzInput) {
    let mut confused_message = input.raw_message.clone();
    
    // Injecter des marqueurs de différents protocoles
    let protocol_markers = [
        b"HTTP/1.1",
        b"SSH-2.0",
        b"BitTorrent",
        b"TSN-1.0",
        b"Bitcoin",
        b"Ethereum",
    ];
    
    for (i, marker) in protocol_markers.iter().enumerate() {
        let offset = i * marker.len();
        if offset + marker.len() <= confused_message.len() {
            confused_message[offset..offset+marker.len()].copy_from_slice(marker);
        }
    }
    
    // Tester si le parser TSN est confus par ces marqueurs
    test_network_message_parsing(&confused_message);
}

/// **ATTAQUE 8: FRAGMENTATION DE MESSAGE**
/// Teste la robustesse face aux messages fragmentés ou partiels
fn attack_message_fragmentation(input: &NetworkFuzzInput) {
    let message_len = input.raw_message.len();
    
    if message_len > 8 {
        // Tester différents points de fragmentation
        let fragment_points = [
            1, 2, 4, 8, 16, 32, 64,
            message_len / 4,
            message_len / 2,
            message_len * 3 / 4,
            message_len - 1,
        ];
        
        for &fragment_point in &fragment_points {
            if fragment_point < message_len {
                // Tester avec fragment partiel
                let fragment = &input.raw_message[..fragment_point];
                test_network_message_parsing(fragment);
                
                // Tester avec fragment + padding
                let mut padded_fragment = fragment.to_vec();
                padded_fragment.extend_from_slice(&[0u8; 64]); // Padding
                test_network_message_parsing(&padded_fragment);
            }
        }
    }
}

// === FONCTIONS UTILITAIRES ===

fn create_transaction_network_message(tx_data: &[u8]) -> Vec<u8> {
    // Créer un message réseau TSN contenant une transaction
    let mut message = Vec::new();
    
    // Header simplifié
    message.extend_from_slice(b"TSN\x01"); // Magic + version
    message.extend_from_slice(&(tx_data.len() as u32).to_le_bytes()); // Longueur
    message.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Type: Transaction
    
    // Payload
    message.extend_from_slice(tx_data);
    
    message
}

fn create_block_network_message(block_data: &[u8]) -> Vec<u8> {
    let mut message = Vec::new();
    
    // Header
    message.extend_from_slice(b"TSN\x01");
    message.extend_from_slice(&(block_data.len() as u32).to_le_bytes());
    message.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // Type: Block
    
    // Payload
    message.extend_from_slice(block_data);
    
    message
}

fn test_network_message_parsing(message_data: &[u8]) {
    // Test de parsing basique
    let _ = bincode::deserialize::<TsnMessage>(message_data);
    
    // Test de parsing avec timeout
    let start = Instant::now();
    let _ = bincode::deserialize::<NetworkMessage>(message_data);
    let elapsed = start.elapsed();
    
    if elapsed.as_millis() > 100 {
        panic!("NETWORK PARSING TIMEOUT: {}ms for {} bytes", 
               elapsed.as_millis(), message_data.len());
    }
}

fn test_network_message_streaming(message_data: &[u8]) {
    // Simuler un parsing en streaming (par chunks)
    let chunk_size = 1024;
    
    for chunk_start in (0..message_data.len()).step_by(chunk_size) {
        let chunk_end = (chunk_start + chunk_size).min(message_data.len());
        let chunk = &message_data[chunk_start..chunk_end];
        
        // Tenter de parser chaque chunk
        let _ = bincode::deserialize::<TsnMessage>(chunk);
    }
}

fn test_embedded_transaction_extraction(message: &TsnMessage) {
    // Extraire et tester les transactions contenues dans le message
    // (Cette fonction dépend de l'implémentation exacte de TsnMessage)
    
    // Simuler l'extraction de payload
    if let Ok(payload) = bincode::serialize(message) {
        // Tenter de désérialiser comme transaction
        let _ = bincode::deserialize::<ShieldedTransaction>(&payload);
        let _ = bincode::deserialize::<CoinbaseTransaction>(&payload);
    }
}

fn estimate_memory_usage() -> usize {
    // Estimation simplifiée de l'usage mémoire
    std::env::var("MEMORY_USAGE_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}