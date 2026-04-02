// DISABLED: uses API/modules that no longer exist in current codebase
#![cfg(feature = "disabled_test")]
//! Tests de charge pour le protocole Gossip TSN
//!
//! Tests de performance spécifiques au gossip protocol:
//! - Latence de propagation des blocs avec 100+ peers
//! - Bande passante utilisée sous charge
//! - Résistance aux pics de trafic
//! - Dégradation gracieuse sous stress

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{sleep, timeout};
use tracing::{info, warn, debug};

use tsn::core::{Block, Transaction};
use tsn::network::gossip::{GossipMessage, GossipNode, GossipConfig};

/// Métriques de performance pour les tests de charge
#[derive(Debug, Clone)]
pub struct LoadTestMetrics {
    pub propagation_latencies: Vec<Duration>,
    pub bandwidth_bytes: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub failed_deliveries: u64,
    pub peak_memory_usage: u64,
    pub cpu_time_ms: u64,
}

impl LoadTestMetrics {
    pub fn new() -> Self {
        Self {
            propagation_latencies: Vec::new(),
            bandwidth_bytes: 0,
            messages_sent: 0,
            messages_received: 0,
            failed_deliveries: 0,
            peak_memory_usage: 0,
            cpu_time_ms: 0,
        }
    }

    pub fn avg_latency(&self) -> Duration {
        if self.propagation_latencies.is_empty() {
            return Duration::ZERO;
        }
        let total: Duration = self.propagation_latencies.iter().sum();
        total / self.propagation_latencies.len() as u32
    }

    pub fn p95_latency(&self) -> Duration {
        if self.propagation_latencies.is_empty() {
            return Duration::ZERO;
        }
        let mut sorted = self.propagation_latencies.clone();
        sorted.sort();
        let index = (sorted.len() as f64 * 0.95) as usize;
        sorted[index.min(sorted.len() - 1)]
    }

    pub fn throughput_mbps(&self, duration: Duration) -> f64 {
        let bytes_per_sec = self.bandwidth_bytes as f64 / duration.as_secs_f64();
        bytes_per_sec * 8.0 / 1_000_000.0 // Convert to Mbps
    }
}

/// Nœud de test simulé pour les tests de charge
#[derive(Debug)]
pub struct LoadTestNode {
    pub id: u32,
    pub addr: SocketAddr,
    pub gossip_node: Arc<GossipNode>,
    pub metrics: Arc<Mutex<LoadTestMetrics>>,
    pub message_log: Arc<RwLock<Vec<(Instant, GossipMessage)>>>,
    pub is_malicious: bool,
}

impl LoadTestNode {
    pub async fn new(id: u32, port: u16, config: GossipConfig) -> Self {
        let addr = format!("127.0.0.1:{}", port).parse().unwrap();
        let gossip_node = Arc::new(GossipNode::new(addr, config));
        
        Self {
            id,
            addr,
            gossip_node,
            metrics: Arc::new(Mutex::new(LoadTestMetrics::new())),
            message_log: Arc::new(RwLock::new(Vec::new())),
            is_malicious: false,
        }
    }

    /// Crée un nœud malveillant pour les tests adversariaux
    pub async fn new_malicious(id: u32, port: u16, config: GossipConfig) -> Self {
        let mut node = Self::new(id, port, config).await;
        node.is_malicious = true;
        node
    }

    /// Simule l'envoi d'un message gossip
    pub async fn send_gossip(&self, message: GossipMessage, targets: &[SocketAddr]) -> Result<(), Box<dyn std::error::Error>> {
        let start_time = Instant::now();
        
        for &target in targets {
            // Simule la latence réseau
            let network_delay = if self.is_malicious {
                Duration::from_millis(0) // Nœud malveillant sans délai
            } else {
                Duration::from_millis(fastrand::u64(1..=10)) // 1-10ms de latence
            };
            
            sleep(network_delay).await;
            
            // Log du message
            self.message_log.write().await.push((Instant::now(), message.clone()));
            
            // Mise à jour des métriques
            let mut metrics = self.metrics.lock().await;
            metrics.messages_sent += 1;
            metrics.bandwidth_bytes += message.size_bytes();
        }
        
        let propagation_time = start_time.elapsed();
        self.metrics.lock().await.propagation_latencies.push(propagation_time);
        
        Ok(())
    }

    /// Simule la réception d'un message
    pub async fn receive_gossip(&self, message: GossipMessage) {
        self.message_log.write().await.push((Instant::now(), message));
        self.metrics.lock().await.messages_received += 1;
    }

    /// Génère du spam si le nœud est malveillant
    pub async fn spam_network(&self, targets: &[SocketAddr], spam_count: u32) {
        if !self.is_malicious {
            return;
        }

        for i in 0..spam_count {
            let spam_message = GossipMessage::Block {
                block: Block::new(
                    i as u64,
                    [0u8; 32], // Hash invalide
                    vec![],
                    [0u8; 32],
                    0, // Timestamp invalide
                    0,
                ),
                hop_count: 0,
                timestamp: Instant::now(),
            };

            let _ = self.send_gossip(spam_message, targets).await;
            
            // Petit délai pour éviter de saturer complètement
            if i % 10 == 0 {
                sleep(Duration::from_millis(1)).await;
            }
        }
    }
}

/// Réseau de test pour les tests de charge
pub struct LoadTestNetwork {
    pub nodes: Vec<LoadTestNode>,
    pub topology: HashMap<u32, Vec<u32>>, // node_id -> connected_node_ids
    pub start_time: Instant,
}

impl LoadTestNetwork {
    pub async fn new(node_count: usize, base_port: u16) -> Self {
        let mut nodes = Vec::new();
        let config = GossipConfig {
            max_peers: 50,
            heartbeat_interval: Duration::from_millis(100),
            message_timeout: Duration::from_secs(5),
            max_message_size: 1024 * 1024, // 1MB
            rate_limit_per_peer: 100, // 100 messages/sec
        };

        for i in 0..node_count {
            let node = LoadTestNode::new(i as u32, base_port + i as u16, config.clone()).await;
            nodes.push(node);
        }

        Self {
            nodes,
            topology: HashMap::new(),
            start_time: Instant::now(),
        }
    }

    /// Crée une topologie en étoile (un nœud central connecté à tous)
    pub fn create_star_topology(&mut self, center_node: u32) {
        self.topology.clear();
        
        for node in &self.nodes {
            if node.id == center_node {
                // Le nœud central est connecté à tous
                let connections: Vec<u32> = self.nodes.iter()
                    .filter(|n| n.id != center_node)
                    .map(|n| n.id)
                    .collect();
                self.topology.insert(center_node, connections);
            } else {
                // Les autres nœuds ne sont connectés qu'au centre
                self.topology.insert(node.id, vec![center_node]);
            }
        }
    }

    /// Crée une topologie en grille (chaque nœud connecté à ses voisins)
    pub fn create_mesh_topology(&mut self, connections_per_node: usize) {
        self.topology.clear();
        
        for node in &self.nodes {
            let mut connections = Vec::new();
            let mut added = 0;
            
            for other in &self.nodes {
                if other.id != node.id && added < connections_per_node {
                    connections.push(other.id);
                    added += 1;
                }
            }
            
            self.topology.insert(node.id, connections);
        }
    }

    /// Simule la propagation d'un bloc à travers le réseau
    pub async fn propagate_block(&self, origin_node: u32, block: Block) -> Duration {
        let start_time = Instant::now();
        let message = GossipMessage::Block {
            block,
            hop_count: 0,
            timestamp: start_time,
        };

        // Trouve le nœud d'origine
        let origin = self.nodes.iter().find(|n| n.id == origin_node).unwrap();
        
        // Obtient les connexions du nœud d'origine
        if let Some(connections) = self.topology.get(&origin_node) {
            let target_addrs: Vec<SocketAddr> = connections.iter()
                .filter_map(|&id| self.nodes.iter().find(|n| n.id == id))
                .map(|n| n.addr)
                .collect();

            // Envoie le message aux peers connectés
            let _ = origin.send_gossip(message.clone(), &target_addrs).await;

            // Simule la propagation en cascade
            self.simulate_cascade_propagation(message, connections, 1).await;
        }

        start_time.elapsed()
    }

    /// Simule la propagation en cascade
    async fn simulate_cascade_propagation(&self, message: GossipMessage, from_nodes: &[u32], hop_count: u8) {
        if hop_count > 10 { // Limite la profondeur pour éviter les boucles
            return;
        }

        for &node_id in from_nodes {
            if let Some(connections) = self.topology.get(&node_id) {
                let node = self.nodes.iter().find(|n| n.id == node_id).unwrap();
                
                // Simule le délai de traitement
                sleep(Duration::from_millis(fastrand::u64(1..=5))).await;
                
                let target_addrs: Vec<SocketAddr> = connections.iter()
                    .filter_map(|&id| self.nodes.iter().find(|n| n.id == id))
                    .map(|n| n.addr)
                    .collect();

                let mut propagated_message = message.clone();
                if let GossipMessage::Block { ref mut hop_count, .. } = propagated_message {
                    *hop_count += 1;
                }

                let _ = node.send_gossip(propagated_message.clone(), &target_addrs).await;
                
                // Récursion pour la prochaine couche
                tokio::spawn({
                    let network = self;
                    let msg = propagated_message;
                    let conns = connections.clone();
                    let hc = hop_count + 1;
                    async move {
                        // Note: dans un vrai test, on passerait une référence
                        // Ici on simule juste le délai
                        sleep(Duration::from_millis(1)).await;
                    }
                });
            }
        }
    }

    /// Collecte les métriques de tous les nœuds
    pub async fn collect_metrics(&self) -> LoadTestMetrics {
        let mut combined = LoadTestMetrics::new();
        
        for node in &self.nodes {
            let metrics = node.metrics.lock().await;
            combined.propagation_latencies.extend(metrics.propagation_latencies.clone());
            combined.bandwidth_bytes += metrics.bandwidth_bytes;
            combined.messages_sent += metrics.messages_sent;
            combined.messages_received += metrics.messages_received;
            combined.failed_deliveries += metrics.failed_deliveries;
        }
        
        combined
    }

    /// Ajoute des nœuds malveillants au réseau
    pub async fn add_malicious_nodes(&mut self, count: usize, base_port: u16) {
        let start_id = self.nodes.len() as u32;
        let config = GossipConfig {
            max_peers: 50,
            heartbeat_interval: Duration::from_millis(50), // Plus agressif
            message_timeout: Duration::from_secs(1),
            max_message_size: 1024 * 1024,
            rate_limit_per_peer: 1000, // Pas de limite pour les malveillants
        };

        for i in 0..count {
            let node = LoadTestNode::new_malicious(
                start_id + i as u32,
                base_port + i as u16,
                config.clone()
            ).await;
            self.nodes.push(node);
        }
    }
}

#[tokio::test]
async fn test_gossip_latency_100_peers() {
    let mut network = LoadTestNetwork::new(100, 9000).await;
    network.create_mesh_topology(10); // Chaque nœud connecté à 10 autres

    info!("Starting latency test with 100 peers");
    let start_time = Instant::now();

    // Crée un bloc de test
    let test_block = Block::new(
        1,
        [1u8; 32],
        vec![],
        [2u8; 32],
        start_time.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        12345,
    );

    // Propage le bloc depuis le nœud 0
    let propagation_time = network.propagate_block(0, test_block).await;
    
    // Attend que la propagation se termine
    sleep(Duration::from_millis(500)).await;
    
    let metrics = network.collect_metrics().await;
    let test_duration = start_time.elapsed();

    info!("=== RÉSULTATS TEST LATENCE 100 PEERS ===");
    info!("Temps de propagation: {:?}", propagation_time);
    info!("Latence moyenne: {:?}", metrics.avg_latency());
    info!("Latence P95: {:?}", metrics.p95_latency());
    info!("Messages envoyés: {}", metrics.messages_sent);
    info!("Messages reçus: {}", metrics.messages_received);
    info!("Bande passante: {:.2} Mbps", metrics.throughput_mbps(test_duration));

    // Assertions de performance
    assert!(metrics.avg_latency() < Duration::from_millis(100), 
            "Latence moyenne trop élevée: {:?}", metrics.avg_latency());
    assert!(metrics.p95_latency() < Duration::from_millis(200),
            "Latence P95 trop élevée: {:?}", metrics.p95_latency());
    assert!(metrics.messages_sent > 0, "Aucun message envoyé");
}

#[tokio::test]
async fn test_gossip_bandwidth_under_load() {
    let mut network = LoadTestNetwork::new(50, 9100).await;
    network.create_star_topology(0); // Topologie en étoile avec nœud 0 au centre

    info!("Starting bandwidth test under load");
    let start_time = Instant::now();

    // Envoie 100 blocs rapidement
    for i in 1..=100 {
        let block = Block::new(
            i,
            [i as u8; 32],
            vec![],
            [(i * 2) as u8; 32],
            start_time.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            i * 1000,
        );

        network.propagate_block(0, block).await;
        
        // Petit délai entre les blocs
        sleep(Duration::from_millis(10)).await;
    }

    // Attend que tous les messages soient traités
    sleep(Duration::from_secs(2)).await;
    
    let metrics = network.collect_metrics().await;
    let test_duration = start_time.elapsed();

    info!("=== RÉSULTATS TEST BANDE PASSANTE ===");
    info!("Durée du test: {:?}", test_duration);
    info!("Données transmises: {} bytes", metrics.bandwidth_bytes);
    info!("Débit: {:.2} Mbps", metrics.throughput_mbps(test_duration));
    info!("Messages/seconde: {:.2}", metrics.messages_sent as f64 / test_duration.as_secs_f64());

    // Assertions de performance
    assert!(metrics.bandwidth_bytes > 0, "Aucune donnée transmise");
    assert!(metrics.throughput_mbps(test_duration) > 0.1, "Débit trop faible");
}

#[tokio::test]
async fn test_gossip_resilience_with_malicious_nodes() {
    let mut network = LoadTestNetwork::new(80, 9200).await;
    network.add_malicious_nodes(20, 9300).await; // 20% de nœuds malveillants
    network.create_mesh_topology(15);

    info!("Starting resilience test with 20% malicious nodes");
    let start_time = Instant::now();

    // Les nœuds malveillants commencent à spammer
    let malicious_targets: Vec<SocketAddr> = network.nodes.iter()
        .filter(|n| !n.is_malicious)
        .map(|n| n.addr)
        .collect();

    for node in &network.nodes {
        if node.is_malicious {
            let targets = malicious_targets.clone();
            let node_clone = node;
            tokio::spawn(async move {
                node_clone.spam_network(&targets, 500).await;
            });
        }
    }

    // Pendant ce temps, propage des blocs légitimes
    for i in 1..=20 {
        let legitimate_block = Block::new(
            i,
            [i as u8; 32],
            vec![],
            [(i * 3) as u8; 32],
            start_time.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            i * 2000,
        );

        network.propagate_block(0, legitimate_block).await;
        sleep(Duration::from_millis(100)).await;
    }

    sleep(Duration::from_secs(3)).await;
    
    let metrics = network.collect_metrics().await;
    let test_duration = start_time.elapsed();

    info!("=== RÉSULTATS TEST RÉSILIENCE ===");
    info!("Messages légitimes vs spam ratio: {:.2}", 
          metrics.messages_received as f64 / metrics.messages_sent as f64);
    info!("Échecs de livraison: {}", metrics.failed_deliveries);
    info!("Débit maintenu: {:.2} Mbps", metrics.throughput_mbps(test_duration));

    // Le réseau doit maintenir des performances acceptables malgré l'attaque
    assert!(metrics.avg_latency() < Duration::from_millis(500), 
            "Latence dégradée par l'attaque: {:?}", metrics.avg_latency());
}

#[tokio::test]
async fn test_gossip_scalability_200_peers() {
    let mut network = LoadTestNetwork::new(200, 9400).await;
    network.create_mesh_topology(20); // Chaque nœud connecté à 20 autres

    info!("Starting scalability test with 200 peers");
    let start_time = Instant::now();

    // Test de montée en charge progressive
    for batch in 1..=5 {
        info!("Batch {} - propagating 10 blocks", batch);
        
        for i in 1..=10 {
            let block_id = (batch - 1) * 10 + i;
            let block = Block::new(
                block_id,
                [block_id as u8; 32],
                vec![],
                [(block_id * 4) as u8; 32],
                start_time.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                block_id * 3000,
            );

            network.propagate_block(fastrand::usize(0..200) as u32, block).await;
            sleep(Duration::from_millis(20)).await;
        }
        
        // Pause entre les batches
        sleep(Duration::from_millis(200)).await;
    }

    sleep(Duration::from_secs(5)).await; // Temps pour que tout se propage
    
    let metrics = network.collect_metrics().await;
    let test_duration = start_time.elapsed();

    info!("=== RÉSULTATS TEST SCALABILITÉ 200 PEERS ===");
    info!("Durée totale: {:?}", test_duration);
    info!("Latence moyenne: {:?}", metrics.avg_latency());
    info!("Latence P95: {:?}", metrics.p95_latency());
    info!("Débit global: {:.2} Mbps", metrics.throughput_mbps(test_duration));
    info!("Efficacité réseau: {:.2}%", 
          (metrics.messages_received as f64 / metrics.messages_sent as f64) * 100.0);

    // Assertions de scalabilité
    assert!(metrics.avg_latency() < Duration::from_millis(300), 
            "Latence non-scalable: {:?}", metrics.avg_latency());
    assert!(metrics.p95_latency() < Duration::from_secs(1),
            "Latence P95 non-scalable: {:?}", metrics.p95_latency());
    assert!(metrics.throughput_mbps(test_duration) > 1.0, 
            "Débit insuffisant pour 200 peers");
}

#[tokio::test]
async fn test_gossip_memory_usage_under_stress() {
    let mut network = LoadTestNetwork::new(100, 9600).await;
    network.create_mesh_topology(12);

    info!("Starting memory stress test");
    let start_time = Instant::now();

    // Génère une charge soutenue pendant 30 secondes
    let stress_duration = Duration::from_secs(30);
    let end_time = start_time + stress_duration;

    let mut block_counter = 0u64;
    while Instant::now() < end_time {
        block_counter += 1;
        
        let block = Block::new(
            block_counter,
            [block_counter as u8; 32],
            vec![], // Pas de transactions pour ce test
            [(block_counter * 5) as u8; 32],
            start_time.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            block_counter * 4000,
        );

        network.propagate_block(fastrand::usize(0..100) as u32, block).await;
        
        // Fréquence élevée: un bloc toutes les 100ms
        sleep(Duration::from_millis(100)).await;
    }

    let metrics = network.collect_metrics().await;
    let actual_duration = start_time.elapsed();

    info!("=== RÉSULTATS TEST STRESS MÉMOIRE ===");
    info!("Blocs générés: {}", block_counter);
    info!("Durée réelle: {:?}", actual_duration);
    info!("Messages traités: {}", metrics.messages_received);
    info!("Débit soutenu: {:.2} Mbps", metrics.throughput_mbps(actual_duration));
    info!("Latence sous stress: {:?}", metrics.avg_latency());

    // Le système doit maintenir des performances stables sous stress
    assert!(metrics.avg_latency() < Duration::from_millis(400), 
            "Latence dégradée sous stress: {:?}", metrics.avg_latency());
    assert!(block_counter > 250, "Pas assez de blocs générés: {}", block_counter);
}
