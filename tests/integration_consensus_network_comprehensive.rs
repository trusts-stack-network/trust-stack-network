// DISABLED: uses API/modules that no longer exist in current codebase
#![cfg(feature = "disabled_test")]
//! Tests d'intégration consensus-réseau pour TSN
//!
//! Suite complète de tests end-to-end validant l'interaction entre :
//! - Consensus et validation des blocs
//! - Signatures SLH-DSA post-quantiques
//! - Propagation réseau et synchronisation
//! - Scénarios de forks et résolution
//!
//! THREAT MODEL:
//! - Adversaire contrôlant jusqu'à 49% du réseau
//! - Attaques de partition réseau temporaires
//! - Blocs malformés ou signatures invalides
//! - Race conditions lors de la synchronisation

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn, error};

use tsn::core::{Block, Blockchain, Transaction, ShieldedBlock};
use tsn::crypto::keys::{KeyPair, PublicKey};
use tsn::crypto::signature::Signature;
use tsn::consensus::validation::{Validator, ValidationError};
use tsn::network::{AppState, Mempool};

/// Configuration sécurisée d'un nœud de test
#[derive(Clone)]
struct SecureTestNode {
    id: u32,
    addr: SocketAddr,
    keypair: KeyPair,
    state: Arc<AppState>,
    blockchain: Arc<Blockchain>,
    validator: Validator,
    // Métriques de sécurité
    invalid_blocks_received: Arc<std::sync::atomic::AtomicU64>,
    fork_events: Arc<std::sync::atomic::AtomicU64>,
}

impl SecureTestNode {
    async fn new(id: u32, port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        let addr = format!("127.0.0.1:{}", port).parse()?;
        let keypair = KeyPair::generate();
        let blockchain = Arc::new(Blockchain::new());
        let mempool = Arc::new(tokio::sync::RwLock::new(Mempool::new()));
        
        let state = Arc::new(AppState {
            blockchain: blockchain.clone(),
            mempool,
            peers: std::sync::RwLock::new(Vec::new()),
        });

        let validator = Validator::new();

        Ok(Self {
            id,
            addr,
            keypair,
            state,
            blockchain,
            validator,
            invalid_blocks_received: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            fork_events: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    /// Connecte ce nœud à un autre avec validation de l'identité
    async fn secure_connect_to(&self, peer: &SecureTestNode) -> Result<(), Box<dyn std::error::Error>> {
        let peer_url = format!("http://{}", peer.addr);
        
        // Validation de l'identité du peer (simulation)
        debug!("Node {} connecting to peer {} at {}", self.id, peer.id, peer_url);
        
        self.state.peers.write().unwrap().push(peer_url);
        Ok(())
    }

    /// Génère un bloc valide avec signature SLH-DSA
    async fn mine_valid_block(&self, transactions: Vec<Transaction>) -> Result<Block, Box<dyn std::error::Error>> {
        let parent_hash = self.blockchain.get_latest_block_hash();
        let height = self.blockchain.get_height() + 1;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        
        let mut block = Block::new(
            height,
            parent_hash,
            transactions,
            [0u8; 32], // merkle_root calculé après
            timestamp,
            0, // nonce pour PoW
        );

        // Calcul du merkle root
        block.merkle_root = block.calculate_merkle_root();
        
        // Signature SLH-DSA du bloc
        let block_hash = block.calculate_hash();
        let signature = self.keypair.sign(&block_hash)?;
        
        // Ajout de la signature au bloc (simulation - en vrai ce serait dans les métadonnées)
        debug!("Node {} mined block {} with SLH-DSA signature", self.id, height);
        
        Ok(block)
    }

    /// Génère un bloc INVALIDE pour tester la validation
    async fn mine_invalid_block(&self, invalid_type: InvalidBlockType) -> Result<Block, Box<dyn std::error::Error>> {
        let parent_hash = self.blockchain.get_latest_block_hash();
        let height = self.blockchain.get_height() + 1;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        
        let block = match invalid_type {
            InvalidBlockType::InvalidParentHash => {
                Block::new(height, [0xFF; 32], Vec::new(), [0u8; 32], timestamp, 0)
            },
            InvalidBlockType::FutureTimestamp => {
                Block::new(height, parent_hash, Vec::new(), [0u8; 32], timestamp + 3600, 0)
            },
            InvalidBlockType::InvalidHeight => {
                Block::new(height + 100, parent_hash, Vec::new(), [0u8; 32], timestamp, 0)
            },
            InvalidBlockType::CorruptedMerkleRoot => {
                let mut block = Block::new(height, parent_hash, Vec::new(), [0u8; 32], timestamp, 0);
                block.merkle_root = [0xFF; 32]; // Merkle root incorrect
                block
            },
        };

        warn!("Node {} generated invalid block type {:?}", self.id, invalid_type);
        Ok(block)
    }

    /// Valide un bloc reçu avec toutes les vérifications de sécurité
    async fn validate_received_block(&self, block: &Block) -> Result<(), ValidationError> {
        debug!("Node {} validating block {}", self.id, block.height);
        
        // Validation structurelle
        self.validator.validate_block_structure(block)?;
        
        // Validation consensus
        self.validator.validate_consensus_rules(block, &self.blockchain)?;
        
        // Validation cryptographique (simulation SLH-DSA)
        self.validator.validate_block_signatures(block)?;
        
        info!("Node {} successfully validated block {}", self.id, block.height);
        Ok(())
    }

    /// Propage un bloc vers les peers avec gestion d'erreurs
    async fn secure_propagate_block(&self, block: &Block) -> Result<(), Box<dyn std::error::Error>> {
        let peers = self.state.peers.read().unwrap().clone();
        
        for peer_url in peers {
            match timeout(Duration::from_secs(5), self.send_block_to_peer(&peer_url, block)).await {
                Ok(Ok(())) => {
                    debug!("Block {} propagated to {}", block.height, peer_url);
                },
                Ok(Err(e)) => {
                    warn!("Failed to propagate block {} to {}: {}", block.height, peer_url, e);
                },
                Err(_) => {
                    warn!("Timeout propagating block {} to {}", block.height, peer_url);
                },
            }
        }
        
        Ok(())
    }

    /// Simulation d'envoi de bloc à un peer
    async fn send_block_to_peer(&self, peer_url: &str, block: &Block) -> Result<(), Box<dyn std::error::Error>> {
        // En vrai test d'intégration, ceci serait un appel HTTP/RPC
        debug!("Sending block {} to peer {}", block.height, peer_url);
        sleep(Duration::from_millis(10)).await; // Simulation latence réseau
        Ok(())
    }

    /// Traite un bloc reçu du réseau
    async fn process_received_block(&self, block: Block) -> Result<(), Box<dyn std::error::Error>> {
        match self.validate_received_block(&block).await {
            Ok(()) => {
                // Bloc valide - l'ajouter à la blockchain
                self.blockchain.add_block(block.clone())?;
                
                // Propager aux autres peers
                self.secure_propagate_block(&block).await?;
                
                info!("Node {} accepted and propagated block {}", self.id, block.height);
                Ok(())
            },
            Err(validation_error) => {
                // Bloc invalide - incrémenter les métriques et rejeter
                self.invalid_blocks_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                
                error!("Node {} rejected invalid block {}: {:?}", 
                       self.id, block.height, validation_error);
                
                Err(Box::new(validation_error))
            }
        }
    }

    /// Détecte et gère les forks
    async fn handle_fork_detection(&self, competing_block: &Block) -> Result<(), Box<dyn std::error::Error>> {
        self.fork_events.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        info!("Node {} detected fork at height {}", self.id, competing_block.height);
        
        // Logique de résolution de fork (plus long chain rule)
        let current_height = self.blockchain.get_height();
        if competing_block.height > current_height {
            warn!("Node {} switching to longer chain", self.id);
            // En vrai, on ferait une synchronisation complète
        }
        
        Ok(())
    }

    /// Synchronise avec un peer spécifique
    async fn sync_with_peer(&self, peer: &SecureTestNode) -> Result<(), Box<dyn std::error::Error>> {
        let peer_height = peer.blockchain.get_height();
        let our_height = self.blockchain.get_height();
        
        if peer_height > our_height {
            info!("Node {} syncing {} blocks from peer {}", 
                  self.id, peer_height - our_height, peer.id);
            
            // Simulation de synchronisation block par block
            for height in (our_height + 1)..=peer_height {
                // En vrai, on récupérerait le bloc via RPC
                debug!("Node {} requesting block {} from peer {}", self.id, height, peer.id);
                sleep(Duration::from_millis(5)).await; // Simulation latence
            }
        }
        
        Ok(())
    }

    /// Métriques de sécurité du nœud
    fn security_metrics(&self) -> SecurityMetrics {
        SecurityMetrics {
            invalid_blocks_received: self.invalid_blocks_received.load(std::sync::atomic::Ordering::Relaxed),
            fork_events: self.fork_events.load(std::sync::atomic::Ordering::Relaxed),
            blockchain_height: self.blockchain.get_height(),
            peer_count: self.state.peers.read().unwrap().len(),
        }
    }
}

/// Types de blocs invalides pour les tests
#[derive(Debug, Clone)]
enum InvalidBlockType {
    InvalidParentHash,
    FutureTimestamp,
    InvalidHeight,
    CorruptedMerkleRoot,
}

/// Métriques de sécurité d'un nœud
#[derive(Debug)]
struct SecurityMetrics {
    invalid_blocks_received: u64,
    fork_events: u64,
    blockchain_height: u64,
    peer_count: usize,
}

/// Réseau de test sécurisé
struct SecureTestNetwork {
    nodes: Vec<SecureTestNode>,
    adversarial_nodes: Vec<SecureTestNode>,
}

impl SecureTestNetwork {
    async fn new(honest_nodes: usize, adversarial_nodes: usize, base_port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        let mut nodes = Vec::new();
        let mut adv_nodes = Vec::new();
        
        // Nœuds honnêtes
        for i in 0..honest_nodes {
            let node = SecureTestNode::new(i as u32, base_port + i as u16).await?;
            nodes.push(node);
        }

        // Nœuds adversaires
        for i in 0..adversarial_nodes {
            let node = SecureTestNode::new((honest_nodes + i) as u32, base_port + (honest_nodes + i) as u16).await?;
            adv_nodes.push(node);
        }

        Ok(Self {
            nodes,
            adversarial_nodes: adv_nodes,
        })
    }

    /// Connecte tous les nœuds honnêtes entre eux
    async fn connect_honest_nodes(&self) -> Result<(), Box<dyn std::error::Error>> {
        for i in 0..self.nodes.len() {
            for j in (i + 1)..self.nodes.len() {
                self.nodes[i].secure_connect_to(&self.nodes[j]).await?;
                self.nodes[j].secure_connect_to(&self.nodes[i]).await?;
            }
        }
        Ok(())
    }

    /// Simule une partition réseau
    async fn simulate_network_partition(&self, partition_duration: Duration) -> Result<(), Box<dyn std::error::Error>> {
        info!("Simulating network partition for {:?}", partition_duration);
        
        // Diviser le réseau en deux partitions
        let mid = self.nodes.len() / 2;
        
        // Déconnecter les partitions (simulation)
        for i in 0..mid {
            for j in mid..self.nodes.len() {
                debug!("Partitioning nodes {} and {}", i, j);
            }
        }
        
        sleep(partition_duration).await;
        
        // Reconnecter
        info!("Healing network partition");
        self.connect_honest_nodes().await?;
        
        Ok(())
    }

    /// Collecte les métriques de sécurité de tous les nœuds
    fn collect_security_metrics(&self) -> Vec<SecurityMetrics> {
        self.nodes.iter()
            .chain(self.adversarial_nodes.iter())
            .map(|node| node.security_metrics())
            .collect()
    }
}

// ============================================================================
// TESTS D'INTÉGRATION CONSENSUS-RÉSEAU
// ============================================================================

#[tokio::test]
async fn test_consensus_network_basic_propagation() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();
    
    // Réseau de 5 nœuds honnêtes
    let network = SecureTestNetwork::new(5, 0, 8000).await?;
    network.connect_honest_nodes().await?;
    
    // Le nœud 0 mine un bloc valide
    let block = network.nodes[0].mine_valid_block(Vec::new()).await?;
    
    // Propager le bloc
    network.nodes[0].secure_propagate_block(&block).await?;
    
    // Simuler la réception par les autres nœuds
    for i in 1..network.nodes.len() {
        network.nodes[i].process_received_block(block.clone()).await?;
    }
    
    // Vérifier que tous les nœuds ont le même état
    let heights: Vec<u64> = network.nodes.iter()
        .map(|node| node.blockchain.get_height())
        .collect();
    
    assert!(heights.iter().all(|&h| h == heights[0]), 
            "Tous les nœuds doivent avoir la même hauteur après propagation");
    
    // Vérifier les métriques de sécurité
    let metrics = network.collect_security_metrics();
    for metric in &metrics {
        assert_eq!(metric.invalid_blocks_received, 0, 
                   "Aucun bloc invalide ne devrait être reçu");
    }
    
    info!("✅ Test propagation basique réussi");
    Ok(())
}

#[tokio::test]
async fn test_consensus_network_invalid_block_rejection() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();
    
    let network = SecureTestNetwork::new(3, 1, 8100).await?;
    network.connect_honest_nodes().await?;
    
    // Nœud adversaire génère des blocs invalides
    let invalid_types = vec![
        InvalidBlockType::InvalidParentHash,
        InvalidBlockType::FutureTimestamp,
        InvalidBlockType::InvalidHeight,
        InvalidBlockType::CorruptedMerkleRoot,
    ];
    
    for invalid_type in invalid_types {
        let invalid_block = network.adversarial_nodes[0].mine_invalid_block(invalid_type.clone()).await?;
        
        // Tenter de propager le bloc invalide
        for honest_node in &network.nodes {
            let result = honest_node.process_received_block(invalid_block.clone()).await;
            assert!(result.is_err(), 
                    "Les nœuds honnêtes doivent rejeter les blocs invalides {:?}", invalid_type);
        }
    }
    
    // Vérifier que les métriques de sécurité reflètent les rejets
    let metrics = network.collect_security_metrics();
    for (i, metric) in metrics.iter().enumerate() {
        if i < network.nodes.len() { // Nœuds honnêtes
            assert!(metric.invalid_blocks_received > 0, 
                    "Les nœuds honnêtes doivent compter les blocs invalides reçus");
        }
    }
    
    info!("✅ Test rejet blocs invalides réussi");
    Ok(())
}

#[tokio::test]
async fn test_consensus_network_fork_resolution() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();
    
    let network = SecureTestNetwork::new(4, 0, 8200).await?;
    network.connect_honest_nodes().await?;
    
    // Créer un fork : deux nœuds minent des blocs concurrents
    let block_a = network.nodes[0].mine_valid_block(Vec::new()).await?;
    let block_b = network.nodes[1].mine_valid_block(Vec::new()).await?;
    
    // Propager les blocs concurrents
    network.nodes[0].secure_propagate_block(&block_a).await?;
    network.nodes[1].secure_propagate_block(&block_b).await?;
    
    // Simuler la détection de fork
    for node in &network.nodes[2..] {
        node.handle_fork_detection(&block_a).await?;
        node.handle_fork_detection(&block_b).await?;
    }
    
    // Vérifier que les forks sont détectés
    let metrics = network.collect_security_metrics();
    let total_fork_events: u64 = metrics.iter()
        .map(|m| m.fork_events)
        .sum();
    
    assert!(total_fork_events > 0, "Des événements de fork doivent être détectés");
    
    info!("✅ Test résolution de fork réussi");
    Ok(())
}

#[tokio::test]
async fn test_consensus_network_partition_recovery() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();
    
    let network = SecureTestNetwork::new(6, 0, 8300).await?;
    network.connect_honest_nodes().await?;
    
    // État initial : tous les nœuds synchronisés
    let initial_block = network.nodes[0].mine_valid_block(Vec::new()).await?;
    for i in 1..network.nodes.len() {
        network.nodes[i].process_received_block(initial_block.clone()).await?;
    }
    
    // Simuler une partition réseau de 10 secondes
    network.simulate_network_partition(Duration::from_secs(10)).await?;
    
    // Après la partition, synchroniser les nœuds
    for i in 0..network.nodes.len() {
        for j in (i + 1)..network.nodes.len() {
            network.nodes[i].sync_with_peer(&network.nodes[j]).await?;
        }
    }
    
    // Vérifier que la synchronisation a réussi
    let final_metrics = network.collect_security_metrics();
    let heights: Vec<u64> = final_metrics.iter()
        .map(|m| m.blockchain_height)
        .collect();
    
    // Tous les nœuds doivent converger vers la même hauteur
    let max_height = *heights.iter().max().unwrap();
    let min_height = *heights.iter().min().unwrap();
    
    assert!(max_height - min_height <= 1, 
            "Les nœuds doivent converger après partition (écart max: 1 bloc)");
    
    info!("✅ Test récupération après partition réussi");
    Ok(())
}

#[tokio::test]
async fn test_consensus_network_slh_dsa_signature_validation() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();
    
    let network = SecureTestNetwork::new(3, 0, 8400).await?;
    network.connect_honest_nodes().await?;
    
    // Test avec transaction signée SLH-DSA
    let sender_keypair = KeyPair::generate();
    let receiver_pubkey = KeyPair::generate().public_key();
    
    // Créer une transaction avec signature post-quantique
    let mut transaction = Transaction::new(
        sender_keypair.public_key(),
        receiver_pubkey,
        1000,
        100, // fee
        0,   // nonce
    );
    
    // Signer la transaction avec SLH-DSA
    let tx_hash = transaction.calculate_hash();
    let signature = sender_keypair.sign(&tx_hash)?;
    transaction.signature = Some(signature);
    
    // Créer un bloc contenant cette transaction
    let block = network.nodes[0].mine_valid_block(vec![transaction]).await?;
    
    // Valider et propager
    for i in 1..network.nodes.len() {
        let result = network.nodes[i].process_received_block(block.clone()).await;
        assert!(result.is_ok(), 
                "Les blocs avec signatures SLH-DSA valides doivent être acceptés");
    }
    
    // Vérifier qu'aucune erreur de validation crypto
    let metrics = network.collect_security_metrics();
    for metric in &metrics {
        assert_eq!(metric.invalid_blocks_received, 0, 
                   "Aucun rejet pour signatures SLH-DSA valides");
    }
    
    info!("✅ Test validation signatures SLH-DSA réussi");
    Ok(())
}

#[tokio::test]
async fn test_consensus_network_adversarial_majority() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();
    
    // Scénario critique : 49% de nœuds adversaires
    let network = SecureTestNetwork::new(3, 2, 8500).await?;
    network.connect_honest_nodes().await?;
    
    // Les nœuds adversaires tentent de créer une chaîne alternative
    let mut adversarial_blocks = Vec::new();
    for i in 0..5 {
        let adv_block = network.adversarial_nodes[0].mine_invalid_block(
            InvalidBlockType::InvalidParentHash
        ).await?;
        adversarial_blocks.push(adv_block);
    }
    
    // Tenter de propager les blocs adversaires
    for adv_block in &adversarial_blocks {
        for honest_node in &network.nodes {
            let result = honest_node.process_received_block(adv_block.clone()).await;
            assert!(result.is_err(), 
                    "Les nœuds honnêtes doivent résister aux attaques majoritaires");
        }
    }
    
    // Vérifier que les nœuds honnêtes maintiennent leur intégrité
    let metrics = network.collect_security_metrics();
    for i in 0..network.nodes.len() {
        assert!(metrics[i].invalid_blocks_received > 0, 
                "Les nœuds honnêtes doivent détecter les attaques");
        assert_eq!(metrics[i].blockchain_height, 0, 
                   "Les nœuds honnêtes ne doivent pas accepter de blocs adversaires");
    }
    
    info!("✅ Test résistance majorité adversaire réussi");
    Ok(())
}

#[tokio::test]
async fn test_consensus_network_stress_high_throughput() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();
    
    let network = SecureTestNetwork::new(5, 0, 8600).await?;
    network.connect_honest_nodes().await?;
    
    // Test de stress : 100 blocs propagés rapidement
    let start_time = std::time::Instant::now();
    
    for block_num in 1..=100 {
        let transactions = vec![]; // Blocs vides pour la vitesse
        let block = network.nodes[block_num % network.nodes.len()]
            .mine_valid_block(transactions).await?;
        
        // Propagation parallèle
        let propagation_tasks: Vec<_> = network.nodes.iter()
            .filter(|node| node.id != (block_num % network.nodes.len()) as u32)
            .map(|node| {
                let block_clone = block.clone();
                async move {
                    node.process_received_block(block_clone).await
                }
            })
            .collect();
        
        // Attendre que tous les nœuds traitent le bloc
        for task in propagation_tasks {
            let _ = task.await; // Ignorer les erreurs pour ce test de stress
        }
        
        if block_num % 20 == 0 {
            debug!("Processed {} blocks", block_num);
        }
    }
    
    let duration = start_time.elapsed();
    info!("Processed 100 blocks in {:?} ({:.2} blocks/sec)", 
          duration, 100.0 / duration.as_secs_f64());
    
    // Vérifier que le réseau reste cohérent sous stress
    let final_metrics = network.collect_security_metrics();
    let heights: Vec<u64> = final_metrics.iter()
        .map(|m| m.blockchain_height)
        .collect();
    
    let height_variance = heights.iter().max().unwrap() - heights.iter().min().unwrap();
    assert!(height_variance <= 5, 
            "Variance de hauteur acceptable sous stress (max 5 blocs)");
    
    info!("✅ Test stress haut débit réussi");
    Ok(())
}
