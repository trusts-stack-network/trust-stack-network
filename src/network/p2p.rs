//! TSN P2P Network Layer using libp2p
//!
//! Provides:
//! - **GossipSub** for block/transaction propagation (push-based)
//! - **Kademlia DHT** for peer discovery
//! - **AutoNAT + Relay + DCUtR** for NAT traversal
//! - **Identify** for peer metadata exchange
//! - Node identity via Ed25519 keypair (PeerID)
//!
//! This module runs alongside the existing HTTP API (which serves
//! wallet, explorer, and external tools). The P2P layer handles
//! real-time block/tx propagation between nodes.

use libp2p::{
    autonat, dcutr, gossipsub, identify, kad, noise, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
    futures::StreamExt,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn, error, debug};

/// GossipSub topic names
const TOPIC_BLOCKS: &str = "tsn/blocks/1";
const TOPIC_TRANSACTIONS: &str = "tsn/transactions/1";

/// P2P configuration
pub struct P2pConfig {
    /// Port to listen on for P2P connections
    pub listen_port: u16,
    /// Bootstrap peer addresses with known PeerIDs (multiaddr format)
    pub bootstrap_peers: Vec<(PeerId, Multiaddr)>,
    /// Seed addresses to dial (PeerID unknown — discovered via Identify)
    pub dial_seeds: Vec<Multiaddr>,
    /// Whether to act as a relay server (seeds should enable this)
    pub relay_server: bool,
    /// Network name for protocol identification
    pub protocol_version: String,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            listen_port: 9334,
            bootstrap_peers: Vec::new(),
            dial_seeds: Vec::new(),
            relay_server: false,
            protocol_version: format!("tsn/{}", env!("CARGO_PKG_VERSION")),
        }
    }
}

/// Events emitted by the P2P layer to the application
#[derive(Debug)]
pub enum P2pEvent {
    /// A new block was received via GossipSub
    NewBlock(Vec<u8>),
    /// A new transaction was received via GossipSub
    NewTransaction(Vec<u8>),
    /// A new peer connected
    PeerConnected(PeerId),
    /// A peer disconnected
    PeerDisconnected(PeerId),
    /// NAT status detected
    NatStatus(String),
}

/// Commands sent to the P2P layer from the application
#[derive(Debug)]
pub enum P2pCommand {
    /// Broadcast a mined block to the network
    BroadcastBlock(Vec<u8>),
    /// Broadcast a transaction to the network
    BroadcastTransaction(Vec<u8>),
    /// Get the list of connected peers
    GetPeers(tokio::sync::oneshot::Sender<Vec<PeerInfo>>),
}

/// Information about a connected peer
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub height: Option<u64>,
    pub protocol: String,
}

/// Combined libp2p behaviour for TSN
#[derive(NetworkBehaviour)]
pub struct TsnBehaviour {
    /// Block and transaction propagation
    pub gossipsub: gossipsub::Behaviour,
    /// Peer discovery via DHT
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    /// Peer identification and metadata exchange
    pub identify: identify::Behaviour,
    /// NAT detection
    pub autonat: autonat::Behaviour,
    /// Relay client (for nodes behind NAT)
    pub relay_client: relay::client::Behaviour,
    /// Relay server (for seed nodes that help NAT traversal)
    pub relay_server: relay::Behaviour,
    /// Direct connection upgrade through relay (hole punching)
    pub dcutr: dcutr::Behaviour,
}

/// The P2P node handle — used by the application to interact with the P2P layer
pub struct P2pNode {
    /// Send commands to the P2P event loop
    pub command_tx: mpsc::Sender<P2pCommand>,
    /// Receive events from the P2P event loop
    pub event_rx: mpsc::Receiver<P2pEvent>,
    /// Our PeerId
    pub peer_id: PeerId,
    /// Our local keypair (for signing)
    local_key: libp2p::identity::Keypair,
}

impl P2pNode {
    /// Create and start a new P2P node.
    /// Returns the node handle and spawns the event loop as a tokio task.
    pub async fn start(config: P2pConfig) -> anyhow::Result<Self> {
        // Generate or load Ed25519 keypair for P2P identity
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(local_key.public());

        info!("P2P node starting with PeerID: {}", peer_id);

        // Build the swarm with all behaviours
        let mut swarm = SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_quic()
            .with_relay_client(noise::Config::new, yamux::Config::default)?
            .with_behaviour(|key, relay_client| {
                // GossipSub with message deduplication
                // M7 audit fix: use Blake2s (crypto hash) instead of DefaultHasher (SipHash)
                // SipHash is not collision-resistant — an attacker could craft messages
                // with the same SipHash to bypass deduplication.
                let message_id_fn = |message: &gossipsub::Message| {
                    use blake2::{Blake2s256, Digest};
                    let mut hasher = Blake2s256::new();
                    hasher.update(&message.data);
                    let hash = hasher.finalize();
                    gossipsub::MessageId::from(hex::encode(hash))
                };

                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_millis(700)) // ETH2/Polkadot standard (was 5s)
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .message_id_fn(message_id_fn)
                    .max_transmit_size(1 * 1024 * 1024) // M6 audit fix: 1MB max (was 4MB — too large for gossip)
                    .flood_publish(false) // Mesh-only propagation: O(D×N) instead of O(N²) flood
                    .mesh_n_low(4)        // ETH2-inspired mesh params for 100+ nodes
                    .mesh_n(6)            // 6 mesh peers (scales to log_6(500) = 3.5 hops)
                    .mesh_n_high(12)      // Prune if too many mesh connections
                    .mesh_outbound_min(2) // Min outbound for partition resistance
                    .gossip_lazy(6)       // IHAVE/IWANT backup for nodes outside mesh
                    .history_length(10)   // Keep 10 heartbeats of message history
                    .history_gossip(3)    // Announce last 3 heartbeats via gossip
                    .fanout_ttl(Duration::from_secs(60))
                    .build()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )?;

                // Kademlia DHT
                let mut kademlia = kad::Behaviour::new(
                    peer_id,
                    kad::store::MemoryStore::new(peer_id),
                );
                kademlia.set_mode(Some(kad::Mode::Server));

                // Identify protocol
                let identify = identify::Behaviour::new(
                    identify::Config::new(
                        config.protocol_version.clone(),
                        key.public(),
                    )
                    .with_push_listen_addr_updates(true)
                    .with_interval(Duration::from_secs(60)),
                );

                // AutoNAT
                let autonat = autonat::Behaviour::new(
                    peer_id,
                    autonat::Config {
                        retry_interval: Duration::from_secs(30),
                        refresh_interval: Duration::from_secs(60),
                        ..Default::default()
                    },
                );

                // Relay server
                let relay_server = relay::Behaviour::new(
                    peer_id,
                    relay::Config::default(),
                );

                // DCUtR (hole punching)
                let dcutr = dcutr::Behaviour::new(peer_id);

                Ok(TsnBehaviour {
                    gossipsub,
                    kademlia,
                    identify,
                    autonat,
                    relay_client,
                    relay_server,
                    dcutr,
                })
            })?
            .with_swarm_config(|c| {
                c.with_idle_connection_timeout(Duration::from_secs(120))
            })
            .build();

        // Subscribe to topics
        let block_topic = gossipsub::IdentTopic::new(TOPIC_BLOCKS);
        let tx_topic = gossipsub::IdentTopic::new(TOPIC_TRANSACTIONS);
        swarm.behaviour_mut().gossipsub.subscribe(&block_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&tx_topic)?;

        // Listen on TCP and QUIC
        let listen_addr_tcp: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", config.listen_port).parse()?;
        let listen_addr_quic: Multiaddr = format!("/ip4/0.0.0.0/udp/{}/quic-v1", config.listen_port).parse()?;
        swarm.listen_on(listen_addr_tcp)?;
        swarm.listen_on(listen_addr_quic)?;

        // Add bootstrap peers with known PeerIDs to Kademlia
        for (peer, addr) in &config.bootstrap_peers {
            swarm.behaviour_mut().kademlia.add_address(peer, addr.clone());
            swarm.dial(addr.clone()).ok();
            info!("Dialing bootstrap peer: {} at {}", peer, addr);
        }

        // Dial seed nodes (PeerID unknown — Identify protocol will exchange them)
        for addr in &config.dial_seeds {
            match swarm.dial(addr.clone()) {
                Ok(_) => info!("Dialing P2P seed..."),
                Err(e) => warn!("Failed to dial P2P seed: {:?}", e),
            }
        }

        // Bootstrap Kademlia if we have peers
        if !config.bootstrap_peers.is_empty() {
            if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
                warn!("Kademlia bootstrap failed: {:?}", e);
            }
        }

        // Schedule a delayed Kademlia bootstrap (after Identify exchanges PeerIDs)
        let delayed_bootstrap = !config.dial_seeds.is_empty();

        // Create channels for communication with application
        let (event_tx, event_rx) = mpsc::channel(1024);
        let (command_tx, command_rx) = mpsc::channel(1024);

        // Spawn the event loop (with seed addresses for periodic redial)
        let seed_addrs = config.dial_seeds.clone();
        tokio::spawn(p2p_event_loop(swarm, event_tx, command_rx, seed_addrs));

        Ok(P2pNode {
            command_tx,
            event_rx,
            peer_id,
            local_key,
        })
    }

    /// Broadcast a block to the network
    pub async fn broadcast_block(&self, block_data: Vec<u8>) -> anyhow::Result<()> {
        self.command_tx.send(P2pCommand::BroadcastBlock(block_data)).await?;
        Ok(())
    }

    /// Broadcast a transaction to the network
    pub async fn broadcast_transaction(&self, tx_data: Vec<u8>) -> anyhow::Result<()> {
        self.command_tx.send(P2pCommand::BroadcastTransaction(tx_data)).await?;
        Ok(())
    }

    /// Get connected peers
    pub async fn get_peers(&self) -> Vec<PeerInfo> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.command_tx.send(P2pCommand::GetPeers(tx)).await.is_ok() {
            rx.await.unwrap_or_default()
        } else {
            Vec::new()
        }
    }
}

/// The main P2P event loop — runs as a background task
async fn p2p_event_loop(
    mut swarm: Swarm<TsnBehaviour>,
    event_tx: mpsc::Sender<P2pEvent>,
    mut command_rx: mpsc::Receiver<P2pCommand>,
    seed_addrs: Vec<Multiaddr>,
) {
    let block_topic = gossipsub::IdentTopic::new(TOPIC_BLOCKS);
    let tx_topic = gossipsub::IdentTopic::new(TOPIC_TRANSACTIONS);

    // Track identified peers to avoid spam logging
    let mut identified_peers: std::collections::HashSet<PeerId> = std::collections::HashSet::new();
    // Track peer heights (updated via block-announces and identify)
    let mut peer_heights: std::collections::HashMap<PeerId, u64> = std::collections::HashMap::new();

    // Periodic redial timer for seeds (every 30s if not enough peers)
    let mut redial_interval = tokio::time::interval(Duration::from_secs(30));
    redial_interval.tick().await; // skip first immediate tick

    loop {
        tokio::select! {
            // Periodically redial seeds if we have few P2P peers
            _ = redial_interval.tick() => {
                let connected = swarm.connected_peers().count();
                if connected < 3 && !seed_addrs.is_empty() {
                    debug!("P2P: {} peers connected, redialing {} seeds...", connected, seed_addrs.len());
                    for addr in &seed_addrs {
                        swarm.dial(addr.clone()).ok();
                    }
                }
            }
            // Handle incoming swarm events
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(TsnBehaviourEvent::Gossipsub(
                        gossipsub::Event::Message { message, .. }
                    )) => {
                        let topic = message.topic.as_str();
                        if topic == block_topic.hash().as_str() {
                            debug!("Received block via GossipSub ({} bytes)", message.data.len());
                            // Track sender's height from the block
                            if let Some(source) = message.source {
                                // Try to parse height from the block data (coinbase.height)
                                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&message.data) {
                                    if let Some(h) = v.get("coinbase").and_then(|c| c.get("height")).and_then(|h| h.as_u64()) {
                                        peer_heights.insert(source, h);
                                    }
                                }
                            }
                            event_tx.send(P2pEvent::NewBlock(message.data)).await.ok();
                        } else if topic == tx_topic.hash().as_str() {
                            debug!("Received transaction via GossipSub ({} bytes)", message.data.len());
                            event_tx.send(P2pEvent::NewTransaction(message.data)).await.ok();
                        }
                    }
                    SwarmEvent::Behaviour(TsnBehaviourEvent::Identify(
                        identify::Event::Received { peer_id, info, .. }
                    )) => {
                        // Only log first identification per peer (avoid spam)
                        if identified_peers.insert(peer_id) {
                            info!("P2P: identified peer {} — {}",
                                &peer_id.to_string()[..16],
                                info.protocol_version,
                            );

                            // FORK PROTECTION: disconnect peers with incompatible protocol version
                            if !info.protocol_version.starts_with("tsn/") {
                                warn!("P2P: disconnecting peer {} — not a TSN node ({})",
                                    &peer_id.to_string()[..16], info.protocol_version);
                                let _ = swarm.disconnect_peer_id(peer_id);
                                continue;
                            }
                            // Signal peer version to auto-update system
                            if let Some(ver) = info.protocol_version.strip_prefix("tsn/") {
                                crate::network::auto_update::notify_peer_version(ver);
                            }
                        }
                        // Add discovered addresses to Kademlia
                        for addr in &info.listen_addrs {
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                        }
                        // Bootstrap Kademlia now that we know a peer
                        let _ = swarm.behaviour_mut().kademlia.bootstrap();
                    }
                    SwarmEvent::Behaviour(TsnBehaviourEvent::Autonat(
                        autonat::Event::StatusChanged { old, new }
                    )) => {
                        let status_str = match &new {
                            autonat::NatStatus::Public(_) => "public".to_string(),
                            autonat::NatStatus::Private => "private (behind NAT)".to_string(),
                            autonat::NatStatus::Unknown => "unknown".to_string(),
                        };
                        info!("P2P: NAT status = {}", status_str);

                        // If behind NAT, listen on relay circuit through connected peers
                        if matches!(new, autonat::NatStatus::Private) {
                            let connected: Vec<PeerId> = swarm.connected_peers().cloned().collect();
                            for relay_peer in connected.iter().take(2) {
                                let relay_addr: Multiaddr = format!(
                                    "/p2p/{}/p2p-circuit",
                                    relay_peer
                                ).parse().unwrap();
                                match swarm.listen_on(relay_addr) {
                                    Ok(_) => info!("P2P: listening via relay through {}", &relay_peer.to_string()[..16]),
                                    Err(e) => debug!("P2P: relay listen failed: {:?}", e),
                                }
                            }
                        }

                        event_tx.send(P2pEvent::NatStatus(status_str)).await.ok();
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        debug!("P2P peer connected: {}", peer_id);
                        event_tx.send(P2pEvent::PeerConnected(peer_id)).await.ok();
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        debug!("P2P peer disconnected: {}", peer_id);
                        identified_peers.remove(&peer_id);
                        peer_heights.remove(&peer_id);
                        event_tx.send(P2pEvent::PeerDisconnected(peer_id)).await.ok();
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        // Log relay circuit addresses (not direct IPs)
                        let addr_str = address.to_string();
                        if addr_str.contains("p2p-circuit") {
                            info!("P2P: reachable via relay at {}", &addr_str[..addr_str.len().min(60)]);
                        }
                    }
                    _ => {}
                }
            }
            // Handle commands from the application
            Some(cmd) = command_rx.recv() => {
                match cmd {
                    P2pCommand::BroadcastBlock(data) => {
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(block_topic.clone(), data) {
                            warn!("Failed to publish block: {:?}", e);
                        }
                    }
                    P2pCommand::BroadcastTransaction(data) => {
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(tx_topic.clone(), data) {
                            warn!("Failed to publish transaction: {:?}", e);
                        }
                    }
                    P2pCommand::GetPeers(reply) => {
                        let peers: Vec<PeerInfo> = swarm.connected_peers()
                            .map(|p| PeerInfo {
                                peer_id: p.to_string(),
                                height: peer_heights.get(p).copied(),
                                protocol: "tsn/1.1.0".to_string(),
                            })
                            .collect();
                        reply.send(peers).ok();
                    }
                }
            }
        }
    }
}

/// Convert DNS seed URLs to libp2p multiaddrs.
/// Extracts the IP and HTTP port from each seed URL, then uses HTTP_port + 1 as the P2P port.
/// This ensures that nodes on any HTTP port correctly dial seeds on their actual P2P port.
pub fn seeds_to_bootstrap(seed_urls: &[String], _local_p2p_port: u16) -> Vec<Multiaddr> {
    seed_urls.iter().filter_map(|url| {
        // Extract IP and port from "http://1.2.3.4:9333"
        let stripped = url.trim_start_matches("http://").trim_start_matches("https://");
        let mut parts = stripped.split(':');
        let ip = parts.next()?;
        // Parse the seed's HTTP port (default 9333), then P2P = HTTP + 1
        let seed_http_port: u16 = parts.next()
            .and_then(|p| p.trim_matches('/').parse().ok())
            .unwrap_or(9333);
        let seed_p2p_port = seed_http_port + 1;
        let addr: Multiaddr = format!("/ip4/{}/tcp/{}", ip, seed_p2p_port).parse().ok()?;
        Some(addr)
    }).collect()
}
