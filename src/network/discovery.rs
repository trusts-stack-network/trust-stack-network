use std::sync::{Arc, Mutex};
use tokio::time::interval;
use std::time::{Duration, Instant};
use tracing::{info, debug, warn};

use crate::network::api::AppState;
use crate::network::peer_id;

/// Intervalle entre les tentatives de découverte
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(60);

/// Timeout pour les requêtes HTTP de découverte
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Max retry attempts avant d'activer le circuit breaker
const MAX_RETRY_ATTEMPTS: u32 = 3;

/// Limite maximale de peers à découvrir
#[allow(dead_code)]
const MAX_PEERS: usize = 50;

/// Durée minimum avant de réessayer quand le circuit breaker est ouvert
const CIRCUIT_BREAKER_COOLDOWN: Duration = Duration::from_secs(300); // 5 minutes

/// État du circuit breaker
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
enum CircuitState {
    Closed,   // Normal operation
    Open,     // Blocking requests due to failures
    HalfOpen, // Testing if service is back up
}

/// Circuit breaker pour éviter les retry loops infinis
#[derive(Debug)]
#[allow(dead_code)]
struct CircuitBreaker {
    state: CircuitState,
    failure_count: u32,
    last_failure_time: Option<Instant>,
    success_threshold: u32,
    failure_threshold: u32,
}

impl CircuitBreaker {
    fn new() -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            last_failure_time: None,
            success_threshold: 1, // Une réussite suffit pour fermer le circuit
            failure_threshold: MAX_RETRY_ATTEMPTS,
        }
    }

    fn can_proceed(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                if let Some(last_failure) = self.last_failure_time {
                    if last_failure.elapsed() >= CIRCUIT_BREAKER_COOLDOWN {
                        self.state = CircuitState::HalfOpen;
                        info!("Circuit breaker entering HALF_OPEN state");
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => true,
        }
    }

    #[allow(dead_code)]
    fn record_success(&mut self) {
        match self.state {
            CircuitState::HalfOpen => {
                self.state = CircuitState::Closed;
                self.failure_count = 0;
                info!("Circuit breaker CLOSED - service recovered");
            }
            CircuitState::Closed => {
                // Reset failure count on success
                self.failure_count = 0;
            }
            _ => {}
        }
    }

    #[allow(dead_code)]
    fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure_time = Some(Instant::now());

        if self.failure_count >= self.failure_threshold {
            self.state = CircuitState::Open;
            warn!("Circuit breaker OPENED due to {} consecutive failures", self.failure_count);
        }
    }
}

/// Découverte de pairs via gossip avec circuit breaker
pub async fn discovery_loop(state: Arc<AppState>) {
    let mut ticker = interval(DISCOVERY_INTERVAL);
    let client = reqwest::Client::builder()
        .timeout(DISCOVERY_TIMEOUT)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let circuit_breaker = Arc::new(Mutex::new(CircuitBreaker::new()));
    let _backoff_delay = Duration::from_secs(1);
    let _max_backoff = Duration::from_secs(300); // 5 minutes max

    loop {
        ticker.tick().await;

        // Vérifier si le circuit breaker permet de continuer
        let can_proceed = {
            let mut cb = circuit_breaker.lock().unwrap();
            cb.can_proceed()
        };

        if !can_proceed {
            debug!("Circuit breaker is OPEN, skipping discovery attempt");
            continue;
        }

        // Récupère la liste des pairs connus
        let peers: Vec<String> = {
            let peers_guard = state.peers.read().unwrap();
            peers_guard.clone()
        };

        // Annonce à chaque pair et découvre de nouveaux pairs
        for peer in &peers {
            // Announce ourselves to the peer
            if let Err(e) = announce_to_peer(&client, peer, &state).await {
                debug!("Failed to announce to peer {}: {}", peer, e);
            }

            // Fetch their peer list for discovery
            match discover_peers(&client, peer).await {
                Ok(new_peers) => {
                    let our_port = crate::config::get_port();
                    let public_url = state.public_url.as_deref().unwrap_or("");
                    let mut peers_guard = state.peers.write().unwrap();
                    for new_peer in new_peers {
                        // Avoid adding localhost/self and duplicates
                        if new_peer.contains("://localhost")
                            || new_peer.contains("://127.0.0.1")
                            || new_peer.contains("://0.0.0.0")
                        {
                            continue;
                        }
                        // Skip our own public URL
                        let normalized = normalize_url(&new_peer);
                        if !public_url.is_empty() && normalized == normalize_url(public_url) {
                            debug!("Skipping self (public_url): {}", new_peer);
                            continue;
                        }
                        // Skip if the peer URL contains our own port on our own IP
                        // (catches cases where our IP was announced back to us)
                        if let Some(ref pub_url) = state.public_url {
                            let pub_norm = normalize_url(pub_url);
                            if normalized == pub_norm {
                                continue;
                            }
                        }
                        // Also skip if peer matches our announced port on 0.0.0.0
                        let self_announce = format!("://0.0.0.0:{}", our_port);
                        if new_peer.contains(&self_announce) {
                            continue;
                        }
                        if !peers_guard.iter().any(|p| normalize_url(p) == normalized) {
                            info!("Discovered new peer: {}", peer_id(&new_peer));
                            peers_guard.push(new_peer);
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to discover peers from {}: {}", peer, e);
                }
            }
        }
    }
}

/// Annonce ce nœud à un pair via POST /peers
async fn announce_to_peer(
    client: &reqwest::Client,
    peer: &str,
    state: &Arc<AppState>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Determine our external URL from the listening port
    let our_port = crate::config::get_port();
    let our_url = format!("http://0.0.0.0:{}", our_port);

    let url = format!("{}/peers", peer.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .json(&serde_json::json!({ "url": our_url }))
        .send()
        .await?;

    if resp.status().is_success() {
        debug!("Announced to peer {}", peer);
    }
    let _ = state; // AppState available for future use
    Ok(())
}

/// Découvre de nouveaux pairs via GET /peers
async fn discover_peers(
    client: &reqwest::Client,
    peer: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let url = format!("{}/peers", peer.trim_end_matches('/'));
    let resp = client.get(&url).send().await?;
    let body: serde_json::Value = resp.json().await?;
    let peers = body
        .get("peers")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    Ok(peers)
}

/// Normalise une URL de pair pour comparaison
fn normalize_url(url: &str) -> String {
    let mut s = url.trim().to_lowercase();
    while s.ends_with('/') {
        s.pop();
    }
    s
}

/// Information sur un pair
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub address: String,
    pub last_seen: Duration,
    pub capabilities: Vec<String>,
}

impl PeerInfo {
    pub fn new(address: String) -> Self {
        Self {
            address,
            last_seen: Duration::from_secs(0),
            capabilities: Vec::new(),
        }
    }
}

/// Gestionnaire de découverte
pub struct PeerDiscovery {
    known_peers: Vec<PeerInfo>,
}

impl PeerDiscovery {
    pub fn new() -> Self {
        Self {
            known_peers: Vec::new(),
        }
    }
    
    pub fn add_peer(&mut self, peer: PeerInfo) {
        if !self.known_peers.iter().any(|p| p.address == peer.address) {
            self.known_peers.push(peer);
        }
    }
    
    pub fn get_peers(&self) -> &[PeerInfo] {
        &self.known_peers
    }
}
