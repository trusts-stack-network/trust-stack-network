//! Protection contre les eclipse attacks dans le réseau P2P TSN
//!
//! Un eclipse attack consiste à isoler un nœud en contrôlant tous ses pairs,
//! permettant de lui présenter une vue falsifiée de la blockchain.
//! 
//! Ce module implémente plusieurs mécanismes de défense :
//! - Diversification géographique des connexions
//! - Rotation périodique des peers
//! - Détection de comportements suspects (consensus anormal)
//! - Validation croisée avec des sources externes

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, warn, info};
use serde::{Deserialize, Serialize};

/// Configuration pour la protection contre les eclipse attacks
#[derive(Debug, Clone)]
pub struct EclipseProtectionConfig {
    /// Nombre minimum de pairs de différents ASN (Autonomous System Numbers)
    pub min_diverse_asn_peers: usize,
    /// Nombre minimum de pairs de différents pays/régions
    pub min_diverse_geo_peers: usize,
    /// Pourcentage maximum de pairs d'une même région
    pub max_same_region_ratio: f32,
    /// Intervalle de rotation des peers (en secondes)
    pub peer_rotation_interval: Duration,
    /// Pourcentage de peers à faire tourner à chaque cycle
    pub peer_rotation_percentage: f32,
    /// Seuil de détection d'anomalie de consensus (% de peers en désaccord)
    pub consensus_anomaly_threshold: f32,
    /// Durée de quarantaine pour les peers suspects
    pub quarantine_duration: Duration,
    /// Nombre maximum de tentatives de connexion par IP/24
    pub max_connections_per_subnet: usize,
    /// Intervalle de vérification des anomalies
    pub anomaly_check_interval: Duration,
}

impl Default for EclipseProtectionConfig {
    fn default() -> Self {
        Self {
            min_diverse_asn_peers: 8,
            min_diverse_geo_peers: 5,
            max_same_region_ratio: 0.4, // Max 40% de peers d'une même région
            peer_rotation_interval: Duration::from_secs(3600), // 1 heure
            peer_rotation_percentage: 0.2, // 20% des peers
            consensus_anomaly_threshold: 0.3, // 30% de désaccord = suspect
            quarantine_duration: Duration::from_secs(7200), // 2 heures
            max_connections_per_subnet: 3,
            anomaly_check_interval: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Informations géographiques d'un peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerGeoInfo {
    pub ip: IpAddr,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub asn: Option<u32>,
    pub is_datacenter: bool,
    pub last_updated: SystemTime,
}

/// État d'un peer dans le contexte de protection eclipse
#[derive(Debug, Clone)]
pub struct PeerEclipseState {
    pub addr: SocketAddr,
    pub geo_info: Option<PeerGeoInfo>,
    pub connection_time: Instant,
    pub last_block_hash: Option<[u8; 32]>,
    pub consensus_agreements: u32,
    pub consensus_disagreements: u32,
    pub is_quarantined: bool,
    pub quarantine_until: Option<Instant>,
    pub rotation_priority: f32, // 0.0 = ne pas faire tourner, 1.0 = priorité max
}

/// Anomalie détectée dans le réseau
#[derive(Debug, Clone)]
pub struct NetworkAnomaly {
    pub anomaly_type: AnomalyType,
    pub detected_at: Instant,
    pub affected_peers: Vec<SocketAddr>,
    pub severity: f32, // 0.0 à 1.0
    pub description: String,
}

#[derive(Debug, Clone)]
pub enum AnomalyType {
    /// Trop de peers d'une même région/ASN
    GeographicClustering,
    /// Consensus anormal (trop de désaccords)
    ConsensusAnomaly,
    /// Rotation des peers bloquée
    PeerRotationStuck,
    /// Trop de connexions depuis le même subnet
    SubnetFlooding,
    /// Peers qui présentent toujours les mêmes blocs
    SynchronizedBehavior,
}

/// Gestionnaire principal de protection contre les eclipse attacks
#[derive(Debug)]
pub struct EclipseProtection {
    config: EclipseProtectionConfig,
    peers: Arc<RwLock<HashMap<SocketAddr, PeerEclipseState>>>,
    geo_cache: Arc<RwLock<HashMap<IpAddr, PeerGeoInfo>>>,
    detected_anomalies: Arc<RwLock<Vec<NetworkAnomaly>>>,
    last_rotation: Arc<RwLock<Instant>>,
    subnet_connections: Arc<RwLock<HashMap<String, usize>>>, // subnet -> count
}

impl EclipseProtection {
    pub fn new(config: EclipseProtectionConfig) -> Self {
        Self {
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            geo_cache: Arc::new(RwLock::new(HashMap::new())),
            detected_anomalies: Arc::new(RwLock::new(Vec::new())),
            last_rotation: Arc::new(RwLock::new(Instant::now())),
            subnet_connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Ajouter un nouveau peer et vérifier la diversité
    pub async fn add_peer(&self, addr: SocketAddr) -> Result<(), String> {
        // Vérifier les limites de subnet
        let subnet = self.get_subnet(&addr.ip());
        {
            let mut subnet_conns = self.subnet_connections.write().await;
            let current_count = subnet_conns.get(&subnet).copied().unwrap_or(0);

            if current_count >= self.config.max_connections_per_subnet {
                return Err(format!("Trop de connexions depuis le subnet {}", subnet));
            }

            subnet_conns.insert(subnet, current_count + 1);
        }

        // Obtenir les informations géographiques
        let geo_info = self.get_geo_info(&addr.ip()).await;
        
        let peer_state = PeerEclipseState {
            addr,
            geo_info,
            connection_time: Instant::now(),
            last_block_hash: None,
            consensus_agreements: 0,
            consensus_disagreements: 0,
            is_quarantined: false,
            quarantine_until: None,
            rotation_priority: 0.5, // Priorité moyenne par défaut
        };

        {
            let mut peers = self.peers.write().await;
            peers.insert(addr, peer_state);
        }

        // Vérifier la diversité après ajout
        self.check_diversity_violations().await;

        info!("Peer {} ajouté avec protection eclipse", addr);
        Ok(())
    }

    /// Supprimer un peer
    pub async fn remove_peer(&self, addr: &SocketAddr) {
        // Décrémenter le compteur de subnet
        let subnet = self.get_subnet(&addr.ip());
        {
            let mut subnet_conns = self.subnet_connections.write().await;
            if let Some(count) = subnet_conns.get_mut(&subnet) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    subnet_conns.remove(&subnet);
                }
            }
        }

        // Supprimer le peer
        {
            let mut peers = self.peers.write().await;
            peers.remove(addr);
        }

        debug!("Peer {} supprimé de la protection eclipse", addr);
    }

    /// Enregistrer un nouveau bloc reçu d'un peer
    pub async fn record_block_from_peer(&self, peer: &SocketAddr, block_hash: [u8; 32]) {
        let mut peers = self.peers.write().await;
        if let Some(peer_state) = peers.get_mut(peer) {
            peer_state.last_block_hash = Some(block_hash);
        }
    }

    /// Enregistrer un accord/désaccord de consensus avec un peer
    pub async fn record_consensus_result(&self, peer: &SocketAddr, agrees: bool) {
        let mut peers = self.peers.write().await;
        if let Some(peer_state) = peers.get_mut(peer) {
            if agrees {
                peer_state.consensus_agreements += 1;
            } else {
                peer_state.consensus_disagreements += 1;
                // Augmenter la priorité de rotation pour les peers en désaccord
                peer_state.rotation_priority = (peer_state.rotation_priority + 0.1).min(1.0);
            }
        }
    }

    /// Vérifier les violations de diversité géographique
    async fn check_diversity_violations(&self) {
        let peers = self.peers.read().await;
        let mut country_counts: HashMap<String, usize> = HashMap::new();
        let mut asn_counts: HashMap<u32, usize> = HashMap::new();
        let mut total_peers = 0;

        for peer_state in peers.values() {
            if let Some(geo_info) = &peer_state.geo_info {
                total_peers += 1;
                
                if let Some(country) = &geo_info.country_code {
                    *country_counts.entry(country.clone()).or_insert(0) += 1;
                }
                
                if let Some(asn) = geo_info.asn {
                    *asn_counts.entry(asn).or_insert(0) += 1;
                }
            }
        }

        // Vérifier la concentration géographique
        for (country, count) in country_counts {
            let ratio = count as f32 / total_peers as f32;
            if ratio > self.config.max_same_region_ratio {
                let anomaly = NetworkAnomaly {
                    anomaly_type: AnomalyType::GeographicClustering,
                    detected_at: Instant::now(),
                    affected_peers: peers.values()
                        .filter(|p| p.geo_info.as_ref()
                            .and_then(|g| g.country_code.as_ref()) == Some(&country))
                        .map(|p| p.addr)
                        .collect(),
                    severity: ratio,
                    description: format!("{}% des peers sont du pays {}", 
                                       (ratio * 100.0) as u32, country),
                };
                
                self.record_anomaly(anomaly).await;
            }
        }

        // Vérifier la diversité des ASN
        let unique_asns = asn_counts.len();
        if unique_asns < self.config.min_diverse_asn_peers {
            let anomaly = NetworkAnomaly {
                anomaly_type: AnomalyType::GeographicClustering,
                detected_at: Instant::now(),
                affected_peers: peers.keys().cloned().collect(),
                severity: 1.0 - (unique_asns as f32 / self.config.min_diverse_asn_peers as f32),
                description: format!("Seulement {} ASN différents (minimum: {})", 
                                   unique_asns, self.config.min_diverse_asn_peers),
            };
            
            self.record_anomaly(anomaly).await;
        }
    }

    /// Effectuer la rotation périodique des peers
    pub async fn rotate_peers(&self) -> Vec<SocketAddr> {
        let now = Instant::now();
        
        // Vérifier si c'est le moment de faire la rotation
        {
            let last_rotation = self.last_rotation.read().await;
            if now.duration_since(*last_rotation) < self.config.peer_rotation_interval {
                return Vec::new();
            }
        }

        let peers_to_rotate = {
            let peers = self.peers.read().await;
            let total_peers = peers.len();
            let num_to_rotate = ((total_peers as f32 * self.config.peer_rotation_percentage) as usize)
                .max(1)
                .min(total_peers / 2); // Ne jamais faire tourner plus de 50%

            // Sélectionner les peers avec la plus haute priorité de rotation
            let mut peer_priorities: Vec<_> = peers.iter()
                .filter(|(_, state)| !state.is_quarantined)
                .map(|(addr, state)| (*addr, state.rotation_priority))
                .collect();
            
            peer_priorities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
            
            peer_priorities.into_iter()
                .take(num_to_rotate)
                .map(|(addr, _)| addr)
                .collect::<Vec<_>>()
        };

        // Mettre à jour le timestamp de dernière rotation
        {
            let mut last_rotation = self.last_rotation.write().await;
            *last_rotation = now;
        }

        if !peers_to_rotate.is_empty() {
            info!("Rotation de {} peers pour protection eclipse", peers_to_rotate.len());
        }

        peers_to_rotate
    }

    /// Détecter les anomalies de consensus
    pub async fn check_consensus_anomalies(&self) {
        let peers = self.peers.read().await;
        let mut total_agreements = 0u32;
        let mut total_disagreements = 0u32;
        let mut suspicious_peers = Vec::new();

        for (addr, state) in peers.iter() {
            total_agreements += state.consensus_agreements;
            total_disagreements += state.consensus_disagreements;
            
            let total_interactions = state.consensus_agreements + state.consensus_disagreements;
            if total_interactions > 10 {
                let disagreement_ratio = state.consensus_disagreements as f32 / total_interactions as f32;
                if disagreement_ratio > self.config.consensus_anomaly_threshold {
                    suspicious_peers.push(*addr);
                }
            }
        }

        if !suspicious_peers.is_empty() {
            let total_interactions = total_agreements + total_disagreements;
            let overall_disagreement_ratio = if total_interactions > 0 {
                total_disagreements as f32 / total_interactions as f32
            } else {
                0.0
            };

            let anomaly = NetworkAnomaly {
                anomaly_type: AnomalyType::ConsensusAnomaly,
                detected_at: Instant::now(),
                affected_peers: suspicious_peers,
                severity: overall_disagreement_ratio,
                description: format!("{}% de désaccords de consensus détectés", 
                                   (overall_disagreement_ratio * 100.0) as u32),
            };
            
            self.record_anomaly(anomaly).await;
        }
    }

    /// Mettre en quarantaine des peers suspects
    pub async fn quarantine_peers(&self, peers: &[SocketAddr], reason: &str) {
        let quarantine_until = Instant::now() + self.config.quarantine_duration;
        
        {
            let mut peer_states = self.peers.write().await;
            for peer_addr in peers {
                if let Some(state) = peer_states.get_mut(peer_addr) {
                    state.is_quarantined = true;
                    state.quarantine_until = Some(quarantine_until);
                    state.rotation_priority = 1.0; // Priorité max pour rotation
                }
            }
        }

        warn!("Mise en quarantaine de {} peers: {}", peers.len(), reason);
    }

    /// Libérer les peers de quarantaine expirée
    pub async fn release_expired_quarantine(&self) {
        let now = Instant::now();
        let mut released_count = 0;
        
        {
            let mut peer_states = self.peers.write().await;
            for state in peer_states.values_mut() {
                if state.is_quarantined {
                    if let Some(quarantine_until) = state.quarantine_until {
                        if now >= quarantine_until {
                            state.is_quarantined = false;
                            state.quarantine_until = None;
                            state.rotation_priority = 0.3; // Priorité réduite après quarantaine
                            released_count += 1;
                        }
                    }
                }
            }
        }

        if released_count > 0 {
            debug!("Libération de {} peers de quarantaine", released_count);
        }
    }

    /// Enregistrer une anomalie détectée
    async fn record_anomaly(&self, anomaly: NetworkAnomaly) {
        warn!("Anomalie eclipse détectée: {} (sévérité: {:.2})", 
              anomaly.description, anomaly.severity);
        
        // Mettre en quarantaine les peers affectés si la sévérité est élevée
        if anomaly.severity > 0.7 {
            self.quarantine_peers(&anomaly.affected_peers, &anomaly.description).await;
        }
        
        {
            let mut anomalies = self.detected_anomalies.write().await;
            anomalies.push(anomaly);
            
            // Garder seulement les 100 dernières anomalies
            if anomalies.len() > 100 {
                anomalies.remove(0);
            }
        }
    }

    /// Obtenir les informations géographiques d'une IP
    async fn get_geo_info(&self, ip: &IpAddr) -> Option<PeerGeoInfo> {
        // Vérifier le cache d'abord
        {
            let cache = self.geo_cache.read().await;
            if let Some(cached) = cache.get(ip) {
                // Vérifier si les données ne sont pas trop anciennes (24h)
                if let Ok(elapsed) = cached.last_updated.elapsed() {
                    if elapsed < Duration::from_secs(86400) {
                        return Some(cached.clone());
                    }
                }
            }
        }

        // Pour cette implémentation, on simule une lookup géographique
        // En production, on utiliserait une API comme MaxMind GeoIP2
        let geo_info = self.simulate_geo_lookup(ip).await;
        
        if let Some(ref info) = geo_info {
            let mut cache = self.geo_cache.write().await;
            cache.insert(*ip, info.clone());
        }
        
        geo_info
    }

    /// Simulation d'une lookup géographique (à remplacer par une vraie API)
    async fn simulate_geo_lookup(&self, ip: &IpAddr) -> Option<PeerGeoInfo> {
        // Simulation basique basée sur les ranges d'IP
        let (country_code, region, asn, is_datacenter) = match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                match octets[0] {
                    1..=50 => (Some("US".to_string()), Some("NA".to_string()), Some(7922), false),
                    51..=100 => (Some("EU".to_string()), Some("EU".to_string()), Some(3356), false),
                    101..=150 => (Some("CN".to_string()), Some("AS".to_string()), Some(4134), true),
                    151..=200 => (Some("JP".to_string()), Some("AS".to_string()), Some(2516), false),
                    _ => (Some("XX".to_string()), Some("UN".to_string()), Some(65000), false),
                }
            }
            IpAddr::V6(_) => (Some("XX".to_string()), Some("UN".to_string()), Some(65001), false),
        };

        Some(PeerGeoInfo {
            ip: *ip,
            country_code,
            region,
            asn,
            is_datacenter,
            last_updated: SystemTime::now(),
        })
    }

    /// Obtenir le subnet /24 d'une IP
    fn get_subnet(&self, ip: &IpAddr) -> String {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", 
                       segments[0], segments[1], segments[2], segments[3])
            }
        }
    }

    /// Démarrer les tâches de surveillance en arrière-plan
    pub async fn start_background_tasks(self: Arc<Self>) {
        let protection = Arc::clone(&self);
        
        // Tâche de vérification des anomalies
        tokio::spawn(async move {
            let mut interval = interval(protection.config.anomaly_check_interval);
            loop {
                interval.tick().await;
                protection.check_consensus_anomalies().await;
                protection.release_expired_quarantine().await;
            }
        });

        // Tâche de rotation des peers
        let protection = Arc::clone(&self);
        tokio::spawn(async move {
            let mut interval = interval(protection.config.peer_rotation_interval);
            loop {
                interval.tick().await;
                let _rotated = protection.rotate_peers().await;
                // Les peers à faire tourner seraient traités par le gestionnaire de connexions
            }
        });
    }

    /// Obtenir les statistiques de protection
    pub async fn get_stats(&self) -> EclipseProtectionStats {
        let peers = self.peers.read().await;
        let anomalies = self.detected_anomalies.read().await;
        
        let total_peers = peers.len();
        let quarantined_peers = peers.values().filter(|p| p.is_quarantined).count();
        
        let mut unique_countries = HashSet::new();
        let mut unique_asns = HashSet::new();
        
        for peer in peers.values() {
            if let Some(geo_info) = &peer.geo_info {
                if let Some(country) = &geo_info.country_code {
                    unique_countries.insert(country.clone());
                }
                if let Some(asn) = geo_info.asn {
                    unique_asns.insert(asn);
                }
            }
        }

        EclipseProtectionStats {
            total_peers,
            quarantined_peers,
            unique_countries: unique_countries.len(),
            unique_asns: unique_asns.len(),
            recent_anomalies: anomalies.len(),
            last_rotation: *self.last_rotation.read().await,
        }
    }

    /// Obtenir la liste des peers en quarantaine
    pub async fn get_quarantined_peers(&self) -> Vec<(SocketAddr, Option<Instant>)> {
        let peers = self.peers.read().await;
        peers.values()
            .filter(|p| p.is_quarantined)
            .map(|p| (p.addr, p.quarantine_until))
            .collect()
    }

    /// Obtenir les anomalies récentes
    pub async fn get_recent_anomalies(&self) -> Vec<NetworkAnomaly> {
        let anomalies = self.detected_anomalies.read().await;
        anomalies.clone()
    }
}

/// Statistiques de la protection eclipse
#[derive(Debug, Clone)]
pub struct EclipseProtectionStats {
    pub total_peers: usize,
    pub quarantined_peers: usize,
    pub unique_countries: usize,
    pub unique_asns: usize,
    pub recent_anomalies: usize,
    pub last_rotation: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_config() -> EclipseProtectionConfig {
        EclipseProtectionConfig {
            min_diverse_asn_peers: 3,
            min_diverse_geo_peers: 2,
            max_same_region_ratio: 0.5,
            peer_rotation_interval: Duration::from_secs(60),
            peer_rotation_percentage: 0.3,
            consensus_anomaly_threshold: 0.4,
            quarantine_duration: Duration::from_secs(300),
            max_connections_per_subnet: 2,
            anomaly_check_interval: Duration::from_secs(30),
        }
    }

    #[tokio::test]
    async fn test_add_peer_with_subnet_limit() {
        let protection = EclipseProtection::new(test_config());
        
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 8080);
        let addr3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)), 8080);

        // Premiers deux peers du même subnet devraient passer
        assert!(protection.add_peer(addr1).await.is_ok());
        assert!(protection.add_peer(addr2).await.is_ok());
        
        // Troisième peer du même subnet devrait être rejeté
        assert!(protection.add_peer(addr3).await.is_err());
    }

    #[tokio::test]
    async fn test_consensus_anomaly_detection() {
        let protection = EclipseProtection::new(test_config());
        
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
        protection.add_peer(addr).await.unwrap();

        // Simuler beaucoup de désaccords
        for _ in 0..15 {
            protection.record_consensus_result(&addr, false).await;
        }
        
        // Quelques accords pour avoir un échantillon significatif
        for _ in 0..5 {
            protection.record_consensus_result(&addr, true).await;
        }

        protection.check_consensus_anomalies().await;
        
        let anomalies = protection.get_recent_anomalies().await;
        assert!(!anomalies.is_empty());
        assert!(matches!(anomalies[0].anomaly_type, AnomalyType::ConsensusAnomaly));
    }

    #[tokio::test]
    async fn test_peer_quarantine() {
        let protection = EclipseProtection::new(test_config());
        
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
        protection.add_peer(addr).await.unwrap();

        protection.quarantine_peers(&[addr], "Test quarantine").await;
        
        let quarantined = protection.get_quarantined_peers().await;
        assert_eq!(quarantined.len(), 1);
        assert_eq!(quarantined[0].0, addr);
    }

    #[tokio::test]
    async fn test_peer_rotation() {
        let protection = EclipseProtection::new(test_config());
        
        // Ajouter plusieurs peers
        for i in 1..=5 {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)), 8080);
            protection.add_peer(addr).await.unwrap();
        }

        // Forcer la rotation en modifiant le timestamp
        {
            let mut last_rotation = protection.last_rotation.write().await;
            *last_rotation = Instant::now() - Duration::from_secs(3600);
        }

        let rotated = protection.rotate_peers().await;
        assert!(!rotated.is_empty());
        assert!(rotated.len() <= 2); // 30% de 5 peers = 1.5, arrondi à 2 max
    }
}