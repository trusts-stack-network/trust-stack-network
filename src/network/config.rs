use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Configuration réseau TSN
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Version du protocole TSN
    pub protocol_version: u32,
    /// ID du réseau (mainnet, testnet, etc.)
    pub network_id: String,
    /// Adresse d'écoute
    pub listen_addr: SocketAddr,
    /// Port d'écoute
    pub listen_port: u16,
    /// Liste des seed nodes
    pub seed_nodes: Vec<String>,
    /// Capabilities annoncées
    pub capabilities: Vec<String>,
    /// Timeout de connexion
    pub connection_timeout_secs: u64,
    /// Max pairs actifs
    pub max_peers: usize,
}

impl NetworkConfig {
    pub fn mainnet() -> Self {
        Self {
            protocol_version: 1,
            network_id: "tsn-mainnet".to_string(),
            listen_addr: "0.0.0.0:8333".parse().unwrap(),
            listen_port: 8333,
            seed_nodes: vec![
                "seed1.truststack.network:8333".to_string(),
                "seed2.truststack.network:8333".to_string(),
                "seed3.truststack.network:8333".to_string(),
            ],
            capabilities: vec!["full".to_string(), "gossip".to_string()],
            connection_timeout_secs: 30,
            max_peers: 125,
        }
    }

    pub fn testnet() -> Self {
        let mut config = Self::mainnet();
        config.network_id = "tsn-testnet".to_string();
        config.listen_port = 18333;
        config.seed_nodes = vec![
            "testnet-seed1.truststack.network:18333".to_string(),
            "testnet-seed2.truststack.network:18333".to_string(),
        ];
        config
    }

    #[cfg(test)]
    pub fn test_config() -> Self {
        Self {
            protocol_version: 1,
            network_id: "tsn-test".to_string(),
            listen_addr: "127.0.0.1:0".parse().unwrap(), // Port aléatoire
            listen_port: 0,
            seed_nodes: vec![],
            capabilities: vec!["test".to_string()],
            connection_timeout_secs: 5,
            max_peers: 10,
        }
    }
}