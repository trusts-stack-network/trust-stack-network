pub mod role_validator;

use serde::{Deserialize, Serialize};

/// Defines the role a TSN node plays in the network.
///
/// - **Miner**: Full node that mines blocks, relays, and stores the full chain.
/// - **Relay**: Stores and relays full blocks but does not mine.
/// - **Prover**: Runs a ZK prover service endpoint; does not mine.
/// - **LightClient**: Syncs headers only; minimal storage and bandwidth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeRole {
    Miner,
    Relay,
    Prover,
    LightClient,
}

impl NodeRole {
    /// Parse a role from a CLI string (case-insensitive).
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "miner" => Some(Self::Miner),
            "relay" => Some(Self::Relay),
            "prover" => Some(Self::Prover),
            "light" | "lightclient" | "light_client" | "light-client" => Some(Self::LightClient),
            _ => None,
        }
    }

    /// Whether this role is allowed to mine blocks.
    pub fn can_mine(&self) -> bool {
        matches!(self, Self::Miner)
    }

    /// Whether this role relays full blocks to peers.
    pub fn can_relay(&self) -> bool {
        matches!(self, Self::Miner | Self::Relay)
    }

    /// Whether this role can run ZK proof generation.
    pub fn can_prove(&self) -> bool {
        matches!(self, Self::Miner | Self::Prover)
    }

    /// Whether this role stores the full blockchain (not just headers).
    pub fn stores_full_chain(&self) -> bool {
        !matches!(self, Self::LightClient)
    }

    /// Human-readable description of the role.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Miner => "Full node with mining capability",
            Self::Relay => "Relay node — stores and forwards blocks, no mining",
            Self::Prover => "Prover node — ZK proof generation service, no mining",
            Self::LightClient => "Light client — header-only sync, minimal storage",
        }
    }
}

impl std::fmt::Display for NodeRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Miner => write!(f, "miner"),
            Self::Relay => write!(f, "relay"),
            Self::Prover => write!(f, "prover"),
            Self::LightClient => write!(f, "light"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_str() {
        assert_eq!(NodeRole::from_str("miner"), Some(NodeRole::Miner));
        assert_eq!(NodeRole::from_str("relay"), Some(NodeRole::Relay));
        assert_eq!(NodeRole::from_str("prover"), Some(NodeRole::Prover));
        assert_eq!(NodeRole::from_str("light"), Some(NodeRole::LightClient));
        assert_eq!(NodeRole::from_str("lightclient"), Some(NodeRole::LightClient));
        assert_eq!(NodeRole::from_str("MINER"), Some(NodeRole::Miner));
        assert_eq!(NodeRole::from_str("unknown"), None);
    }

    #[test]
    fn test_capabilities() {
        let miner = NodeRole::Miner;
        assert!(miner.can_mine());
        assert!(miner.can_relay());
        assert!(miner.can_prove());
        assert!(miner.stores_full_chain());

        let relay = NodeRole::Relay;
        assert!(!relay.can_mine());
        assert!(relay.can_relay());
        assert!(!relay.can_prove());
        assert!(relay.stores_full_chain());

        let prover = NodeRole::Prover;
        assert!(!prover.can_mine());
        assert!(!prover.can_relay());
        assert!(prover.can_prove());
        assert!(prover.stores_full_chain());

        let light = NodeRole::LightClient;
        assert!(!light.can_mine());
        assert!(!light.can_relay());
        assert!(!light.can_prove());
        assert!(!light.stores_full_chain());
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", NodeRole::Miner), "miner");
        assert_eq!(format!("{}", NodeRole::LightClient), "light");
    }

    #[test]
    fn test_serde_roundtrip() {
        let role = NodeRole::Prover;
        let json = serde_json::to_string(&role).unwrap();
        let parsed: NodeRole = serde_json::from_str(&json).unwrap();
        assert_eq!(role, parsed);
    }
}
