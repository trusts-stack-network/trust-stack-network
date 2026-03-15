//! Role validation & anti-cheat for TSN multi-role nodes
//!
//! Ensures:
//! - One role per node (no dual roles)
//! - Peers prove their claimed capabilities
//! - Work is only routed to capable nodes
//! - Fraudulent role claims are detected and penalized

use super::NodeRole;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Capability proof that a peer must provide to validate its claimed role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleProof {
    /// The claimed role
    pub role: NodeRole,
    /// For Miner: MIK registration tx hash (proves they have a registered Mining Identity Key)
    pub mik_tx_hash: Option<String>,
    /// For Miner/Relay: latest block hash they store (proves full chain)
    pub chain_tip_hash: Option<String>,
    /// For Miner/Relay: chain height (proves full chain storage)
    pub chain_height: Option<u64>,
    /// For Prover: a sample proof hash to demonstrate proving capability
    pub sample_proof_hash: Option<String>,
    /// Timestamp of proof generation
    pub timestamp: u64,
}

impl RoleProof {
    /// Create a proof for a Miner role
    pub fn for_miner(mik_tx_hash: String, chain_tip: String, height: u64) -> Self {
        Self {
            role: NodeRole::Miner,
            mik_tx_hash: Some(mik_tx_hash),
            chain_tip_hash: Some(chain_tip),
            chain_height: Some(height),
            sample_proof_hash: None,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Create a proof for a Relay role
    pub fn for_relay(chain_tip: String, height: u64) -> Self {
        Self {
            role: NodeRole::Relay,
            mik_tx_hash: None,
            chain_tip_hash: Some(chain_tip),
            chain_height: Some(height),
            sample_proof_hash: None,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Create a proof for a Prover role
    pub fn for_prover(chain_tip: String, height: u64, sample_proof: String) -> Self {
        Self {
            role: NodeRole::Prover,
            mik_tx_hash: None,
            chain_tip_hash: Some(chain_tip),
            chain_height: Some(height),
            sample_proof_hash: Some(sample_proof),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Create a proof for a Light Client (minimal — no chain storage required)
    pub fn for_light_client() -> Self {
        Self {
            role: NodeRole::LightClient,
            mik_tx_hash: None,
            chain_tip_hash: None,
            chain_height: None,
            sample_proof_hash: None,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// Result of validating a peer's role claim
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleValidation {
    /// Role is valid and verified
    Valid,
    /// Miner claims to mine but has no MIK registration
    MinerWithoutMik,
    /// Node claims full chain but reported height is too far behind network tip
    ChainTooFarBehind { claimed: u64, network_tip: u64 },
    /// Prover claims to prove but provided no proof sample
    ProverWithoutProof,
    /// Peer already registered with a different role (anti-dual-role)
    DuplicateRole { existing: NodeRole, claimed: NodeRole },
    /// Proof is too old (stale)
    StaleProof { age_secs: u64 },
    /// Role claim is missing required fields
    IncompleteProof(String),
}

impl RoleValidation {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

impl std::fmt::Display for RoleValidation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid => write!(f, "valid"),
            Self::MinerWithoutMik => write!(f, "miner without MIK registration"),
            Self::ChainTooFarBehind { claimed, network_tip } => {
                write!(f, "chain too far behind (claimed: {}, network tip: {})", claimed, network_tip)
            }
            Self::ProverWithoutProof => write!(f, "prover without sample proof"),
            Self::DuplicateRole { existing, claimed } => {
                write!(f, "already registered as {} but claiming {}", existing, claimed)
            }
            Self::StaleProof { age_secs } => {
                write!(f, "proof is {}s old (max: 300s)", age_secs)
            }
            Self::IncompleteProof(msg) => write!(f, "incomplete proof: {}", msg),
        }
    }
}

/// Tracks peer roles and validates capability claims
pub struct RoleValidator {
    /// Known peer roles: peer_addr -> (role, last_validated, score)
    peer_roles: HashMap<SocketAddr, PeerRoleInfo>,
    /// Current network tip height (updated by sync)
    network_tip: u64,
    /// Max allowed height difference for "full chain" claims
    max_chain_lag: u64,
    /// Max age of a role proof before it's considered stale
    max_proof_age: Duration,
}

#[derive(Debug, Clone)]
struct PeerRoleInfo {
    role: NodeRole,
    last_validated: Instant,
    validation_count: u32,
    fraud_strikes: u32,
}

/// Maximum fraud strikes before a peer is banned from the role
const MAX_FRAUD_STRIKES: u32 = 3;
/// Re-validation interval — peers must re-prove their role periodically
const REVALIDATION_INTERVAL: Duration = Duration::from_secs(600); // 10 minutes

impl RoleValidator {
    pub fn new() -> Self {
        Self {
            peer_roles: HashMap::new(),
            network_tip: 0,
            max_chain_lag: 10, // Must be within 10 blocks of tip to claim full chain
            max_proof_age: Duration::from_secs(300), // Proofs valid for 5 minutes
        }
    }

    /// Update the known network tip height
    pub fn update_network_tip(&mut self, height: u64) {
        if height > self.network_tip {
            self.network_tip = height;
        }
    }

    /// Validate a peer's role claim and register if valid
    pub fn validate_and_register(
        &mut self,
        peer: SocketAddr,
        proof: &RoleProof,
    ) -> RoleValidation {
        // 1. Check for dual-role: a peer can only have ONE role
        if let Some(existing) = self.peer_roles.get(&peer) {
            if existing.role != proof.role {
                tracing::warn!(
                    "🚫 Anti-cheat: peer {} already registered as {} but claiming {}",
                    peer, existing.role, proof.role
                );
                return RoleValidation::DuplicateRole {
                    existing: existing.role,
                    claimed: proof.role,
                };
            }
        }

        // 2. Check proof freshness
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let proof_age = now.saturating_sub(proof.timestamp);
        if proof_age > self.max_proof_age.as_secs() {
            return RoleValidation::StaleProof { age_secs: proof_age };
        }

        // 3. Validate role-specific requirements
        let validation = match proof.role {
            NodeRole::Miner => self.validate_miner(proof),
            NodeRole::Relay => self.validate_relay(proof),
            NodeRole::Prover => self.validate_prover(proof),
            NodeRole::LightClient => RoleValidation::Valid, // Light clients need no proof
        };

        if validation.is_valid() {
            let info = self.peer_roles.entry(peer).or_insert(PeerRoleInfo {
                role: proof.role,
                last_validated: Instant::now(),
                validation_count: 0,
                fraud_strikes: 0,
            });
            info.role = proof.role;
            info.last_validated = Instant::now();
            info.validation_count += 1;
            tracing::info!("✅ Peer {} validated as {}", peer, proof.role);
        } else {
            // Record fraud strike
            let info = self.peer_roles.entry(peer).or_insert(PeerRoleInfo {
                role: proof.role,
                last_validated: Instant::now(),
                validation_count: 0,
                fraud_strikes: 0,
            });
            info.fraud_strikes += 1;
            tracing::warn!(
                "⚠️ Anti-cheat: peer {} failed {} validation (strike {}/{}): {}",
                peer, proof.role, info.fraud_strikes, MAX_FRAUD_STRIKES, validation
            );
        }

        validation
    }

    fn validate_miner(&self, proof: &RoleProof) -> RoleValidation {
        // Miner MUST have a MIK registration
        if proof.mik_tx_hash.is_none() {
            return RoleValidation::MinerWithoutMik;
        }
        // Miner MUST store the full chain
        match proof.chain_height {
            Some(h) if self.network_tip > 0 && h + self.max_chain_lag < self.network_tip => {
                RoleValidation::ChainTooFarBehind {
                    claimed: h,
                    network_tip: self.network_tip,
                }
            }
            None => RoleValidation::IncompleteProof("miner must report chain height".into()),
            _ => RoleValidation::Valid,
        }
    }

    fn validate_relay(&self, proof: &RoleProof) -> RoleValidation {
        // Relay MUST store the full chain
        match proof.chain_height {
            Some(h) if self.network_tip > 0 && h + self.max_chain_lag < self.network_tip => {
                RoleValidation::ChainTooFarBehind {
                    claimed: h,
                    network_tip: self.network_tip,
                }
            }
            None => RoleValidation::IncompleteProof("relay must report chain height".into()),
            _ => RoleValidation::Valid,
        }
    }

    fn validate_prover(&self, proof: &RoleProof) -> RoleValidation {
        // Prover MUST demonstrate proving capability
        if proof.sample_proof_hash.is_none() {
            return RoleValidation::ProverWithoutProof;
        }
        // Prover should also store full chain for witness generation
        match proof.chain_height {
            Some(h) if self.network_tip > 0 && h + self.max_chain_lag < self.network_tip => {
                RoleValidation::ChainTooFarBehind {
                    claimed: h,
                    network_tip: self.network_tip,
                }
            }
            None => RoleValidation::IncompleteProof("prover must report chain height".into()),
            _ => RoleValidation::Valid,
        }
    }

    /// Get the verified role of a peer (None if not registered or expired)
    pub fn get_peer_role(&self, peer: &SocketAddr) -> Option<NodeRole> {
        self.peer_roles.get(peer).and_then(|info| {
            // Check if validation is still fresh
            if info.last_validated.elapsed() < REVALIDATION_INTERVAL
                && info.fraud_strikes < MAX_FRAUD_STRIKES
            {
                Some(info.role)
            } else {
                None
            }
        })
    }

    /// Check if a peer is banned (too many fraud strikes)
    pub fn is_banned(&self, peer: &SocketAddr) -> bool {
        self.peer_roles
            .get(peer)
            .map(|info| info.fraud_strikes >= MAX_FRAUD_STRIKES)
            .unwrap_or(false)
    }

    /// Check if a peer can handle a specific task
    pub fn can_handle_task(&self, peer: &SocketAddr, task: PeerTask) -> bool {
        match self.get_peer_role(peer) {
            Some(role) => match task {
                PeerTask::MineBlock => role.can_mine(),
                PeerTask::RelayBlock | PeerTask::RelayTransaction => role.can_relay(),
                PeerTask::GenerateProof => role.can_prove(),
                PeerTask::ServeSnapshot => role.stores_full_chain(),
                PeerTask::ServeWitness => role.stores_full_chain(),
                PeerTask::SyncHeaders => true, // All roles can sync headers
            },
            None => false, // Unknown peer — don't route work to them
        }
    }

    /// Get all peers capable of a specific task
    pub fn peers_for_task(&self, task: PeerTask) -> Vec<SocketAddr> {
        self.peer_roles
            .iter()
            .filter(|(addr, _)| self.can_handle_task(addr, task))
            .map(|(addr, _)| *addr)
            .collect()
    }

    /// Remove a peer (disconnect)
    pub fn remove_peer(&mut self, peer: &SocketAddr) {
        self.peer_roles.remove(peer);
    }

    /// Get peers that need re-validation
    pub fn peers_needing_revalidation(&self) -> Vec<SocketAddr> {
        self.peer_roles
            .iter()
            .filter(|(_, info)| info.last_validated.elapsed() >= REVALIDATION_INTERVAL)
            .map(|(addr, _)| *addr)
            .collect()
    }

    /// Stats for monitoring
    pub fn stats(&self) -> RoleValidatorStats {
        let mut miners = 0;
        let mut relays = 0;
        let mut provers = 0;
        let mut light_clients = 0;
        let mut banned = 0;

        for info in self.peer_roles.values() {
            if info.fraud_strikes >= MAX_FRAUD_STRIKES {
                banned += 1;
                continue;
            }
            match info.role {
                NodeRole::Miner => miners += 1,
                NodeRole::Relay => relays += 1,
                NodeRole::Prover => provers += 1,
                NodeRole::LightClient => light_clients += 1,
            }
        }

        RoleValidatorStats {
            total_peers: self.peer_roles.len(),
            miners,
            relays,
            provers,
            light_clients,
            banned,
        }
    }
}

/// Types of tasks that can be routed to peers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTask {
    MineBlock,
    RelayBlock,
    RelayTransaction,
    GenerateProof,
    ServeSnapshot,
    ServeWitness,
    SyncHeaders,
}

/// Statistics about the role distribution in the network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleValidatorStats {
    pub total_peers: usize,
    pub miners: usize,
    pub relays: usize,
    pub provers: usize,
    pub light_clients: usize,
    pub banned: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_addr(port: u16) -> SocketAddr {
        use std::net::{IpAddr, Ipv4Addr};
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[test]
    fn test_single_role_enforcement() {
        let mut validator = RoleValidator::new();
        let peer = test_addr(9001);

        // Register as miner
        let proof = RoleProof::for_miner("mik123".into(), "blockhash".into(), 100);
        assert!(validator.validate_and_register(peer, &proof).is_valid());

        // Try to switch to relay — should fail (duplicate role)
        let proof2 = RoleProof::for_relay("blockhash".into(), 100);
        let result = validator.validate_and_register(peer, &proof2);
        assert_eq!(
            result,
            RoleValidation::DuplicateRole {
                existing: NodeRole::Miner,
                claimed: NodeRole::Relay,
            }
        );
    }

    #[test]
    fn test_miner_without_mik_rejected() {
        let mut validator = RoleValidator::new();
        let peer = test_addr(9002);

        let proof = RoleProof {
            role: NodeRole::Miner,
            mik_tx_hash: None, // No MIK!
            chain_tip_hash: Some("hash".into()),
            chain_height: Some(100),
            sample_proof_hash: None,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        assert_eq!(
            validator.validate_and_register(peer, &proof),
            RoleValidation::MinerWithoutMik
        );
    }

    #[test]
    fn test_chain_too_far_behind() {
        let mut validator = RoleValidator::new();
        validator.update_network_tip(1000);
        let peer = test_addr(9003);

        // Relay claims height 50 but network is at 1000
        let proof = RoleProof::for_relay("hash".into(), 50);
        match validator.validate_and_register(peer, &proof) {
            RoleValidation::ChainTooFarBehind { claimed, network_tip } => {
                assert_eq!(claimed, 50);
                assert_eq!(network_tip, 1000);
            }
            other => panic!("Expected ChainTooFarBehind, got {:?}", other),
        }
    }

    #[test]
    fn test_prover_without_proof_rejected() {
        let mut validator = RoleValidator::new();
        let peer = test_addr(9004);

        let proof = RoleProof {
            role: NodeRole::Prover,
            mik_tx_hash: None,
            chain_tip_hash: Some("hash".into()),
            chain_height: Some(100),
            sample_proof_hash: None, // No proof!
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        assert_eq!(
            validator.validate_and_register(peer, &proof),
            RoleValidation::ProverWithoutProof
        );
    }

    #[test]
    fn test_light_client_always_valid() {
        let mut validator = RoleValidator::new();
        let peer = test_addr(9005);

        let proof = RoleProof::for_light_client();
        assert!(validator.validate_and_register(peer, &proof).is_valid());
    }

    #[test]
    fn test_task_routing() {
        let mut validator = RoleValidator::new();

        let miner = test_addr(9010);
        let relay = test_addr(9011);
        let prover = test_addr(9012);
        let light = test_addr(9013);

        validator.validate_and_register(miner, &RoleProof::for_miner("mik".into(), "h".into(), 100));
        validator.validate_and_register(relay, &RoleProof::for_relay("h".into(), 100));
        validator.validate_and_register(prover, &RoleProof::for_prover("h".into(), 100, "proof".into()));
        validator.validate_and_register(light, &RoleProof::for_light_client());

        // Only miner can mine
        assert!(validator.can_handle_task(&miner, PeerTask::MineBlock));
        assert!(!validator.can_handle_task(&relay, PeerTask::MineBlock));
        assert!(!validator.can_handle_task(&prover, PeerTask::MineBlock));
        assert!(!validator.can_handle_task(&light, PeerTask::MineBlock));

        // Miner and relay can relay
        assert!(validator.can_handle_task(&miner, PeerTask::RelayBlock));
        assert!(validator.can_handle_task(&relay, PeerTask::RelayBlock));
        assert!(!validator.can_handle_task(&prover, PeerTask::RelayBlock));
        assert!(!validator.can_handle_task(&light, PeerTask::RelayBlock));

        // Miner and prover can prove
        assert!(validator.can_handle_task(&miner, PeerTask::GenerateProof));
        assert!(!validator.can_handle_task(&relay, PeerTask::GenerateProof));
        assert!(validator.can_handle_task(&prover, PeerTask::GenerateProof));
        assert!(!validator.can_handle_task(&light, PeerTask::GenerateProof));

        // Light client can't serve snapshots or witnesses
        assert!(!validator.can_handle_task(&light, PeerTask::ServeSnapshot));
        assert!(!validator.can_handle_task(&light, PeerTask::ServeWitness));

        // Everyone can sync headers
        assert!(validator.can_handle_task(&light, PeerTask::SyncHeaders));
    }

    #[test]
    fn test_fraud_ban() {
        let mut validator = RoleValidator::new();
        validator.update_network_tip(1000);
        let peer = test_addr(9020);

        // 3 failed validations = banned
        for _ in 0..MAX_FRAUD_STRIKES {
            let proof = RoleProof::for_relay("h".into(), 50); // Far behind
            validator.validate_and_register(peer, &proof);
        }

        assert!(validator.is_banned(&peer));
        assert_eq!(validator.get_peer_role(&peer), None);
    }

    #[test]
    fn test_stats() {
        let mut validator = RoleValidator::new();

        validator.validate_and_register(test_addr(9030), &RoleProof::for_miner("m".into(), "h".into(), 100));
        validator.validate_and_register(test_addr(9031), &RoleProof::for_relay("h".into(), 100));
        validator.validate_and_register(test_addr(9032), &RoleProof::for_prover("h".into(), 100, "p".into()));
        validator.validate_and_register(test_addr(9033), &RoleProof::for_light_client());

        let stats = validator.stats();
        assert_eq!(stats.miners, 1);
        assert_eq!(stats.relays, 1);
        assert_eq!(stats.provers, 1);
        assert_eq!(stats.light_clients, 1);
        assert_eq!(stats.total_peers, 4);
        assert_eq!(stats.banned, 0);
    }
}
