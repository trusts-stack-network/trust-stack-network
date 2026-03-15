use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

/// Maximum block gap allowed before mining is paused
const MAX_MINING_GAP: u64 = 2;
/// Blocks behind threshold for stale block rejection
const STALE_BLOCK_THRESHOLD: u64 = 3;
/// Tip announcements expire after this many seconds
const TIP_EXPIRY_SECS: u64 = 120;

/// Statut de minage retourné par le sync gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MiningStatus {
    /// Le noeud est synchronisé, le minage est autorisé.
    CanMine,
    /// Le noeud est en retard par rapport au réseau.
    BehindNetwork {
        local_height: u64,
        network_tip: u64,
        gap: u64,
    },
    /// Aucun tip réseau connu (pas de peers).
    NoNetworkTips,
}

impl MiningStatus {
    /// Retourne true si le minage est autorisé.
    pub fn is_allowed(&self) -> bool {
        matches!(self, MiningStatus::CanMine | MiningStatus::NoNetworkTips)
    }

    /// Retourne un message lisible décrivant le statut de minage.
    pub fn mining_status_message(&self) -> String {
        match self {
            MiningStatus::CanMine => "Minage autorisé: noeud synchronisé avec le réseau".to_string(),
            MiningStatus::BehindNetwork { local_height, network_tip, gap } => {
                format!(
                    "Minage suspendu: noeud en retard de {} blocs (local: {}, réseau: {})",
                    gap, local_height, network_tip
                )
            }
            MiningStatus::NoNetworkTips => {
                "Minage autorisé: aucun peer connu, fonctionnement en mode solo".to_string()
            }
        }
    }
}

impl fmt::Display for MiningStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.mining_status_message())
    }
}

#[derive(Debug, Clone)]
pub struct TipAnnouncement {
    pub height: u64,
    pub hash: [u8; 32],
    pub timestamp: u64,
}

pub struct SyncGate {
    network_tips: Arc<RwLock<HashMap<String, TipAnnouncement>>>,
}

impl SyncGate {
    pub fn new() -> Self {
        Self {
            network_tips: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record a tip announcement from a peer
    pub fn update_tip(&self, peer_id: &str, height: u64, hash: [u8; 32]) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let mut tips = self.network_tips.write().unwrap_or_else(|e| e.into_inner());
        tips.insert(peer_id.to_string(), TipAnnouncement { height, hash, timestamp: now });
        // Purge expired
        tips.retain(|_, tip| now - tip.timestamp < TIP_EXPIRY_SECS);
    }

    /// Get the highest known network tip height
    pub fn network_tip_height(&self) -> u64 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let tips = self.network_tips.read().unwrap_or_else(|e| e.into_inner());
        tips.values()
            .filter(|t| now - t.timestamp < TIP_EXPIRY_SECS)
            .map(|t| t.height)
            .max()
            .unwrap_or(0)
    }

    /// Retourne le statut de minage détaillé.
    /// Logue un WARNING si le noeud est en retard.
    pub fn mining_status(&self, local_height: u64) -> MiningStatus {
        let net_tip = self.network_tip_height();
        if net_tip == 0 {
            return MiningStatus::NoNetworkTips;
        }
        if local_height + MAX_MINING_GAP >= net_tip {
            MiningStatus::CanMine
        } else {
            let gap = net_tip - local_height;
            warn!(
                "Minage suspendu: noeud en retard de {} blocs (local: {}, réseau: {})",
                gap, local_height, net_tip
            );
            MiningStatus::BehindNetwork {
                local_height,
                network_tip: net_tip,
                gap,
            }
        }
    }

    /// Check if local node is synced enough to mine.
    /// Rétrocompatible: retourne un bool (true = minage autorisé).
    pub fn can_mine(&self, local_height: u64) -> bool {
        self.mining_status(local_height).is_allowed()
    }

    /// Check if a received block is stale (too far behind network tip)
    pub fn is_stale_block(&self, block_height: u64) -> bool {
        let net_tip = self.network_tip_height();
        if net_tip == 0 { return false; }
        net_tip > block_height + STALE_BLOCK_THRESHOLD
    }

    /// Get number of known peers
    pub fn peer_count(&self) -> usize {
        let tips = self.network_tips.read().unwrap_or_else(|e| e.into_inner());
        tips.len()
    }
}

impl Clone for SyncGate {
    fn clone(&self) -> Self {
        Self {
            network_tips: Arc::clone(&self.network_tips),
        }
    }
}
