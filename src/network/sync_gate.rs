use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum block gap allowed before mining is paused
const MAX_MINING_GAP: u64 = 2;
/// Blocks behind threshold for stale block rejection
const STALE_BLOCK_THRESHOLD: u64 = 3;
/// Tip announcements expire after this many seconds
const TIP_EXPIRY_SECS: u64 = 120;

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

    /// Check if local node is synced enough to mine
    pub fn can_mine(&self, local_height: u64) -> bool {
        let net_tip = self.network_tip_height();
        if net_tip == 0 { return true; } // No peers known, allow mining
        local_height + MAX_MINING_GAP >= net_tip
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
