//! TSN Upgrade Protocol (TUP) — Version bits signaling for coordinated upgrades.
//!
//! Miners signal support for upgrades using 3 reserved bits (29-31) in block header version.
//! When 75% of blocks in a 100-block window signal support, the upgrade locks in.
//! After a 200-block grace period, the new rules activate.

use tracing::info;

/// Number of version bits available for signaling
pub const VERSION_BITS_COUNT: usize = 3;
/// Percentage of blocks needed to lock in (75%)
pub const SIGNAL_THRESHOLD_PERCENT: u64 = 75;
/// Window size for counting signals
pub const SIGNAL_WINDOW: u64 = 100;
/// Grace period after lock-in before activation
pub const GRACE_PERIOD: u64 = 200;

/// Represents a proposed upgrade
#[derive(Debug, Clone)]
pub struct UpgradeProposal {
    /// Bit position (0, 1, or 2)
    pub bit: u8,
    /// Human-readable name
    pub name: String,
    /// Height at which signaling starts
    pub start_height: u64,
    /// Height at which upgrade activates regardless of signaling (flag day)
    pub flag_day_height: u64,
}

/// State of an upgrade proposal
#[derive(Debug, Clone, PartialEq)]
pub enum UpgradeState {
    /// Proposal defined but not yet at start_height
    Defined,
    /// Signaling started, collecting votes
    Started,
    /// 75% threshold reached, locked in at given height
    LockedIn { lock_height: u64 },
    /// Upgrade is active (new rules enforced)
    Active { activation_height: u64 },
}

/// Manages the upgrade signaling process
pub struct UpgradeManager {
    proposals: Vec<UpgradeProposal>,
    states: Vec<UpgradeState>,
}

impl UpgradeManager {
    pub fn new() -> Self {
        Self {
            proposals: Vec::new(),
            states: Vec::new(),
        }
    }

    /// Register a new upgrade proposal
    pub fn add_proposal(&mut self, proposal: UpgradeProposal) {
        self.states.push(UpgradeState::Defined);
        self.proposals.push(proposal);
    }

    /// Extract signal bits from a block version
    pub fn extract_signal_bits(version: u32) -> u8 {
        ((version >> 29) & 0x07) as u8
    }

    /// Set signal bits in a block version
    pub fn set_signal_bits(version: u32, bits: u8) -> u32 {
        (version & 0x1FFFFFFF) | ((bits as u32 & 0x07) << 29)
    }

    /// Extract the base version number (without signal bits)
    pub fn base_version(version: u32) -> u32 {
        version & 0x1FFFFFFF
    }

    /// Check if a specific bit is signaled in a version
    pub fn is_bit_signaled(version: u32, bit: u8) -> bool {
        if bit >= VERSION_BITS_COUNT as u8 { return false; }
        (version >> (29 + bit)) & 1 == 1
    }

    /// Update upgrade states based on recent blocks
    /// `recent_versions` should contain the versions of the last SIGNAL_WINDOW blocks
    pub fn update_states(&mut self, current_height: u64, recent_versions: &[u32]) {
        for i in 0..self.proposals.len() {
            let proposal = &self.proposals[i];
            match &self.states[i] {
                UpgradeState::Defined => {
                    if current_height >= proposal.start_height {
                        info!("TUP: Upgrade '{}' signaling started at height {}", proposal.name, current_height);
                        self.states[i] = UpgradeState::Started;
                    }
                }
                UpgradeState::Started => {
                    // Check flag day
                    if current_height >= proposal.flag_day_height {
                        info!("TUP: Upgrade '{}' activated via flag day at height {}", proposal.name, current_height);
                        self.states[i] = UpgradeState::Active { activation_height: current_height };
                        continue;
                    }
                    // Count signals in window
                    if recent_versions.len() >= SIGNAL_WINDOW as usize {
                        let bit = proposal.bit;
                        let signal_count = recent_versions.iter()
                            .filter(|v| Self::is_bit_signaled(**v, bit))
                            .count() as u64;
                        let threshold = SIGNAL_WINDOW * SIGNAL_THRESHOLD_PERCENT / 100;
                        if signal_count >= threshold {
                            info!("TUP: Upgrade '{}' LOCKED IN at height {} ({}/{} signals)",
                                proposal.name, current_height, signal_count, SIGNAL_WINDOW);
                            self.states[i] = UpgradeState::LockedIn { lock_height: current_height };
                        }
                    }
                }
                UpgradeState::LockedIn { lock_height } => {
                    let lh = *lock_height;
                    if current_height >= lh + GRACE_PERIOD {
                        info!("TUP: Upgrade '{}' ACTIVATED at height {} (grace period complete)",
                            proposal.name, current_height);
                        self.states[i] = UpgradeState::Active {
                            activation_height: lh + GRACE_PERIOD,
                        };
                    }
                }
                UpgradeState::Active { .. } => {
                    // Already active, nothing to do
                }
            }
        }
    }

    /// Get the state of an upgrade by bit
    pub fn get_state(&self, bit: u8) -> Option<&UpgradeState> {
        self.proposals.iter().position(|p| p.bit == bit)
            .map(|i| &self.states[i])
    }

    /// Get all proposals and their states
    pub fn proposals(&self) -> Vec<(&UpgradeProposal, &UpgradeState)> {
        self.proposals.iter().zip(self.states.iter()).collect()
    }

    /// Check minimum required version for current height
    pub fn minimum_version(&self) -> u32 {
        let mut min = 0u32;
        for (_proposal, state) in self.proposals.iter().zip(self.states.iter()) {
            if matches!(state, UpgradeState::Active { .. }) {
                // If an upgrade is active, version must have been at least 3
                min = min.max(3); // v0.3.0 base version
            }
        }
        min
    }

    /// Check if a block version is compatible
    pub fn is_version_compatible(&self, version: u32, _height: u64) -> Result<(), String> {
        let base = Self::base_version(version);
        let min = self.minimum_version();
        if base < min {
            return Err(format!(
                "Block version {} incompatible — please upgrade your TSN node. Minimum version: {}",
                base, min
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_bits() {
        let v = UpgradeManager::set_signal_bits(3, 0b101);
        assert_eq!(UpgradeManager::extract_signal_bits(v), 0b101);
        assert_eq!(UpgradeManager::base_version(v), 3);
        assert!(UpgradeManager::is_bit_signaled(v, 0));
        assert!(!UpgradeManager::is_bit_signaled(v, 1));
        assert!(UpgradeManager::is_bit_signaled(v, 2));
    }

    #[test]
    fn test_upgrade_lifecycle() {
        let mut mgr = UpgradeManager::new();
        mgr.add_proposal(UpgradeProposal {
            bit: 0,
            name: "poseidon2-pow".to_string(),
            start_height: 100,
            flag_day_height: 10000,
        });

        // Before start
        mgr.update_states(50, &[]);
        assert_eq!(*mgr.get_state(0).unwrap(), UpgradeState::Defined);

        // After start, not enough signals
        let versions: Vec<u32> = (0..100).map(|i| if i < 50 { UpgradeManager::set_signal_bits(3, 1) } else { 3 }).collect();
        mgr.update_states(200, &versions);
        assert_eq!(*mgr.get_state(0).unwrap(), UpgradeState::Started);

        // 75% signals
        let versions: Vec<u32> = (0..100).map(|i| if i < 75 { UpgradeManager::set_signal_bits(3, 1) } else { 3 }).collect();
        mgr.update_states(300, &versions);
        assert!(matches!(mgr.get_state(0).unwrap(), UpgradeState::LockedIn { .. }));

        // After grace period
        mgr.update_states(501, &versions);
        assert!(matches!(mgr.get_state(0).unwrap(), UpgradeState::Active { .. }));
    }

    #[test]
    fn test_flag_day_activation() {
        let mut mgr = UpgradeManager::new();
        mgr.add_proposal(UpgradeProposal {
            bit: 0,
            name: "test-upgrade".to_string(),
            start_height: 100,
            flag_day_height: 500,
        });

        // No signals at all, but flag day reached
        mgr.update_states(100, &[]);
        mgr.update_states(500, &vec![3u32; 100]);
        assert!(matches!(mgr.get_state(0).unwrap(), UpgradeState::Active { .. }));
    }
}
