//! Anti-DoS protection combining rate limiting and peer scoring
//!
//! This module provides comprehensive protection against various DoS attacks:
//! - Rate limiting per peer using token bucket algorithm
//! - Peer scoring based on behavior patterns
//! - Automatic banning of malicious peers
//! - Cleanup of old data to prevent memory leaks

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, warn, info};

use crate::network::rate_limiter::{RateLimiter, RateLimitConfig};
use crate::network::scoring::{PeerScoring, ScoringConfig, PenaltyReason};

/// Configuration for the anti-DoS system
#[derive(Debug, Clone)]
pub struct AntiDoSConfig {
    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,
    /// Peer scoring configuration
    pub scoring: ScoringConfig,
    /// Duration to keep banned peers
    pub ban_duration: Duration,
    /// Interval for cleanup tasks
    pub cleanup_interval: Duration,
    /// Maximum number of peers to track
    pub max_tracked_peers: usize,
}

impl Default for AntiDoSConfig {
    fn default() -> Self {
        Self {
            rate_limit: RateLimitConfig::default(),
            scoring: ScoringConfig::default(),
            ban_duration: Duration::from_secs(3600),
            cleanup_interval: Duration::from_secs(300),
            max_tracked_peers: 10000,
        }
    }
}

/// Banned peer information
#[derive(Debug, Clone)]
struct BannedPeer {
    banned_at: Instant,
    reason: String,
    ban_count: u32,
}

/// Combined anti-DoS protection system
pub struct AntiDoSProtection {
    config: AntiDoSConfig,
    rate_limiter: Arc<RateLimiter>,
    peer_scorer: Arc<PeerScoring>,
    banned_peers: Arc<RwLock<HashMap<SocketAddr, BannedPeer>>>,
    last_cleanup: Arc<RwLock<Instant>>,
}

impl AntiDoSProtection {
    /// Create a new anti-DoS protection system
    pub fn new(config: AntiDoSConfig) -> Self {
        let rate_limiter = RateLimiter::new(config.rate_limit);
        let peer_scorer = PeerScoring::new(config.scoring.clone());

        Self {
            config,
            rate_limiter: Arc::new(rate_limiter),
            peer_scorer: Arc::new(peer_scorer),
            banned_peers: Arc::new(RwLock::new(HashMap::new())),
            last_cleanup: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Check if a request from a peer should be allowed
    pub async fn check_request(&self, peer: &SocketAddr, _request_type: &str) -> Result<(), String> {
        // Check if peer is banned
        if self.is_banned(peer).await {
            return Err("Peer is banned".to_string());
        }

        // Check rate limit
        if !self.rate_limiter.check(peer).await {
            self.peer_scorer.apply_penalty(peer, PenaltyReason::RateLimitExceeded).await;
            return Err("Rate limit exceeded".to_string());
        }

        Ok(())
    }

    /// Check if a peer is currently banned
    pub async fn is_banned(&self, peer: &SocketAddr) -> bool {
        // Check our local ban list
        let banned_peers = self.banned_peers.read().await;
        if let Some(ban_info) = banned_peers.get(peer) {
            let ban_duration = if ban_info.ban_count > 1 {
                self.config.ban_duration * 2_u32.pow((ban_info.ban_count - 1).min(5))
            } else {
                self.config.ban_duration
            };
            if ban_info.banned_at.elapsed() < ban_duration {
                return true;
            }
        }
        drop(banned_peers);

        // Also check rate limiter ban
        self.rate_limiter.is_banned(peer).await
    }

    /// Record a penalty for a peer
    pub async fn record_penalty(&self, peer: &SocketAddr, reason: PenaltyReason) {
        self.peer_scorer.apply_penalty(peer, reason).await;

        // Check if peer should be banned based on scoring
        if self.peer_scorer.is_peer_banned(peer).await {
            self.ban_peer(peer, format!("Low peer score after {:?}", reason)).await;
        }
    }

    /// Ban a peer for a specific reason
    pub async fn ban_peer(&self, peer: &SocketAddr, reason: String) {
        let mut banned_peers = self.banned_peers.write().await;

        let ban_count = banned_peers.get(peer)
            .map(|info| info.ban_count + 1)
            .unwrap_or(1);

        let ban_info = BannedPeer {
            banned_at: Instant::now(),
            reason: reason.clone(),
            ban_count,
        };

        banned_peers.insert(*peer, ban_info);

        warn!("Banned peer {} (count: {}): {}", peer, ban_count, reason);
    }

    /// Unban a peer manually
    pub async fn unban_peer(&self, peer: &SocketAddr) -> bool {
        let mut banned_peers = self.banned_peers.write().await;
        let removed = banned_peers.remove(peer).is_some();

        if removed {
            self.rate_limiter.unban_peer(peer).await;
            info!("Manually unbanned peer {}", peer);
        }

        removed
    }

    /// Get list of currently banned peers
    pub async fn get_banned_peers(&self) -> Vec<(SocketAddr, String, Instant)> {
        let banned_peers = self.banned_peers.read().await;

        banned_peers.iter()
            .filter(|(_, info)| {
                let ban_duration = if info.ban_count > 1 {
                    self.config.ban_duration * 2_u32.pow((info.ban_count - 1).min(5))
                } else {
                    self.config.ban_duration
                };
                info.banned_at.elapsed() < ban_duration
            })
            .map(|(addr, info)| (*addr, info.reason.clone(), info.banned_at))
            .collect()
    }

    /// Perform cleanup of old data
    pub async fn cleanup(&self) {
        let now = Instant::now();

        {
            let last_cleanup = self.last_cleanup.read().await;
            if now.duration_since(*last_cleanup) < self.config.cleanup_interval {
                return;
            }
        }

        {
            let mut last_cleanup = self.last_cleanup.write().await;
            *last_cleanup = now;
        }

        // Cleanup expired bans
        let mut removed_bans = 0;
        {
            let mut banned_peers = self.banned_peers.write().await;
            banned_peers.retain(|_, info| {
                let ban_duration = if info.ban_count > 1 {
                    self.config.ban_duration * 2_u32.pow((info.ban_count - 1).min(5))
                } else {
                    self.config.ban_duration
                };

                let should_keep = info.banned_at.elapsed() < ban_duration;
                if !should_keep {
                    removed_bans += 1;
                }
                should_keep
            });
        }

        // Cleanup rate limiter
        self.rate_limiter.cleanup().await;

        if removed_bans > 0 {
            debug!("Anti-DoS cleanup: removed {} expired bans", removed_bans);
        }
    }

    /// Start background cleanup task
    pub async fn start_cleanup_task(self: Arc<Self>) {
        let cleanup_interval = self.config.cleanup_interval;
        tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);
            loop {
                interval.tick().await;
                self.cleanup().await;
            }
        });
    }

    /// Get system statistics
    pub async fn get_stats(&self) -> AntiDoSStats {
        let banned_peers = self.banned_peers.read().await;

        let active_bans = banned_peers.iter()
            .filter(|(_, info)| {
                let ban_duration = if info.ban_count > 1 {
                    self.config.ban_duration * 2_u32.pow((info.ban_count - 1).min(5))
                } else {
                    self.config.ban_duration
                };
                info.banned_at.elapsed() < ban_duration
            })
            .count();

        AntiDoSStats {
            active_bans,
            total_bans_issued: banned_peers.len(),
        }
    }
}

/// Anti-DoS system statistics
#[derive(Debug, Clone)]
pub struct AntiDoSStats {
    pub active_bans: usize,
    pub total_bans_issued: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_peer() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
    }

    #[tokio::test]
    async fn test_peer_banning() {
        let protection = AntiDoSProtection::new(AntiDoSConfig::default());
        let peer = test_peer();

        protection.ban_peer(&peer, "Test ban".to_string()).await;
        assert!(protection.is_banned(&peer).await);
    }

    #[tokio::test]
    async fn test_cleanup() {
        let config = AntiDoSConfig {
            ban_duration: Duration::from_millis(100),
            cleanup_interval: Duration::from_millis(50),
            ..Default::default()
        };

        let protection = AntiDoSProtection::new(config);
        let peer = test_peer();

        protection.ban_peer(&peer, "Test ban".to_string()).await;
        assert!(protection.is_banned(&peer).await);

        tokio::time::sleep(Duration::from_millis(150)).await;

        protection.cleanup().await;

        assert!(!protection.is_banned(&peer).await);
    }
}
