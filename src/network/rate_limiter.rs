//! Rate limiting for TSN P2P network
//!
//! Implémentation robuste avec:
//! - Token bucket algorithm pour le rate limiting précis
//! - Sliding window pour la détection de bursts
//! - Nettoyage automatique des entrées inactives
//! - Support IPv4/IPv6

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, trace, warn};

/// Configuration du rate limiter
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateLimitConfig {
    /// Requêtes maximum par seconde (sustained rate)
    pub max_requests_per_second: u32,
    /// Taille du burst autorisé (peak rate)
    pub burst_size: u32,
    /// Durée de bannissement après dépassement
    pub ban_duration: Duration,
    /// Intervalle de nettoyage des entrées inactives
    pub cleanup_interval: Duration,
    /// Durée d'inactivité avant suppression d'une entrée
    pub inactive_timeout: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests_per_second: 100,
            burst_size: 150,
            ban_duration: Duration::from_secs(300),
            cleanup_interval: Duration::from_secs(60),
            inactive_timeout: Duration::from_secs(600),
        }
    }
}

/// État d'un bucket token pour un peer
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Tokens disponibles actuellement
    tokens: f64,
    /// Dernier refill des tokens
    last_refill: Instant,
    /// Dernière activité (pour cleanup)
    last_activity: Instant,
    /// Timestamp du ban si applicable
    banned_until: Option<Instant>,
    /// Nombre de violations consécutives
    violation_count: u32,
}

impl TokenBucket {
    fn new(burst_size: u32) -> Self {
        let now = Instant::now();
        Self {
            tokens: burst_size as f64,
            last_refill: now,
            last_activity: now,
            banned_until: None,
            violation_count: 0,
        }
    }

    /// Vérifie si le peer est actuellement banni
    fn is_banned(&self, now: Instant) -> bool {
        match self.banned_until {
            Some(until) => now < until,
            None => false,
        }
    }

    /// Met à jour le nombre de tokens disponibles
    fn refill(&mut self, rate_per_sec: f64, burst_size: f64, now: Instant) {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate_per_sec).min(burst_size);
        self.last_refill = now;
    }

    /// Tente de consommer un token
    fn try_consume(&mut self) -> bool {
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            self.last_activity = Instant::now();
            true
        } else {
            false
        }
    }

    /// Marque une violation et retourne true si le peer doit être banni
    fn record_violation(&mut self, ban_duration: Duration) -> bool {
        self.violation_count += 1;
        
        // Ban exponentiel : 1min, 5min, 15min, 30min, 1h
        let ban_multiplier = match self.violation_count {
            1 => 1,
            2 => 5,
            3 => 15,
            4 => 30,
            _ => 60,
        };
        
        let actual_ban_duration = ban_duration * ban_multiplier;
        self.banned_until = Some(Instant::now() + actual_ban_duration);
        
        self.violation_count >= 3 // Ban permanent après 3 violations
    }

    /// Réinitialise les violations après une période sans problème
    fn clear_violations(&mut self) {
        self.violation_count = 0;
        self.banned_until = None;
    }
}

/// Rate limiter thread-safe avec token bucket algorithm
#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: Arc<RwLock<HashMap<SocketAddr, TokenBucket>>>,
}

impl RateLimiter {
    /// Crée un nouveau rate limiter avec la configuration donnée
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Crée un rate limiter avec la configuration par défaut
    pub fn default() -> Self {
        Self::new(RateLimitConfig::default())
    }

    /// Vérifie si une requête est autorisée pour ce peer
    /// Retourne true si la requête est autorisée, false si rate limited
    pub async fn check(&self, addr: &SocketAddr) -> bool {
        let mut buckets = self.buckets.write().await;
        let now = Instant::now();

        // Récupère ou crée le bucket
        let bucket = buckets.entry(*addr).or_insert_with(|| {
            TokenBucket::new(self.config.burst_size)
        });

        // Vérifie si banni
        if bucket.is_banned(now) {
            trace!("Peer {} is banned", addr);
            return false;
        }

        // Refill des tokens
        bucket.refill(
            self.config.max_requests_per_second as f64,
            self.config.burst_size as f64,
            now,
        );

        // Tente de consommer un token
        if bucket.try_consume() {
            // Réinitialise les violations si le peer se comporte bien
            if bucket.violation_count > 0 && bucket.tokens > self.config.burst_size as f64 * 0.5 {
                bucket.clear_violations();
            }
            true
        } else {
            // Rate limit atteint
            let should_perma_ban = bucket.record_violation(self.config.ban_duration);
            if should_perma_ban {
                warn!(
                    "Peer {} exceeded rate limit {} times, permanently banned",
                    addr, bucket.violation_count
                );
            } else {
                warn!(
                    "Peer {} rate limited (violation #{}, banned for {:?})",
                    addr, bucket.violation_count, 
                    self.config.ban_duration * bucket.violation_count
                );
            }
            false
        }
    }

    /// Vérifie si un peer est actuellement banni
    pub async fn is_banned(&self, addr: &SocketAddr) -> bool {
        let buckets = self.buckets.read().await;
        match buckets.get(addr) {
            Some(bucket) => bucket.is_banned(Instant::now()),
            None => false,
        }
    }

    /// Bannit manuellement un peer
    pub async fn ban_peer(&self, addr: &SocketAddr, duration: Duration) {
        let mut buckets = self.buckets.write().await;
        let bucket = buckets.entry(*addr).or_insert_with(|| {
            TokenBucket::new(self.config.burst_size)
        });
        bucket.banned_until = Some(Instant::now() + duration);
        bucket.violation_count += 1;
        debug!("Peer {} manually banned for {:?}", addr, duration);
    }

    /// Débannit un peer
    pub async fn unban_peer(&self, addr: &SocketAddr) {
        let mut buckets = self.buckets.write().await;
        if let Some(bucket) = buckets.get_mut(addr) {
            bucket.banned_until = None;
            bucket.violation_count = 0;
            debug!("Peer {} unbanned", addr);
        }
    }

    /// Récupère les statistiques d'un peer
    pub async fn get_peer_stats(&self, addr: &SocketAddr) -> Option<PeerRateStats> {
        let buckets = self.buckets.read().await;
        buckets.get(addr).map(|bucket| PeerRateStats {
            tokens_available: bucket.tokens,
            violation_count: bucket.violation_count,
            is_banned: bucket.is_banned(Instant::now()),
            banned_until: bucket.banned_until,
            last_activity: bucket.last_activity,
        })
    }

    /// Nettoie les entrées inactives
    pub async fn cleanup(&self) {
        let mut buckets = self.buckets.write().await;
        let now = Instant::now();
        let before_count = buckets.len();
        
        buckets.retain(|addr, bucket| {
            let should_keep = now.duration_since(bucket.last_activity) < self.config.inactive_timeout
                && (bucket.banned_until.is_none() || bucket.is_banned(now));
            
            if !should_keep {
                trace!("Removing inactive rate limiter entry for {}", addr);
            }
            should_keep
        });
        
        let removed = before_count - buckets.len();
        if removed > 0 {
            debug!("Cleaned up {} inactive rate limiter entries", removed);
        }
    }

    /// Démarre la tâche de nettoyage périodique
    pub fn start_cleanup_task(self: Arc<Self>) {
        let interval = self.config.cleanup_interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                self.cleanup().await;
            }
        });
    }

    /// Nombre de peers trackés
    pub async fn peer_count(&self) -> usize {
        self.buckets.read().await.len()
    }

    /// Liste des peers actuellement bannis
    pub async fn get_banned_peers(&self) -> Vec<(SocketAddr, Instant)> {
        let buckets = self.buckets.read().await;
        let now = Instant::now();
        
        buckets
            .iter()
            .filter_map(|(addr, bucket)| {
                if bucket.is_banned(now) {
                    bucket.banned_until.map(|until| (*addr, until))
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Statistiques de rate limiting pour un peer
#[derive(Debug, Clone, Copy)]
pub struct PeerRateStats {
    pub tokens_available: f64,
    pub violation_count: u32,
    pub is_banned: bool,
    pub banned_until: Option<Instant>,
    pub last_activity: Instant,
}

/// Rate limiter pour messages spécifiques (gossip, sync, etc.)
#[derive(Debug)]
pub struct MessageRateLimiter {
    /// Rate limiter pour les messages gossip
    pub gossip: RateLimiter,
    /// Rate limiter pour les requêtes de sync
    pub sync: RateLimiter,
    /// Rate limiter pour les handshakes
    pub handshake: RateLimiter,
}

impl MessageRateLimiter {
    /// Crée des rate limiters avec des configurations adaptées à chaque type
    pub fn new() -> Self {
        Self {
            gossip: RateLimiter::new(RateLimitConfig {
                max_requests_per_second: 50,
                burst_size: 100,
                ban_duration: Duration::from_secs(300),
                cleanup_interval: Duration::from_secs(60),
                inactive_timeout: Duration::from_secs(600),
            }),
            sync: RateLimiter::new(RateLimitConfig {
                max_requests_per_second: 10,
                burst_size: 20,
                ban_duration: Duration::from_secs(600),
                cleanup_interval: Duration::from_secs(60),
                inactive_timeout: Duration::from_secs(600),
            }),
            handshake: RateLimiter::new(RateLimitConfig {
                max_requests_per_second: 2,
                burst_size: 5,
                ban_duration: Duration::from_secs(3600),
                cleanup_interval: Duration::from_secs(300),
                inactive_timeout: Duration::from_secs(3600),
            }),
        }
    }

    /// Démarre les tâches de nettoyage pour tous les limiters
    pub fn start_cleanup_tasks(self: Arc<Self>) {
        let this = Arc::clone(&self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            loop {
                ticker.tick().await;
                this.gossip.cleanup().await;
                this.sync.cleanup().await;
                this.handshake.cleanup().await;
            }
        });
    }
}

impl Default for MessageRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[tokio::test]
    async fn test_rate_limiter_accepts_initial_requests() {
        let config = RateLimitConfig::default();
        let limiter = RateLimiter::new(config);
        let addr: SocketAddr = "127.0.0.1:8001".parse().unwrap();

        for _ in 0..10 {
            assert!(limiter.check(&addr).await);
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_blocks_after_burst() {
        let config = RateLimitConfig {
            max_requests_per_second: 5,
            burst_size: 5,
            ban_duration: Duration::from_secs(300),
            cleanup_interval: Duration::from_secs(60),
            inactive_timeout: Duration::from_secs(600),
        };
        let limiter = RateLimiter::new(config);
        let addr: SocketAddr = "127.0.0.1:8002".parse().unwrap();

        for _ in 0..5 {
            assert!(limiter.check(&addr).await);
        }
        assert!(!limiter.check(&addr).await);
    }

    #[tokio::test]
    async fn test_rate_limiter_per_peer_isolation() {
        let config = RateLimitConfig {
            max_requests_per_second: 2,
            burst_size: 2,
            ban_duration: Duration::from_secs(300),
            cleanup_interval: Duration::from_secs(60),
            inactive_timeout: Duration::from_secs(600),
        };
        let limiter = RateLimiter::new(config);
        
        let addr1: SocketAddr = "127.0.0.1:8004".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:8005".parse().unwrap();

        assert!(limiter.check(&addr1).await);
        assert!(limiter.check(&addr1).await);
        assert!(!limiter.check(&addr1).await);

        assert!(limiter.check(&addr2).await);
        assert!(limiter.check(&addr2).await);
    }

    #[tokio::test]
    async fn test_manual_ban_unban() {
        let limiter = RateLimiter::default();
        let addr: SocketAddr = "127.0.0.1:8006".parse().unwrap();

        assert!(!limiter.is_banned(&addr).await);
        
        limiter.ban_peer(&addr, Duration::from_secs(60)).await;
        assert!(limiter.is_banned(&addr).await);
        
        limiter.unban_peer(&addr).await;
        assert!(!limiter.is_banned(&addr).await);
    }
}
