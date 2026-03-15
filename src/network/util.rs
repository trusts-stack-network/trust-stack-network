use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose};

/// Hash simple d'une adresse pour créer un PeerId
pub fn hash_peer_id(addr: &str) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(addr.as_bytes());
    hasher.update(b"-tsn-2024");
    hasher.finalize().into()
}

/// Parse une adresse "IP:port" avec support IPv6
pub fn parse_addr(s: &str) -> Result<SocketAddr> {
    s.parse().map_err(|_| anyhow!("Adresse invalide : {}", s))
}

/// Timestamp actuel en secondes depuis epoch
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Encode en base64 url-safe sans padding
pub fn b64_encode(bytes: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Décode base64 url-safe sans padding
pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| anyhow!("Base64 err: {}", e))
}

/// Rate limiter simple : token bucket
pub struct RateLimiter {
    tokens: f64,
    max: f64,
    refill_per_sec: f64,
    last: SystemTime,
}

impl RateLimiter {
    pub fn new(max: f64, refill_per_sec: f64) -> Self {
        Self {
            tokens: max,
            max,
            refill_per_sec,
            last: SystemTime::now(),
        }
    }

    /// Tente de consommer n tokens
    pub fn allow(&mut self, n: f64) -> bool {
        let now = SystemTime::now();
        let elapsed = now.duration_since(self.last).unwrap_or_default().as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.max);
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let mut rl = RateLimiter::new(10.0, 1.0);
        assert!(rl.allow(5.0));
        assert!(rl.allow(5.0));
        assert!(!rl.allow(1.0)); // épuisé
    }
}