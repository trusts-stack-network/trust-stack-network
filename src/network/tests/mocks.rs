//! Mocks pour les tests réseau TSN
//! 
//! Ce module fournit des implémentations mock des interfaces réseau pour permettre
//! des tests unitaires isolés sans dépendances externes.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};
use async_trait::async_trait;

/// Mock d'un socket réseau pour les tests
#[derive(Debug, Clone)]
pub struct MockSocket {
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub incoming: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    pub outgoing: Arc<Mutex<mpsc::Sender<Vec<u8>>>>,
}

impl MockSocket {
    pub fn new_pair() -> (Self, Self) {
        let (tx1, rx1) = mpsc::channel(100);
        let (tx2, rx2) = mpsc::channel(100);
        
        let addr1: SocketAddr = "127.0.0.1:10001".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:10002".parse().unwrap();
        
        let socket1 = MockSocket {
            local_addr: addr1,
            peer_addr: addr2,
            incoming: Arc::new(Mutex::new(rx2)),
            outgoing: Arc::new(Mutex::new(tx1)),
        };
        
        let socket2 = MockSocket {
            local_addr: addr2,
            peer_addr: addr1,
            incoming: Arc::new(Mutex::new(rx1)),
            outgoing: Arc::new(Mutex::new(tx2)),
        };
        
        (socket1, socket2)
    }
    
    pub async fn send(&self, data: Vec<u8>) -> std::io::Result<()> {
        self.outgoing.lock().await.send(data).await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "channel closed"))
    }
    
    pub async fn recv(&self) -> std::io::Result<Vec<u8>> {
        self.incoming.lock().await.recv().await
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "channel closed"))
    }
}

/// Mock discovery service
#[derive(Debug, Clone)]
pub struct MockDiscovery {
    pub known_peers: Arc<Mutex<Vec<SocketAddr>>>,
    pub discovery_delay: Duration,
}

impl MockDiscovery {
    pub fn new() -> Self {
        Self {
            known_peers: Arc::new(Mutex::new(vec![
                "127.0.0.1:9001".parse().unwrap(),
                "127.0.0.1:9002".parse().unwrap(),
                "127.0.0.1:9003".parse().unwrap(),
            ])),
            discovery_delay: Duration::from_millis(10),
        }
    }
    
    pub async fn discover(&self) -> Vec<SocketAddr> {
        tokio::time::sleep(self.discovery_delay).await;
        self.known_peers.lock().await.clone()
    }
    
    pub async fn add_peer(&self, addr: SocketAddr) {
        self.known_peers.lock().await.push(addr);
    }
}

/// Mock handshake handler
#[derive(Debug, Clone)]
pub struct MockHandshake {
    pub should_fail: Arc<Mutex<bool>>,
    pub delay: Duration,
}

impl MockHandshake {
    pub fn new() -> Self {
        Self {
            should_fail: Arc::new(Mutex::new(false)),
            delay: Duration::from_millis(10),
        }
    }
    
    pub async fn set_fail(&self, should_fail: bool) {
        *self.should_fail.lock().await = should_fail;
    }
    
    pub async fn perform(&self) -> Result<(), std::io::Error> {
        tokio::time::sleep(self.delay).await;
        
        if *self.should_fail.lock().await {
            Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "mock handshake failed"))
        } else {
            Ok(())
        }
    }
}

/// Mock rate limiter pour les tests
#[derive(Debug, Clone)]
pub struct MockRateLimiter {
    pub allowed_count: Arc<Mutex<u32>>,
    pub max_requests: u32,
    pub window_duration: Duration,
    pub last_reset: Arc<Mutex<Instant>>,
}

impl MockRateLimiter {
    pub fn new(max_requests: u32, window_duration: Duration) -> Self {
        Self {
            allowed_count: Arc::new(Mutex::new(0)),
            max_requests,
            window_duration,
            last_reset: Arc::new(Mutex::new(Instant::now())),
        }
    }
    
    pub async fn check(&self, _addr: &SocketAddr) -> bool {
        let mut count = self.allowed_count.lock().await;
        let mut last_reset = self.last_reset.lock().await;
        let now = Instant::now();
        
        if now.duration_since(*last_reset) >= self.window_duration {
            *count = 0;
            *last_reset = now;
        }
        
        if *count < self.max_requests {
            *count += 1;
            true
        } else {
            false
        }
    }
}

/// Mock anti-DoS protector
#[derive(Debug, Clone)]
pub struct MockAntiDos {
    pub banned_peers: Arc<Mutex<Vec<SocketAddr>>>,
    pub violation_threshold: u32,
}

impl MockAntiDos {
    pub fn new(violation_threshold: u32) -> Self {
        Self {
            banned_peers: Arc::new(Mutex::new(Vec::new())),
            violation_threshold,
        }
    }
    
    pub async fn report_violation(&self, peer: SocketAddr) {
        let mut banned = self.banned_peers.lock().await;
        if !banned.contains(&peer) {
            banned.push(peer);
        }
    }
    
    pub async fn is_banned(&self, peer: &SocketAddr) -> bool {
        self.banned_peers.lock().await.contains(peer)
    }
}