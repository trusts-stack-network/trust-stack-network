//! Transport réseau TCP/UDP pour TSN
//!
//! Implémente les sockets TCP/UDP avec gestion d'erreurs robuste,
//! rate limiting, et support des connexions persistantes pour Kademlia DHT.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{RwLock, mpsc};
use tokio::time::timeout;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use bytes::{Buf, BytesMut};
use tracing::{debug, info, warn, error, trace};
use serde::{Serialize, Deserialize};

use super::rate_limiter::{RateLimiter, RateLimitConfig};
use super::protocol::{encode_message, decode_message, TsnMessage};
use super::{NetworkError, Result};

/// Mask a SocketAddr to a short hash for logs (no IP leak).
fn masked_addr(addr: &SocketAddr) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    addr.hash(&mut h);
    format!("tcp:{:08x}", h.finish() as u32)
}

/// Configuration du transport réseau
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub tcp_listen_addr: SocketAddr,
    pub udp_listen_addr: SocketAddr,
    pub tcp_connect_timeout: Duration,
    pub udp_request_timeout: Duration,
    pub max_buffer_size: usize,
    pub max_tcp_connections: usize,
    pub rate_limit: RateLimitConfig,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            tcp_listen_addr: "0.0.0.0:8000".parse().unwrap(),
            udp_listen_addr: "0.0.0.0:8001".parse().unwrap(),
            tcp_connect_timeout: Duration::from_secs(10),
            udp_request_timeout: Duration::from_secs(5),
            max_buffer_size: 4 * 1024 * 1024,
            max_tcp_connections: 1000,
            rate_limit: RateLimitConfig::default(),
        }
    }
}

/// Connexion TCP active avec buffer et rate limiting
#[derive(Debug)]
struct TcpConnection {
    stream: TcpStream,
    addr: SocketAddr,
    buffer: BytesMut,
    rate_limiter: Arc<RateLimiter>,
    last_activity: Instant,
}

impl TcpConnection {
    fn new(stream: TcpStream, addr: SocketAddr, rate_limit: RateLimitConfig) -> Self {
        Self {
            stream,
            addr,
            buffer: BytesMut::with_capacity(8192),
            rate_limiter: Arc::new(RateLimiter::new(rate_limit)),
            last_activity: Instant::now(),
        }
    }

    async fn send_message(&mut self, message: &TsnMessage) -> Result<()> {
        if !self.rate_limiter.check(&self.addr).await {
            return Err(NetworkError::RateLimited(format!("TCP peer {}", masked_addr(&self.addr))));
        }

        let encoded = encode_message(message)?;

        match timeout(Duration::from_secs(10), self.stream.write_all(&encoded)).await {
            Ok(Ok(())) => {
                self.last_activity = Instant::now();
                trace!("Message TCP envoyé vers {}: {} bytes", masked_addr(&self.addr), encoded.len());
                Ok(())
            },
            Ok(Err(e)) => Err(NetworkError::Io(e)),
            Err(_) => Err(NetworkError::HandshakeTimeout),
        }
    }

    async fn read_messages(&mut self) -> Result<Vec<TsnMessage>> {
        let mut messages = Vec::new();
        let mut temp_buf = [0u8; 8192];

        match timeout(Duration::from_millis(100), self.stream.read(&mut temp_buf)).await {
            Ok(Ok(0)) => {
                // Use a zeroed addr to avoid leaking the real IP in error Display
                return Err(NetworkError::PeerDisconnected(
                    SocketAddr::from(([0, 0, 0, 0], 0))
                ));
            }
            Ok(Ok(n)) => {
                self.buffer.extend_from_slice(&temp_buf[..n]);
                self.last_activity = Instant::now();
            },
            Ok(Err(e)) => return Err(NetworkError::Io(e)),
            Err(_) => return Ok(messages),
        }

        while let Ok(Some((message, consumed))) = decode_message(&mut self.buffer) {
            messages.push(message);
            self.buffer.advance(consumed);

            if self.buffer.len() > 1024 * 1024 {
                warn!("Buffer TCP trop gros pour {}, reset", masked_addr(&self.addr));
                self.buffer.clear();
                break;
            }
        }

        Ok(messages)
    }

    fn is_active(&self) -> bool {
        self.last_activity.elapsed() < Duration::from_secs(300)
    }
}

/// Transport réseau principal
pub struct NetworkTransport {
    config: TransportConfig,
    tcp_connections: Arc<RwLock<HashMap<SocketAddr, TcpConnection>>>,
    udp_rate_limiters: Arc<RwLock<HashMap<SocketAddr, Arc<RateLimiter>>>>,
    message_tx: mpsc::UnboundedSender<(SocketAddr, TsnMessage)>,
    message_rx: Arc<RwLock<Option<mpsc::UnboundedReceiver<(SocketAddr, TsnMessage)>>>>,
}

impl NetworkTransport {
    pub fn new(config: TransportConfig) -> Self {
        let (message_tx, message_rx) = mpsc::unbounded_channel();

        Self {
            config,
            tcp_connections: Arc::new(RwLock::new(HashMap::new())),
            udp_rate_limiters: Arc::new(RwLock::new(HashMap::new())),
            message_tx,
            message_rx: Arc::new(RwLock::new(Some(message_rx))),
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        info!("Démarrage transport réseau TCP:{} UDP:{}",
              self.config.tcp_listen_addr, self.config.udp_listen_addr);

        let tcp_listener = Arc::new(TcpListener::bind(self.config.tcp_listen_addr).await?);
        info!("TCP listener actif sur {}", self.config.tcp_listen_addr);

        let udp_socket = Arc::new(UdpSocket::bind(self.config.udp_listen_addr).await?);
        info!("UDP socket actif sur {}", self.config.udp_listen_addr);

        // TCP accept loop
        {
            let listener = Arc::clone(&tcp_listener);
            let transport = self.clone_for_tasks();
            tokio::spawn(async move {
                transport.tcp_accept_loop(listener).await;
            });
        }

        // UDP receive loop
        {
            let socket = Arc::clone(&udp_socket);
            let transport = self.clone_for_tasks();
            tokio::spawn(async move {
                transport.udp_receive_loop(socket).await;
            });
        }

        // Connection maintenance
        let transport = self.clone_for_tasks();
        tokio::spawn(async move {
            transport.connection_maintenance_loop().await;
        });

        Ok(())
    }

    fn clone_for_tasks(&self) -> Self {
        Self {
            config: self.config.clone(),
            tcp_connections: Arc::clone(&self.tcp_connections),
            udp_rate_limiters: Arc::clone(&self.udp_rate_limiters),
            message_tx: self.message_tx.clone(),
            message_rx: Arc::clone(&self.message_rx),
        }
    }

    pub async fn send_message(&self, addr: SocketAddr, message: TsnMessage) -> Result<()> {
        match &message {
            TsnMessage::Heartbeat { .. } => self.send_udp_message(addr, message, None).await,
            _ => self.send_tcp_message(addr, message).await,
        }
    }

    async fn send_udp_message(&self, addr: SocketAddr, message: TsnMessage, socket: Option<&UdpSocket>) -> Result<()> {
        {
            let mut limiters = self.udp_rate_limiters.write().await;
            let limiter = limiters.entry(addr)
                .or_insert_with(|| Arc::new(RateLimiter::new(self.config.rate_limit.clone())));

            if !limiter.check(&addr).await {
                return Err(NetworkError::RateLimited(format!("UDP peer {}", addr)));
            }
        }

        if let Some(socket) = socket {
            let encoded = encode_message(&message)?;

            match timeout(self.config.udp_request_timeout, socket.send_to(&encoded, addr)).await {
                Ok(Ok(bytes_sent)) => {
                    trace!("Message UDP envoyé vers {}: {} bytes", addr, bytes_sent);
                    Ok(())
                },
                Ok(Err(e)) => Err(NetworkError::Io(e)),
                Err(_) => Err(NetworkError::HandshakeTimeout),
            }
        } else {
            Err(NetworkError::InvalidMessage("UDP socket non initialisé".to_string()))
        }
    }

    async fn send_tcp_message(&self, addr: SocketAddr, message: TsnMessage) -> Result<()> {
        {
            let mut connections = self.tcp_connections.write().await;
            if let Some(conn) = connections.get_mut(&addr) {
                if conn.is_active() {
                    return conn.send_message(&message).await;
                } else {
                    connections.remove(&addr);
                }
            }
        }

        self.create_tcp_connection(addr, message).await
    }

    async fn create_tcp_connection(&self, addr: SocketAddr, message: TsnMessage) -> Result<()> {
        debug!("Création connexion TCP vers {}", masked_addr(&addr));

        let stream = match timeout(self.config.tcp_connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => return Err(NetworkError::Io(e)),
            Err(_) => return Err(NetworkError::HandshakeTimeout),
        };

        let mut connection = TcpConnection::new(stream, addr, self.config.rate_limit.clone());
        connection.send_message(&message).await?;

        {
            let mut connections = self.tcp_connections.write().await;
            if connections.len() >= self.config.max_tcp_connections {
                warn!("Limite de connexions TCP atteinte, refuse {}", masked_addr(&addr));
                return Err(NetworkError::RateLimited("Trop de connexions TCP".to_string()));
            }
            connections.insert(addr, connection);
        }

        debug!("Connexion TCP établie vers {}", masked_addr(&addr));
        Ok(())
    }

    async fn tcp_accept_loop(&self, listener: Arc<TcpListener>) {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    debug!("Nouvelle connexion TCP depuis {}", masked_addr(&addr));

                    {
                        let connections = self.tcp_connections.read().await;
                        if connections.len() >= self.config.max_tcp_connections {
                            warn!("Limite de connexions TCP atteinte, refuse {}", masked_addr(&addr));
                            continue;
                        }
                    }

                    let connection = TcpConnection::new(stream, addr, self.config.rate_limit.clone());

                    {
                        let mut connections = self.tcp_connections.write().await;
                        connections.insert(addr, connection);
                    }

                    let transport = self.clone_for_tasks();
                    tokio::spawn(async move {
                        transport.tcp_connection_handler(addr).await;
                    });
                },
                Err(e) => {
                    error!("Erreur acceptation TCP: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn tcp_connection_handler(&self, addr: SocketAddr) {
        loop {
            let messages = {
                let mut connections = self.tcp_connections.write().await;
                match connections.get_mut(&addr) {
                    Some(conn) => {
                        match conn.read_messages().await {
                            Ok(messages) => messages,
                            Err(e) => {
                                debug!("Erreur lecture TCP {}: {}", masked_addr(&addr), e);
                                connections.remove(&addr);
                                break;
                            }
                        }
                    },
                    None => break,
                }
            };

            for message in messages {
                if let Err(e) = self.message_tx.send((addr, message)) {
                    error!("Erreur envoi message interne: {}", e);
                }
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        debug!("Handler TCP terminé pour {}", masked_addr(&addr));
    }

    async fn udp_receive_loop(&self, socket: Arc<UdpSocket>) {
        let mut buffer = vec![0u8; self.config.max_buffer_size];

        loop {
            match socket.recv_from(&mut buffer).await {
                Ok((len, addr)) => {
                    {
                        let mut limiters = self.udp_rate_limiters.write().await;
                        let limiter = limiters.entry(addr)
                            .or_insert_with(|| Arc::new(RateLimiter::new(self.config.rate_limit.clone())));

                        if !limiter.check(&addr).await {
                            trace!("Rate limit UDP dépassé pour {}", masked_addr(&addr));
                            continue;
                        }
                    }

                    let mut buf = BytesMut::from(&buffer[..len]);
                    match decode_message(&mut buf) {
                        Ok(Some((message, _))) => {
                            trace!("Message UDP reçu de {}: {} bytes", masked_addr(&addr), len);
                            if let Err(e) = self.message_tx.send((addr, message)) {
                                error!("Erreur envoi message UDP interne: {}", e);
                            }
                        },
                        Ok(None) => {
                            trace!("Message UDP incomplet de {}", masked_addr(&addr));
                        },
                        Err(e) => {
                            warn!("Erreur décodage UDP de {}: {}", masked_addr(&addr), e);
                        }
                    }
                },
                Err(e) => {
                    error!("Erreur réception UDP: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn connection_maintenance_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            interval.tick().await;

            {
                let mut connections = self.tcp_connections.write().await;
                let before_count = connections.len();
                connections.retain(|addr, conn| {
                    let active = conn.is_active();
                    if !active {
                        debug!("Suppression connexion TCP inactive: {}", masked_addr(addr));
                    }
                    active
                });
                let after_count = connections.len();
                if before_count != after_count {
                    info!("Nettoyage TCP: {} -> {} connexions", before_count, after_count);
                }
            }

            {
                let mut limiters = self.udp_rate_limiters.write().await;
                let before_count = limiters.len();
                // Clean up old entries periodically
                if before_count > 1000 {
                    limiters.clear();
                    debug!("Nettoyage rate limiters UDP: {} -> 0", before_count);
                }
            }
        }
    }

    pub async fn take_message_receiver(&self) -> Option<mpsc::UnboundedReceiver<(SocketAddr, TsnMessage)>> {
        self.message_rx.write().await.take()
    }

    pub async fn stats(&self) -> TransportStats {
        let tcp_connections = self.tcp_connections.read().await.len();
        let udp_rate_limiters = self.udp_rate_limiters.read().await.len();

        TransportStats {
            tcp_connections,
            udp_rate_limiters,
            tcp_listen_addr: self.config.tcp_listen_addr,
            udp_listen_addr: self.config.udp_listen_addr,
        }
    }
}

/// Statistiques du transport réseau
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportStats {
    pub tcp_connections: usize,
    pub udp_rate_limiters: usize,
    pub tcp_listen_addr: SocketAddr,
    pub udp_listen_addr: SocketAddr,
}
