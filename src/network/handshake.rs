use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, Duration};
use std::collections::HashMap;
use std::net::SocketAddr;
use log::{info, warn};

// Structure pour stocker les informations de handshake
struct Handshake {
    socket: TcpStream,
    known_nodes: Mutex<HashMap<SocketAddr, u64>>,
    tx: mpsc::Sender<SocketAddr>,
}

impl Handshake {
    async fn new(known_nodes: Mutex<HashMap<SocketAddr, u64>>, tx: mpsc::Sender<SocketAddr>) -> Self {
        let socket = TcpStream::connect("0.0.0.0:0").await.unwrap();
        Handshake { socket, known_nodes, tx }
    }

    async fn start(&self) {
        let mut interval = interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            self.send_handshake().await;
        }
    }

    async fn send_handshake(&self) {
        let message = "TSN_HANDSHAKE";
        self.socket.write_all(message.as_bytes()).await.unwrap();
    }

    async fn handle_message(&self, message: &[u8], addr: SocketAddr) {
        if message.starts_with(b"TSN_HANDSHAKE") {
            self.add_node(addr).await;
        } else {
            warn!("Message inconnu reçu de {}", addr);
        }
    }

    async fn add_node(&self, addr: SocketAddr) {
        let mut known_nodes = self.known_nodes.lock().await;
        if !known_nodes.contains_key(&addr) {
            known_nodes.insert(addr, std::time::SystemTime::now().elapsed().unwrap().as_secs());
            self.tx.send(addr).await.unwrap();
        }
    }
}

// Gestion des erreurs
async fn handle_error(err: std::io::Error) {
    warn!("Erreur réseau : {}", err);
}

// Test avec mock network
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;

    #[test]
    async fn test_handshake() {
        let (tx, mut rx) = mpsc::channel(10);
        let known_nodes = Mutex::new(HashMap::new());
        let handshake = Handshake::new(known_nodes, tx).await;
        handshake.start().await;

        let message = "TSN_HANDSHAKE";
        let addr = SocketAddr::from(([127, 0, 0, 1], 8081));
        handshake.handle_message(message.as_bytes(), addr).await;

        assert!(rx.recv().await.is_some());
    }
}