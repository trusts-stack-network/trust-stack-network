use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::RwLock;

use libp2p::core::PeerId;

// Fonction de validation des messages
fn validate_message(message: &RpcResponse) -> bool {
    // Validation des messages
    // ...
    true
}

// Fonction de rate limiting
fn rate_limit(peer_id: PeerId, socket_addr: SocketAddr) -> bool {
    // Rate limiting
    // ...
    true
}