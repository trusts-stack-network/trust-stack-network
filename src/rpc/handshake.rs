use serde::{Serialize, Deserialize};
use log::info;

// Requête de handshake RPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRequest {
    pub id: String,
    pub version: String,
}

// Réponse de handshake RPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub id: String,
}