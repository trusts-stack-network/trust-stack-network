use std::convert::TryInto;

#[derive(Debug)]
pub struct DiscoveryMessage {
    pub peer_id: PeerId,
}

impl DiscoveryMessage {
    pub fn new() -> Self {
        let peer_id = PeerId::random();
        DiscoveryMessage { peer_id }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.peer_id.to_bytes());
        buffer
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, String> {
        let peer_id = PeerId::from_bytes(buffer).map_err(|_| "Invalid peer ID".to_string())?;
        Ok(DiscoveryMessage { peer_id })
    }
}

#[derive(Debug)]
pub struct HandshakeMessage {
    pub peer_id: PeerId,
}

impl HandshakeMessage {
    pub fn new(peer_id: PeerId) -> Self {
        HandshakeMessage { peer_id }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.peer_id.to_bytes());
        buffer
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, String> {
        let peer_id = PeerId::from_bytes(buffer).map_err(|_| "Invalid peer ID".to_string())?;
        Ok(HandshakeMessage { peer_id })
    }
}