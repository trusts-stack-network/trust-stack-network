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
    /// Node role announced during handshake (None for backwards compatibility with older peers)
    #[cfg_attr(feature = "serde", serde(default))]
    pub role: Option<String>,
}

impl HandshakeMessage {
    pub fn new(peer_id: PeerId) -> Self {
        HandshakeMessage { peer_id, role: None }
    }

    pub fn with_role(peer_id: PeerId, role: String) -> Self {
        HandshakeMessage { peer_id, role: Some(role) }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.peer_id.to_bytes());
        // Append role as length-prefixed UTF-8 string (0 length = no role, for backwards compat)
        if let Some(ref role) = self.role {
            let role_bytes = role.as_bytes();
            buffer.extend_from_slice(&(role_bytes.len() as u16).to_be_bytes());
            buffer.extend_from_slice(role_bytes);
        }
        buffer
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, String> {
        let peer_id = PeerId::from_bytes(buffer).map_err(|_| "Invalid peer ID".to_string())?;
        // Try to read optional role after the peer_id bytes (backwards compatible)
        let peer_id_len = peer_id.to_bytes().len();
        let role = if buffer.len() > peer_id_len + 2 {
            let role_len = u16::from_be_bytes(
                buffer[peer_id_len..peer_id_len + 2]
                    .try_into()
                    .map_err(|_| "Invalid role length".to_string())?,
            ) as usize;
            if role_len > 0 && buffer.len() >= peer_id_len + 2 + role_len {
                let role_str = std::str::from_utf8(&buffer[peer_id_len + 2..peer_id_len + 2 + role_len])
                    .map_err(|_| "Invalid role UTF-8".to_string())?;
                Some(role_str.to_string())
            } else {
                None
            }
        } else {
            None
        };
        Ok(HandshakeMessage { peer_id, role })
    }
}