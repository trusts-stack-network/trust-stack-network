use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub version: u8,
    pub data: Vec<u8>,
}

impl Packet {
    pub fn new(data: Vec<u8>) -> Self {
        Self { version: 1, data }
    }
}