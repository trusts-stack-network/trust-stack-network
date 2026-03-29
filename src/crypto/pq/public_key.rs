#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlhPublicKey {
    pub bytes: Vec<u8>,
    pub algorithm: SlhAlgorithm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlhAlgorithm {
    Sha2_128f,
    Sha2_128s,
    Sha2_192f,
    Sha2_192s,
    Sha2_256f,
    Sha2_256s,
    Shake_128f,
    Shake_128s,
    Shake_192f,
    Shake_192s,
    Shake_256f,
    Shake_256s,
}

impl SlhPublicKey {
    pub fn new(bytes: Vec<u8>, algorithm: SlhAlgorithm) -> Self {
        Self { bytes, algorithm }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Default for SlhPublicKey {
    fn default() -> Self {
        Self {
            bytes: vec![0u8; 32],
            algorithm: SlhAlgorithm::Shake_128f,
        }
    }
}