use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum DiscoveryError {
    IoError(std::io::Error),
    DecodeError(String),
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DiscoveryError::IoError(err) => write!(f, "IO error: {}", err),
            DiscoveryError::DecodeError(msg) => write!(f, "Decode error: {}", msg),
        }
    }
}

impl Error for DiscoveryError {}

impl From<std::io::Error> for DiscoveryError {
    fn from(err: std::io::Error) -> Self {
        DiscoveryError::IoError(err)
    }
}