use thiserror::Error;

#[derive(Debug, Error)]
pub enum TsnError {
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Consensus error: {0}")]
    Consensus(String),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Crypto error: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, TsnError>;