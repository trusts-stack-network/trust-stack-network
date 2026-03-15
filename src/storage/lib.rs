pub mod error;
pub mod sled_backend;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub use error::{StorageError, Result};

#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;
    async fn put(&self, key: &[u8], value: &[u8]) -> Result<()>;
    async fn delete(&self, key: &[u8]) -> Result<()>;
    async fn contains(&self, key: &[u8]) -> Result<bool>;
}

pub struct Storage {
    backend: Box<dyn StorageBackend>,
}

impl Storage {
    pub fn new(backend: Box<dyn StorageBackend>) -> Self {
        Self { backend }
    }

    pub async fn get<T: for<'de> Deserialize<'de>>(&self, key: &[u8]) -> Result<Option<T>> {
        match self.backend.get(key).await? {
            Some(data) => {
                let value = serde_json::from_slice(&data)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    pub async fn put<T: Serialize>(&self, key: &[u8], value: &T) -> Result<()> {
        let data = serde_json::to_vec(value)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.backend.put(key, &data).await
    }

    pub async fn delete(&self, key: &[u8]) -> Result<()> {
        self.backend.delete(key).await
    }

    pub async fn contains(&self, key: &[u8]) -> Result<bool> {
        self.backend.contains(key).await
    }
}