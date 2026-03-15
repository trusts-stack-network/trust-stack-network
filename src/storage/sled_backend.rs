use async_trait::async_trait;
use sled::Db;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::storage::{StorageBackend, Result, StorageError};

pub struct SledBackend {
    db: Arc<Db>,
}

impl SledBackend {
    pub fn new(path: &str) -> Result<Self> {
        let db = sled::open(path)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;
        Ok(Self {
            db: Arc::new(db),
        })
    }
}

#[async_trait]
impl StorageBackend for SledBackend {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.db.get(key)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?
            .map(|v| v.to_vec()))
    }

    async fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.db.insert(key, value)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn delete(&self, key: &[u8]) -> Result<()> {
        self.db.remove(key)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn contains(&self, key: &[u8]) -> Result<bool> {
        Ok(self.db.contains_key(key)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?)
    }
}