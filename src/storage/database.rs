//! Database abstraction layer using sled

use crate::core::{Block, BlockId, Transaction, TransactionId};
use crate::crypto::note::Note;
use sled::{Db, Tree};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("Sled error: {0}")]
    Sled(#[from] sled::Error),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Key not found")]
    NotFound,
}

pub struct Database {
    db: Db,
    blocks: Tree,
    transactions: Tree,
    notes: Tree,
    metadata: Tree,
}

impl Database {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, DbError> {
        let db = sled::open(path)?;
        let blocks = db.open_tree("blocks")?;
        let transactions = db.open_tree("transactions")?;
        let notes = db.open_tree("notes")?;
        let metadata = db.open_tree("metadata")?;

        Ok(Self {
            db,
            blocks,
            transactions,
            notes,
            metadata,
        })
    }

    pub fn store_block(&self, block: &Block) -> Result<(), DbError> {
        let key = block.id().as_bytes();
        let value = bincode::serialize(block)
            .map_err(|e| DbError::Serialization(e.to_string()))?;
        self.blocks.insert(key, value)?;
        Ok(())
    }

    pub fn get_block(&self, id: &BlockId) -> Result<Option<Block>, DbError> {
        match self.blocks.get(id.as_bytes())? {
            Some(bytes) => {
                let block = bincode::deserialize(&bytes)
                    .map_err(|e| DbError::Serialization(e.to_string()))?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    pub fn store_transaction(&self, tx: &Transaction) -> Result<(), DbError> {
        let key = tx.id().as_bytes();
        let value = bincode::serialize(tx)
            .map_err(|e| DbError::Serialization(e.to_string()))?;
        self.transactions.insert(key, value)?;
        Ok(())
    }

    pub fn get_transaction(&self, id: &TransactionId) -> Result<Option<Transaction>, DbError> {
        match self.transactions.get(id.as_bytes())? {
            Some(bytes) => {
                let tx = bincode::deserialize(&bytes)
                    .map_err(|e| DbError::Serialization(e.to_string()))?;
                Ok(Some(tx))
            }
            None => Ok(None),
        }
    }

    pub fn flush(&self) -> Result<(), DbError> {
        self.db.flush()?;
        Ok(())
    }
}