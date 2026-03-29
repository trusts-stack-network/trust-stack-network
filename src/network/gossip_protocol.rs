//! Gossip Protocol Messages for TSN
//!
//! This module defines the message types used for epidemic broadcast
//! of blocks and transactions across the P2P network.
//!
//! Protocol overview:
//! - `Inv`: Inventory announcement - "I have these blocks/transactions"
//! - `GetData`: Data request - "Please send me these blocks/transactions"
//! - `Block`: Actual block data response
//! - `Tx`: Actual transaction data response

use serde::{Deserialize, Serialize};

/// 32-byte hash type used throughout the network protocol
pub type Hash = [u8; 32];

/// Unique identifier for inventory items
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InventoryId {
    /// Type of inventory item
    pub item_type: InventoryType,
    /// Hash of the item
    pub hash: Hash,
}

impl InventoryId {
    pub fn new(item_type: InventoryType, hash: Hash) -> Self {
        Self { item_type, hash }
    }

    pub fn block(hash: Hash) -> Self {
        Self::new(InventoryType::Block, hash)
    }

    pub fn transaction(hash: Hash) -> Self {
        Self::new(InventoryType::Transaction, hash)
    }
}

/// Type of inventory item being announced or requested
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InventoryType {
    /// A block hash
    Block,
    /// A transaction hash
    Transaction,
}

/// Network messages for gossip protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    /// Inventory announcement - announces available blocks/transactions
    /// 
    /// Sent when a node has new data to share. Receivers should check
    /// if they already have the data and request it if not.
    Inv(Vec<InventoryId>),

    /// Request for specific data
    ///
    /// Sent in response to Inv messages for unknown items, or when
    /// a node needs to fetch specific data (e.g., during sync).
    GetData(Vec<InventoryId>),

    /// Block data response
    ///
    /// Contains the full block data in response to a GetData request
    /// for a block hash.
    Block(Vec<u8>), // Serialized block data

    /// Transaction data response
    ///
    /// Contains the full transaction data in response to a GetData
    /// request for a transaction hash.
    Transaction(Vec<u8>), // Serialized transaction data

    /// Reject message - data not available
    ///
    /// Sent when a requested item is not available (e.g., already
    /// pruned or never known).
    NotFound(Vec<InventoryId>),
}

/// Request for data from a specific peer
#[derive(Debug, Clone)]
pub struct DataRequest {
    pub items: Vec<InventoryId>,
    pub request_time: std::time::Instant,
    pub retry_count: u32,
}

impl DataRequest {
    pub fn new(items: Vec<InventoryId>) -> Self {
        Self {
            items,
            request_time: std::time::Instant::now(),
            retry_count: 0,
        }
    }

    pub fn is_expired(&self, timeout: std::time::Duration) -> bool {
        self.request_time.elapsed() > timeout
    }
}

/// Configuration for gossip data requests
#[derive(Debug, Clone, Copy)]
pub struct GossipRequestConfig {
    /// Timeout for data requests
    pub request_timeout: std::time::Duration,
    /// Maximum number of retries
    pub max_retries: u32,
    /// Maximum number of items per GetData message
    pub max_items_per_request: usize,
}

impl Default for GossipRequestConfig {
    fn default() -> Self {
        Self {
            request_timeout: std::time::Duration::from_secs(30),
            max_retries: 3,
            max_items_per_request: 100,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inventory_id_creation() {
        let hash = [1u8; 32];
        let inv = InventoryId::block(hash);
        assert_eq!(inv.item_type, InventoryType::Block);
        assert_eq!(inv.hash, hash);

        let inv_tx = InventoryId::transaction([2u8; 32]);
        assert_eq!(inv_tx.item_type, InventoryType::Transaction);
    }

    #[test]
    fn test_network_message_serialization() {
        let inv = NetworkMessage::Inv(vec![
            InventoryId::block([1u8; 32]),
            InventoryId::transaction([2u8; 32]),
        ]);

        let serialized = bincode::serialize(&inv).unwrap();
        let deserialized: NetworkMessage = bincode::deserialize(&serialized).unwrap();

        match deserialized {
            NetworkMessage::Inv(items) => {
                assert_eq!(items.len(), 2);
                assert_eq!(items[0].item_type, InventoryType::Block);
                assert_eq!(items[1].item_type, InventoryType::Transaction);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_data_request_expiry() {
        let request = DataRequest::new(vec![InventoryId::block([1u8; 32])]);
        assert!(!request.is_expired(std::time::Duration::from_secs(60)));
        // Note: can't easily test expiry without sleeping
    }
}
