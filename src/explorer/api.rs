//! REST API for blockchain explorer.
//!
//! Provides endpoints to query blocks, transactions, and network statistics.
//! All data is returned in JSON format with proper pagination support.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::core::{
    block::{BlockHeader, ShieldedBlock, BLOCK_HASH_SIZE},
    blockchain::ShieldedBlockchain,
    transaction::{ShieldedTransaction, Transaction},
};

/// Maximum number of items per page for pagination.
const MAX_PAGE_SIZE: usize = 100;

/// Default page size for pagination.
const DEFAULT_PAGE_SIZE: usize = 20;

/// Query parameters for paginated requests.
#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    pub page: Option<usize>,
    pub limit: Option<usize>,
}

impl PaginationParams {
    pub fn page(&self) -> usize {
        self.page.unwrap_or(1).max(1)
    }

    pub fn limit(&self) -> usize {
        self.limit
            .unwrap_or(DEFAULT_PAGE_SIZE)
            .min(MAX_PAGE_SIZE)
            .max(1)
    }

    pub fn offset(&self) -> usize {
        (self.page() - 1) * self.limit()
    }
}

/// Response wrapper for paginated results.
#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: usize,
    pub page: usize,
    pub limit: usize,
    pub total_pages: usize,
}

/// Summary information about a block for list views.
#[derive(Debug, Serialize)]
pub struct BlockSummary {
    pub hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub transaction_count: usize,
    pub size: usize,
    pub difficulty: u64,
}

/// Detailed block information.
#[derive(Debug, Serialize)]
pub struct BlockDetail {
    #[serde(flatten)]
    pub summary: BlockSummary,
    pub header: BlockHeader,
    pub transactions: Vec<TransactionSummary>,
}

/// Summary information about a transaction.
#[derive(Debug, Serialize)]
pub struct TransactionSummary {
    pub hash: String,
    pub block_hash: String,
    pub block_height: u64,
    pub fee: u64,
    pub size: usize,
}

/// Detailed transaction information.
#[derive(Debug, Serialize)]
pub struct TransactionDetail {
    #[serde(flatten)]
    pub summary: TransactionSummary,
    pub transaction: Transaction,
}

/// Network statistics.
#[derive(Debug, Serialize)]
pub struct NetworkStats {
    pub block_height: u64,
    pub total_transactions: u64,
    pub total_fees: u64,
    pub average_block_time: f64,
    pub difficulty: u64,
    pub hash_rate: f64,
}

/// Explorer API state shared across handlers.
#[derive(Clone)]
pub struct ExplorerState {
    pub blockchain: Arc<ShieldedBlockchain>,
}

/// Create the explorer API router.
pub fn create_explorer_api(state: ExplorerState) -> Router {
    Router::new()
        .route("/blocks", get(list_blocks))
        .route("/blocks/:hash", get(get_block))
        .route("/blocks/height/:height", get(get_block_by_height))
        .route("/transactions", get(list_transactions))
        .route("/transactions/:hash", get(get_transaction))
        .route("/stats", get(get_stats))
        .with_state(state)
}

/// List blocks with pagination.
async fn list_blocks(
    State(state): State<ExplorerState>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<BlockSummary>>, StatusCode> {
    let blockchain = &state.blockchain;
    let total_blocks = blockchain.get_block_count();
    
    let mut blocks = Vec::new();
    let start_height = total_blocks.saturating_sub(params.offset() as u64 + 1);
    let end_height = start_height.saturating_sub(params.limit() as u64);
    
    for height in (end_height..=start_height).rev() {
        if let Some(block_hash) = blockchain.get_block_hash(height) {
            if let Some(block) = blockchain.get_block(&block_hash) {
                blocks.push(block_to_summary(&block, height));
            }
        }
    }
    
    let total_pages = (total_blocks as f64 / params.limit() as f64).ceil() as usize;
    
    Ok(Json(PaginatedResponse {
        items: blocks,
        total: total_blocks as usize,
        page: params.page(),
        limit: params.limit(),
        total_pages,
    }))
}

/// Get detailed block information by hash.
async fn get_block(
    State(state): State<ExplorerState>,
    Path(hash): Path<String>,
) -> Result<Json<BlockDetail>, StatusCode> {
    let hash_bytes = hex::decode(&hash)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    let blockchain = &state.blockchain;
    let block = blockchain
        .get_block(&hash_bytes)
        .ok_or(StatusCode::NOT_FOUND)?;
    
    let height = blockchain
        .get_block_height(&hash_bytes)
        .ok_or(StatusCode::NOT_FOUND)?;
    
    let transactions = block
        .transactions
        .iter()
        .enumerate()
        .map(|(idx, tx)| transaction_to_summary(tx, &hash_bytes, height, idx))
        .collect();
    
    let summary = BlockSummary {
        hash,
        height,
        timestamp: block.header.timestamp,
        transaction_count: block.transactions.len(),
        size: compute_block_size(&block),
        difficulty: block.header.difficulty,
    };
    
    Ok(Json(BlockDetail {
        summary,
        header: block.header.clone(),
        transactions,
    }))
}

/// Get block by height.
async fn get_block_by_height(
    State(state): State<ExplorerState>,
    Path(height): Path<u64>,
) -> Result<Json<BlockDetail>, StatusCode> {
    let blockchain = &state.blockchain;
    let hash = blockchain
        .get_block_hash(height)
        .ok_or(StatusCode::NOT_FOUND)?;
    
    let block = blockchain
        .get_block(&hash)
        .ok_or(StatusCode::NOT_FOUND)?;
    
    let transactions = block
        .transactions
        .iter()
        .enumerate()
        .map(|(idx, tx)| transaction_to_summary(tx, &hash, height, idx))
        .collect();
    
    let summary = BlockSummary {
        hash: hex::encode(hash),
        height,
        timestamp: block.header.timestamp,
        transaction_count: block.transactions.len(),
        size: compute_block_size(&block),
        difficulty: block.header.difficulty,
    };
    
    Ok(Json(BlockDetail {
        summary,
        header: block.header.clone(),
        transactions,
    }))
}

/// List transactions with pagination.
async fn list_transactions(
    State(state): State<ExplorerState>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<TransactionSummary>>, StatusCode> {
    let blockchain = &state.blockchain;
    let total_height = blockchain.get_block_count();
    let mut all_transactions = Vec::new();
    
    // Collect transactions from recent blocks
    let start_height = total_height.saturating_sub(1000); // Last 1000 blocks max
    for height in start_height..=total_height {
        if let Some(hash) = blockchain.get_block_hash(height) {
            if let Some(block) = blockchain.get_block(&hash) {
                for (idx, tx) in block.transactions.iter().enumerate() {
                    all_transactions.push(transaction_to_summary(tx, &hash, height, idx));
                }
            }
        }
    }
    
    // Apply pagination
    let total = all_transactions.len();
    let offset = params.offset().min(total);
    let limit = params.limit().min(total - offset);
    let items = all_transactions.into_iter().skip(offset).take(limit).collect();
    
    let total_pages = (total as f64 / params.limit() as f64).ceil() as usize;
    
    Ok(Json(PaginatedResponse {
        items,
        total,
        page: params.page(),
        limit: params.limit(),
        total_pages,
    }))
}

/// Get detailed transaction information.
async fn get_transaction(
    State(state): State<ExplorerState>,
    Path(hash): Path<String>,
) -> Result<Json<TransactionDetail>, StatusCode> {
    let hash_bytes = hex::decode(&hash)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    let blockchain = &state.blockchain;
    let total_height = blockchain.get_block_count();
    
    // Search for transaction in all blocks
    for height in 0..=total_height {
        if let Some(block_hash) = blockchain.get_block_hash(height) {
            if let Some(block) = blockchain.get_block(&block_hash) {
                for (idx, tx) in block.transactions.iter().enumerate() {
                    if tx_hash(tx) == hash_bytes {
                        let summary = TransactionSummary {
                            hash,
                            block_hash: hex::encode(block_hash),
                            block_height: height,
                            fee: tx.fee(),
                            size: compute_transaction_size(tx),
                        };
                        
                        return Ok(Json(TransactionDetail {
                            summary,
                            transaction: tx.clone(),
                        }));
                    }
                }
            }
        }
    }
    
    Err(StatusCode::NOT_FOUND)
}

/// Get network statistics.
async fn get_stats(State(state): State<ExplorerState>) -> Json<NetworkStats> {
    let blockchain = &state.blockchain;
    let block_height = blockchain.get_block_count();
    
    // Calculate average block time
    let average_block_time = if block_height > 1 {
        let latest_height = block_height;
        let earliest_height = block_height.saturating_sub(100);
        
        if let (Some(latest_hash), Some(earliest_hash)) = (
            blockchain.get_block_hash(latest_height),
            blockchain.get_block_hash(earliest_height),
        ) {
            if let (Some(latest_block), Some(earliest_block)) = (
                blockchain.get_block(&latest_hash),
                blockchain.get_block(&earliest_hash),
            ) {
                let time_span = latest_block.header.timestamp - earliest_block.header.timestamp;
                let blocks = latest_height - earliest_height;
                if blocks > 0 {
                    time_span as f64 / blocks as f64
                } else {
                    0.0
                }
            } else {
                0.0
            }
        } else {
            0.0
        }
    } else {
        0.0
    };
    
    // Calculate hash rate from difficulty
    let hash_rate = estimate_hash_rate(blockchain.get_difficulty());
    
    Json(NetworkStats {
        block_height,
        total_transactions: count_total_transactions(blockchain),
        total_fees: count_total_fees(blockchain),
        average_block_time,
        difficulty: blockchain.get_difficulty(),
        hash_rate,
    })
}

// Helper functions

fn block_to_summary(block: &ShieldedBlock, height: u64) -> BlockSummary {
    BlockSummary {
        hash: hex::encode(block.header.hash()),
        height,
        timestamp: block.header.timestamp,
        transaction_count: block.transactions.len(),
        size: compute_block_size(block),
        difficulty: block.header.difficulty,
    }
}

fn transaction_to_summary(
    tx: &Transaction,
    block_hash: &[u8; BLOCK_HASH_SIZE],
    block_height: u64,
    _index: usize,
) -> TransactionSummary {
    TransactionSummary {
        hash: hex::encode(tx_hash(tx)),
        block_hash: hex::encode(block_hash),
        block_height,
        fee: tx.fee(),
        size: compute_transaction_size(tx),
    }
}

fn tx_hash(tx: &Transaction) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let data = bincode::serialize(tx).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn compute_block_size(block: &ShieldedBlock) -> usize {
    bincode::serialize(block).unwrap_or_default().len()
}

fn compute_transaction_size(tx: &Transaction) -> usize {
    bincode::serialize(tx).unwrap_or_default().len()
}

fn count_total_transactions(blockchain: &ShieldedBlockchain) -> u64 {
    let mut count = 0u64;
    let total_height = blockchain.get_block_count();
    for height in 0..=total_height {
        if let Some(hash) = blockchain.get_block_hash(height) {
            if let Some(block) = blockchain.get_block(&hash) {
                count += block.transactions.len() as u64;
            }
        }
    }
    count
}

fn count_total_fees(blockchain: &ShieldedBlockchain) -> u64 {
    let mut total = 0u64;
    let total_height = blockchain.get_block_count();
    for height in 0..=total_height {
        if let Some(hash) = blockchain.get_block_hash(height) {
            if let Some(block) = blockchain.get_block(&hash) {
                for tx in &block.transactions {
                    total += tx.fee();
                }
            }
        }
    }
    total
}

fn estimate_hash_rate(difficulty: u64) -> f64 {
    // Simplified estimation: hash_rate ≈ difficulty * 2^32 / block_time
    // Using average block time of 600 seconds (10 minutes)
    const TARGET_BLOCK_TIME: f64 = 600.0;
    (difficulty as f64 * 4_294_967_296.0) / TARGET_BLOCK_TIME
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pagination_params() {
        let params = PaginationParams {
            page: Some(2),
            limit: Some(10),
        };
        assert_eq!(params.page(), 2);
        assert_eq!(params.limit(), 10);
        assert_eq!(params.offset(), 10);
    }

    #[test]
    fn test_pagination_defaults() {
        let params = PaginationParams {
            page: None,
            limit: None,
        };
        assert_eq!(params.page(), 1);
        assert_eq!(params.limit(), DEFAULT_PAGE_SIZE);
    }

    #[test]
    fn test_pagination_limits() {
        let params = PaginationParams {
            page: Some(0),
            limit: Some(1000),
        };
        assert_eq!(params.page(), 1); // Min 1
        assert_eq!(params.limit(), MAX_PAGE_SIZE); // Max 100
    }
}