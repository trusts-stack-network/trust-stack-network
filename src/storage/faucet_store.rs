//! Faucet claim storage

use crate::crypto::keys::PublicKey;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaucetClaim {
    pub public_key: PublicKey,
    pub amount: u64,
    pub timestamp: DateTime<Utc>,
    pub claimed: bool,
}

impl FaucetClaim {
    pub fn new(public_key: PublicKey, amount: u64) -> Self {
        Self {
            public_key,
            amount,
            timestamp: Utc::now(),
            claimed: false,
        }
    }
}