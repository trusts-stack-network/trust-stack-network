use serde::{Deserialize, Serialize};

pub type NoteId = [u8; 32];
pub type PublicKey = [u8; 32];
pub type Timestamp = u64;
pub type AccountId = [u8; 32];
pub type TxId = [u8; 32];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub id: AccountId,
    pub balance: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedState {
    pub root: [u8; 32],
    pub size: u64,
}