//! Wallet module for managing private funds.

mod wallet;

pub use wallet::{ShieldedWallet, WalletNote, WalletError};

// Legacy support
pub use wallet::LegacyWallet;
