//! Smart contract system for TSN.
//!
//! Provides contract deployment, execution, storage, and standard templates.

pub mod types;
pub mod storage;
pub mod executor;
pub mod templates;

pub use types::*;
pub use executor::{ContractExecutor, ContractError};
