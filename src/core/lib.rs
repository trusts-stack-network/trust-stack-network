//! Core blockchain primitives for Trust Stack Network.
//! This crate is intentionally minimal; the real implementation lives in the parent workspace.

// Re-export the types that the rest of the workspace expects to find here.
pub use blockchain::*;
pub use block::*;
pub use transaction::*;
pub use state::*;
pub use account::*;

// Place-holder modules so the crate compiles.
// The canonical implementations are still in the top-level `src/core/*.rs` files.
mod blockchain;
mod block;
mod transaction;
mod state;
mod account;