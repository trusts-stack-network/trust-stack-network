//! Module de tests pour le réseau TSN
//! 
//! Organisation des tests en modules séparés pour une meilleure maintenabilité.

pub mod unit_tests;
pub mod handshake_tests;
pub mod security_tests;
pub mod performance_tests;
pub mod integration_tests;

// Re-export des tests pour compatibilité
pub use unit_tests::*;
pub use handshake_tests::*;
pub use security_tests::*;
pub use performance_tests::*;
pub use integration_tests::*;