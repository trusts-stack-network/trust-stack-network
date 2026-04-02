//! Module de cryptographie post-quantique
//! 
//! Utilise `alloc` au lieu de `std` pour la compatibilité no_std avec slh-dsa

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use alloc::string::String;

/// Re-export des types SLH-DSA avec alloc
pub use slh_dsa::{
    Sha2_128s, Sha2_128f, Sha2_192s, Sha2_192f, Sha2_256s, Sha2_256f,
    Shake_128s, Shake_128f, Shake_192s, Shake_192f, Shake_256s, Shake_256f,
    SigningKey, VerifyingKey, Signature, Error,
};

pub mod keygen;
pub mod sign;