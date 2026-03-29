//! SLH-DSA signature validation for consensus
//! Replaces ML-DSA-65 validation with SLH-DSA signatures

use crate::core::block::{Block, BlockHeader};
use crate::core::transaction::{Transaction, TransactionType};
use crate::crypto::pq::slh_dsa::{SlhDsa, SlhPublicKey, SlhSignature};
use crate::crypto::hash::HashValue;
use crate::error::{ProtocolError, ValidationError};
use std::collections::HashSet;

/// SLH-DSA validator for