#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn::crypto::{
    signature::Signature,
    keys::{PublicKey, SecretKey},
    commitment::Commitment,
    nullifier::Nullifier,
    note::Note,
    address::Address,
    poseidon::PoseidonHash
};
use std::convert::TryFrom;

/// Fuzz all crypto parsers for panic conditions
fuzz_target!(|data: &[u8]| {
   