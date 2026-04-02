#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn::crypto::address::Address;
use std::str;

fuzz_target!(|data: &[u8]| {
    // Test parsing d'addresses depuis des données arbitraires
    if let Ok(s) = str::from_utf8(data) {
        let _ = Address::from_str(s);
    }
    
    // Test parsing depuis bytes
    let _ = Address::from_bytes(data);
    
    // Test parsing avec corruption
    if data.len() >= 32 {
        let mut corrupted = data.to_vec();
        corrupted[0] = corrupted[0].wrapping_add(1);
        let _ = Address::from_bytes(&