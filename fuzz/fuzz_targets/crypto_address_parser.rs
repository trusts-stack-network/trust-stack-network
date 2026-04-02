#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::address::{Address, validate_address};

fuzz_target!(|data: &[u8]| {
    if data.len() != 32 {
        return;
    }
    
    // Test address parsing and validation
    let address = Address::from_bytes(data);
    validate_address(&address);
});