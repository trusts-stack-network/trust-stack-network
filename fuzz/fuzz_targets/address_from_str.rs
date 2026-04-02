#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::address::Address;

fuzz_target!(|data: &str| {
    let _ = Address::from_str(data);
});