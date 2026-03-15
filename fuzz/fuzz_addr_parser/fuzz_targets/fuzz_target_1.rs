#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::address::Address;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Le parser ne doit jamais panic
        let _ = Address::from_str(s);
    }
});