#![no_main]

use libfuzzer_sys::fuzz_target;
use trust_stack_network::crypto::legacy_vulnerable::decrypt_aes256ctr_vulnerable;

fuzz_target!(|data: &[u8]| {
    if data.len() < 48 {
        return;
    }
    
    let key = &data[0..32];
    let iv = &data[32..48];
    let ciphertext = &data[48..];
    
    // This should not panic, even with invalid inputs
    let _ = decrypt_aes256ctr_vulnerable(ciphertext, key, iv);
});