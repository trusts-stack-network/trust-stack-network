#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::signature::{SignatureScheme, verify_signature};
use tsn_crypto::keys::PublicKey;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    
    // Split data into public key, message, and signature
    let (pk_bytes, rest) = data.split_at(32);
    if rest.len() < 64 {
        return;
    }
    let (msg, sig_bytes) = rest.split_at(rest.len() - 64);
    
    let public_key = match PublicKey::from_bytes(pk_bytes) {
        Ok(pk) => pk,
        Err(_) => return,
    };
    
    // This should not panic regardless of input
    let _ = verify_signature(&public_key, msg, sig_bytes);
});