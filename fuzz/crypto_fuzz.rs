#![no_main]

use libfuzzer_sys::fuzz_target;
use std::time::Instant;

// Limite de temps par exécution de fuzz
const MAX_FUZZ_TIME_MS: u128 = 100;

fuzz_target!(|data: &[u8]| {
    let start = Instant::now();
    
    // Vérification de taille pour éviter OOM
    if data.len() > 4096 {
        return;
    }
    
    // Timeout de sécurité
    let timeout = || start.elapsed().as_millis() > MAX_FUZZ_TIME_MS;
    
    if data.len() < 32 {
        return;
    }
    
    let mut key = [0u8; 32];
    key.copy_from_slice(&data[..32]);
    let message = &data[32..];
    
    if timeout() { return; }
    
    // Test 1: Roundtrip encryption
    let ciphertext = stream_xor(message, &key);
    let plaintext = stream_xor(&ciphertext, &key);
    assert_eq!(message, plaintext);
    
    if timeout() { return; }
    
    // Test 2: MAC ne panique pas
    let _tag = fast_mac(message, &key);
    
    if timeout() { return; }
    
    // Test 3: Hash ne boucle pas
    let _hash = quick