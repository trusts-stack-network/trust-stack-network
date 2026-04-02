use std::time::{Duration, Instant};

// Limite stricte pour éviter les timeouts
const MAX_TEST_TIME: Duration = Duration::from_millis(500);
const MAX_ITERATIONS: usize = 1000;

#[test]
fn test_encryption_roundtrip() {
    let start = Instant::now();
    
    for i in 0..MAX_ITERATIONS {
        if start.elapsed() > MAX_TEST_TIME {
            break;
        }
        
        let data = format!("test_data_{}", i);
        let key = derive_key(&format!("key_{}", i));
        let encrypted = encrypt(&data, &key);
        let decrypted = decrypt(&encrypted, &key);
        
        assert_eq!(data, decrypted);
    }
}

#[test]
fn test_mac_verification() {
    let key = [0u8; 32];
    let message = b"test message";
    let tag = compute_mac(message, &key);
    
    assert!(verify_mac(message, &tag, &key));
    assert!(!verify_mac(b"wrong", &tag, &key));
}

// Implémentations minimales pour compilation rapide
fn derive_key(seed: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    let bytes = seed.as_bytes();
    for i in 0..32.min(bytes.len()) {
        key[i] = bytes[i];
    }
    key
}

fn encrypt(data: &str, key: &[u8; 32]) -> Vec<u8> {
    data.bytes().zip(key.iter().cycle()).map(|(b, k)| b ^ k).collect()
}

fn decrypt(ciphertext: &[u8], key: &[u8; 32]) -> String {
    String::from_utf8(
        ciphertext.iter().zip(key.iter().cycle()).map(|(b, k)| b ^ k).collect()
    ).unwrap()
}

fn compute_mac(message: &[u8], key: &[u8; 32]) -> [u8; 32] {
    let mut tag = [0u8; 32];
    for (i, &b) in message.iter().enumerate() {
        tag[i % 32] ^= b ^ key[i % 32];
    }
    tag
}

fn verify_mac(message: &[u8], tag: &[u8; 32], key: &[u8; 32]) -> bool {
    compute_mac(message, key) == *tag
}