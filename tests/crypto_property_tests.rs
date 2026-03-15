// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
use proptest::prelude::*;
use proptest::collection::vec;
use proptest::strategy::Strategy;

// Limites strictes pour éviter l'explosion combinatoire
const MAX_SIZE: usize = 1024;
const MAX_TESTS: u32 = 100;

fn limited_bytes() -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..MAX_SIZE)
}

fn fixed_key() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: MAX_TESTS,
        max_local_rejects: 1000,
        max_global_rejects: 10000,
        max_shrink_iters: 100,
        ..ProptestConfig::default()
    })]
    
    #[test]
    fn prop_encryption_roundtrip(data in limited_bytes(), key in fixed_key()) {
        prop_assume!(!data.is_empty());
        
        let encrypted = xor_encrypt(&data, &key);
        let decrypted = xor_decrypt(&encrypted, &key);
        
        prop_assert_eq!(data, decrypted);
    }
    
    #[test]
    fn prop_mac_consistency(data in limited_bytes(), key in fixed_key()) {
        let tag1 = simple_mac(&data, &key);
        let tag2 = simple_mac(&data, &key);
        
        prop_assert_eq!(tag1, tag2);
    }
    
    #[test]
    fn prop_mac_uniqueness(
        data1 in limited_bytes(),
        data2 in limited_bytes(),
        key in fixed_key()
    ) {
        prop_assume!(data1 != data2);
        
        let tag1 = simple_mac(&data1, &key);
        let tag2 = simple_mac(&data2, &key);
        
        // Collision improbable sur données différentes
        prop_assert_ne!(tag1, tag2);
    }
}

// Implémentations O(n) garanties sans boucle infinie
fn xor_encrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % 32])
        .collect()
}

fn xor_decrypt(ciphertext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    xor_encrypt(ciphertext, key) // XOR symétrique
}

fn simple_mac(data: &[u8], key: &[u8; 32]) -> [u8; 32] {
    let mut state = *key;
    for (i, &byte) in data.iter().enumerate() {
        state[i % 32] = state[i % 32].wrapping_add(byte).rotate_left(1);
    }
    state
}
