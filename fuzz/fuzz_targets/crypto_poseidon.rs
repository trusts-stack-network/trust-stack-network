#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::PoseidonHash;

fuzz_target!(|data: &[u8]| {
    // Test la résistance du hash Poseidon aux entrées malformées
    let hasher = PoseidonHash::new();
    
    // Ne doit jamais paniquer
    let _ = hasher.hash(data);
    
    // Test avec des entrées de taille extrême
    let mut big_input = vec![0u8; 1024 * 1024]; // 1MB
    if !data.is_empty() {
        let