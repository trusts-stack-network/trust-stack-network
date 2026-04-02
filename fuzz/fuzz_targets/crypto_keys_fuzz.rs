#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::keys::{KeyPair, PublicKey, SecretKey};
use tsn_crypto::address::Address;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct KeyInput {
    seed: Vec<u8>,
    address_version: u8,
    key_type: u8,
}

fuzz_target!(|input: KeyInput| {
    // Test robustesse du key derivation
    if input.seed.len() >= 32 {
        let keypair = KeyPair::from_seed(&input.seed[..32]);
        let pk = keypair.public_key();
        let addr = Address::from_public_key(&pk, input.address_version);
        
        // Vérification de cohérence
        assert!(addr.verify_public_key(&pk).is_ok());
        
        // Test de malleabilité
        let mut pk_bytes = pk.to_bytes();
        if !pk_bytes.is_empty() {
            pk_bytes[0] ^= 0xFF; // Flip tous les bits
            let