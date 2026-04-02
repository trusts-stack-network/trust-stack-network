#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn::crypto::keys::{PublicKey, SecretKey, Signature};
use tsn::crypto::transaction::Transaction;
use tsn::crypto::note::Note;
use tsn::crypto::commitment::Commitment;
use tsn::crypto::address::Address;

/// Fuzzing des parsers cryptographiques pour détecter des crashs et panics
fuzz_target!(|data: &[u8]| {
    // Test parsing de clé publique
    if data.len() >= 32 {
        let _ = PublicKey::from_bytes(data);
    }
    
    // Test parsing de signature
    if data.len() >= 64 {
        let _ = Signature::from_bytes(data);
    }
    
    // Test parsing de commitment
    if data.len() >= 32 {
        let _ = Commitment::from_bytes(data);
    }
    
    // Test parsing d'adresse
    let _ = Address::from_bytes(data);
    
    // Test parsing de note (nécessite des données structurées)
   