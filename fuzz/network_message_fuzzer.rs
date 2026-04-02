//! Fuzzer: Messages réseau malformés
//!
//! Ce fuzzer teste la robustesse du parser de messages réseau TSN
//! contre des entrées malveillantes.
//!
//! # Surfaces d'attaque testées
//! - Désérialisation de messages
//! - Parsing de headers
//! - Validation de tailles
//! - Gestion des buffers
//!
//! # Usage
//! ```bash
//! cargo fuzz run network_message_fuzzer
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use tsn::network::message::{Message, MessageParser};

fuzz_target!(|data: &[u8]| {
    // Test 1: Parsing de message brut
    // Ne doit jamais paniquer, même avec des données aléatoires
    let _ = MessageParser::parse(data);

    // Test 2: Si le parsing réussit, vérifier les invariants
    if let Ok(msg) = MessageParser::parse(data) {
        // Vérifier que la taille est cohérente
        if let Some(size) = msg.payload_size() {
            assert!(size <= 10_000_000, "Payload trop grand: {}", size);
        }

        // Vérifier que le type de message est valide
        assert!(
            msg.message_type().is_valid(),
            "Type de message invalide"
        );
    }

    // Test 3: Round-trip sérialisation/désérialisation
    if let Ok(original) = MessageParser::parse(data) {
        if let Ok(serialized) = original.serialize() {
            // La resérialisation doit produire le même message
            if let Ok(roundtrip) = MessageParser::parse(&serialized) {
                assert_eq!(
                    original.message_type(),
                    roundtrip.message_type(),
                    "Round-trip incohérent pour le type"
                );
            }
        }
    }
});
