//! Fuzzer pour SLH-DSA post-quantique - SÉCURITÉ CRITIQUE
//!
//! Ce fuzzer teste la robustesse de l'implémentation SLH-DSA contre :
//! - Désérialisation de clés/signatures malformées
//! - Messages de taille arbitraire et contenu malveillant
//! - Attaques par corruption de données
//! - Cas limites et inputs extrêmes
//!
//! ⚠️  RÈGLE ABSOLUE : Aucun panic, crash ou comportement indéfini autorisé
//! ⚠️  Toute vulnérabilité trouvée doit être documentée et corrigée

#![no_main]

use libfuzzer_sys::fuzz_target;
use tsn::crypto::pq::slh_dsa::{SecretKey, PublicKey, Signature, PK_BYTES, SK_BYTES, SIG_BYTES};
use arbitrary::{Arbitrary, Unstructured};

#[derive(Arbitrary, Debug)]
enum SlhDsaOperation {
    /// Test de génération de clé avec graine arbitraire
    KeygenFromSeed { seed: [u8; 32] },
    
    /// Test de désérialisation de clé publique
    DeserializePublicKey { pk_bytes: Vec<u8> },
    
    /// Test de désérialisation de signature
    DeserializeSignature { sig_bytes: Vec<u8> },
    
    /// Test de signature avec message arbitraire
    SignMessage { 
        seed: [u8; 32],
        message: Vec<u8>,
    },
    
    /// Test de vérification avec données arbitraires
    VerifySignature {
        pk_bytes: Vec<u8>,
        message: Vec<u8>,
        sig_bytes: Vec<u8>,
    },
    
    /// Test de sérialisation/désérialisation roundtrip
    SerializationRoundtrip {
        seed: [u8; 32],
        message: Vec<u8>,
    },
    
    /// Test avec des tailles de données extrêmes
    ExtremeSizes {
        large_message: Vec<u8>,
    },
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    
    // Générer une opération arbitraire
    let operation = match SlhDsaOperation::arbitrary(&mut unstructured) {
        Ok(op) => op,
        Err(_) => return, // Pas assez de données pour générer une opération
    };
    
    // Exécuter l'opération de manière sécurisée
    match operation {
        SlhDsaOperation::KeygenFromSeed { seed } => {
            fuzz_keygen_from_seed(seed);
        },
        
        SlhDsaOperation::DeserializePublicKey { pk_bytes } => {
            fuzz_deserialize_public_key(&pk_bytes);
        },
        
        SlhDsaOperation::DeserializeSignature { sig_bytes } => {
            fuzz_deserialize_signature(&sig_bytes);
        },
        
        SlhDsaOperation::SignMessage { seed, message } => {
            fuzz_sign_message(seed, &message);
        },
        
        SlhDsaOperation::VerifySignature { pk_bytes, message, sig_bytes } => {
            fuzz_verify_signature(&pk_bytes, &message, &sig_bytes);
        },
        
        SlhDsaOperation::SerializationRoundtrip { seed, message } => {
            fuzz_serialization_roundtrip(seed, &message);
        },
        
        SlhDsaOperation::ExtremeSizes { large_message } => {
            fuzz_extreme_sizes(&large_message);
        },
    }
});

/// Fuzzer pour la génération de clés à partir de graines arbitraires
fn fuzz_keygen_from_seed(seed: [u8; 32]) {
    // La génération de clé ne doit jamais paniquer, même avec des graines malveillantes
    let result = std::panic::catch_unwind(|| {
        let (_sk, _pk) = SecretKey::generate(&seed);
    });
    
    assert!(result.is_ok(), "Panic lors de la génération de clé avec graine: {:?}", seed);
}

/// Fuzzer pour la désérialisation de clés publiques
fn fuzz_deserialize_public_key(pk_bytes: &[u8]) {
    // Test avec des tailles incorrectes
    if pk_bytes.len() != PK_BYTES {
        // La désérialisation doit échouer gracieusement pour des tailles incorrectes
        return;
    }
    
    // Tenter de désérialiser
    let result = std::panic::catch_unwind(|| {
        let pk_array: [u8; PK_BYTES] = match pk_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => return, // Taille incorrecte
        };
        
        let _pk = PublicKey::from_bytes(&pk_array);
        
        // Tester la sérialisation roundtrip
        let serialized = _pk.to_bytes();
        assert_eq!(serialized, pk_array, "Sérialisation roundtrip échouée");
    });
    
    assert!(result.is_ok(), "Panic lors de la désérialisation de clé publique: {:?}", pk_bytes);
}

/// Fuzzer pour la désérialisation de signatures
fn fuzz_deserialize_signature(sig_bytes: &[u8]) {
    // Test avec des tailles incorrectes
    if sig_bytes.len() != SIG_BYTES {
        return;
    }
    
    let result = std::panic::catch_unwind(|| {
        let sig_array: [u8; SIG_BYTES] = match sig_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => return,
        };
        
        let _sig = Signature::from_bytes(&sig_array);
        
        // Tester la sérialisation roundtrip
        let serialized = _sig.to_bytes();
        assert_eq!(serialized, sig_array, "Sérialisation signature roundtrip échouée");
    });
    
    assert!(result.is_ok(), "Panic lors de la désérialisation de signature: {:?}", sig_bytes);
}

/// Fuzzer pour la signature de messages arbitraires
fn fuzz_sign_message(seed: [u8; 32], message: &[u8]) {
    let result = std::panic::catch_unwind(|| {
        let (sk, pk) = SecretKey::generate(&seed);
        
        // Signer le message
        let sig = sk.sign(message);
        
        // Vérifier que la signature est valide
        assert!(pk.verify(message, &sig), "Signature générée invalide");
        
        // Vérifier que la signature est déterministe
        let sig2 = sk.sign(message);
        assert_eq!(sig.to_bytes(), sig2.to_bytes(), "Signature non déterministe");
        
        // Vérifier qu'un message modifié invalide la signature
        if !message.is_empty() {
            let mut modified_message = message.to_vec();
            modified_message[0] ^= 0x01; // Flip 1 bit
            
            if modified_message != message {
                assert!(!pk.verify(&modified_message, &sig), "Signature valide sur message modifié");
            }
        }
    });
    
    assert!(result.is_ok(), "Panic lors de la signature: seed={:?}, message_len={}", seed, message.len());
}

/// Fuzzer pour la vérification de signatures avec données arbitraires
fn fuzz_verify_signature(pk_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) {
    // Vérifier les tailles
    if pk_bytes.len() != PK_BYTES || sig_bytes.len() != SIG_BYTES {
        return;
    }
    
    let result = std::panic::catch_unwind(|| {
        let pk_array: [u8; PK_BYTES] = pk_bytes.try_into().unwrap();
        let sig_array: [u8; SIG_BYTES] = sig_bytes.try_into().unwrap();
        
        let pk = PublicKey::from_bytes(&pk_array);
        let sig = Signature::from_bytes(&sig_array);
        
        // La vérification ne doit jamais paniquer, même avec des données corrompues
        let _is_valid = pk.verify(message, &sig);
        
        // Tester la cohérence : vérifier deux fois doit donner le même résultat
        let is_valid2 = pk.verify(message, &sig);
        assert_eq!(_is_valid, is_valid2, "Vérification incohérente");
    });
    
    assert!(result.is_ok(), "Panic lors de la vérification: pk_len={}, msg_len={}, sig_len={}", 
            pk_bytes.len(), message.len(), sig_bytes.len());
}

/// Fuzzer pour les roundtrips de sérialisation
fn fuzz_serialization_roundtrip(seed: [u8; 32], message: &[u8]) {
    let result = std::panic::catch_unwind(|| {
        let (sk, pk) = SecretKey::generate(&seed);
        
        // Test roundtrip clé publique
        let pk_bytes = pk.to_bytes();
        let pk_deserialized = PublicKey::from_bytes(&pk_bytes);
        assert_eq!(pk.to_bytes(), pk_deserialized.to_bytes(), "Roundtrip clé publique échoué");
        
        // Test roundtrip signature
        if !message.is_empty() {
            let sig = sk.sign(message);
            let sig_bytes = sig.to_bytes();
            let sig_deserialized = Signature::from_bytes(&sig_bytes);
            assert_eq!(sig.to_bytes(), sig_deserialized.to_bytes(), "Roundtrip signature échoué");
            
            // Vérifier que la signature désérialisée est toujours valide
            assert!(pk.verify(message, &sig_deserialized), "Signature désérialisée invalide");
        }
    });
    
    assert!(result.is_ok(), "Panic lors du roundtrip: seed={:?}, message_len={}", seed, message.len());
}

/// Fuzzer pour les tailles extrêmes
fn fuzz_extreme_sizes(large_message: &[u8]) {
    let result = std::panic::catch_unwind(|| {
        // Tester avec un message très long (jusqu'à la limite du fuzzer)
        let seed = [0x42u8; 32]; // Graine fixe pour la reproductibilité
        let (sk, pk) = SecretKey::generate(&seed);
        
        // Signer le message long
        let sig = sk.sign(large_message);
        
        // Vérifier la signature
        assert!(pk.verify(large_message, &sig), "Signature invalide pour message long");
        
        // Tester la performance : ne doit pas être trop lent
        let start = std::time::Instant::now();
        let _sig2 = sk.sign(large_message);
        let elapsed = start.elapsed();
        
        // Limite arbitraire : 10 secondes pour un message de n'importe quelle taille
        assert!(elapsed.as_secs() < 10, "Signature trop lente pour message de {} bytes: {:?}", 
                large_message.len(), elapsed);
    });
    
    assert!(result.is_ok(), "Panic avec message de taille extrême: {} bytes", large_message.len());
}

/// Tests de propriétés invariantes pendant le fuzzing
#[cfg(test)]
mod fuzz_property_tests {
    use super::*;
    
    #[test]
    fn fuzz_property_deterministic_keygen() {
        let seed = [0x12u8; 32];
        let (sk1, pk1) = SecretKey::generate(&seed);
        let (sk2, pk2) = SecretKey::generate(&seed);
        
        assert_eq!(pk1.to_bytes(), pk2.to_bytes());
        assert_eq!(sk1.as_bytes(), sk2.as_bytes());
    }
    
    #[test]
    fn fuzz_property_signature_consistency() {
        let seed = [0x34u8; 32];
        let (sk, pk) = SecretKey::generate(&seed);
        let message = b"test message";
        
        let sig1 = sk.sign(message);
        let sig2 = sk.sign(message);
        
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
        assert!(pk.verify(message, &sig1));
        assert!(pk.verify(message, &sig2));
    }
}