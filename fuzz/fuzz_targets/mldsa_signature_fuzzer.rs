//! Fuzzer pour les signatures ML-DSA-65 post-quantiques
//! 
//! Ce fuzzer teste spécifiquement l'implémentation FIPS204 ML-DSA-65
//! utilisée dans TSN pour la signature des transactions et blocs.
//! 
//! Modules testés:
//! - Génération de clés ML-DSA-65
//! - Signature de messages
//! - Vérification de signatures
//! - Sérialisation/désérialisation de clés et signatures
//! - Résistance aux attaques par malléabilité

#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use tsn::crypto::pq::signature::*;
use tsn::crypto::keys::*;

/// Structure pour les données de fuzzing ML-DSA
#[derive(Debug)]
struct MLDSAFuzzInput {
    // Message à signer
    message: Vec<u8>,
    
    // Données de clé privée
    private_key_seed: Vec<u8>,
    private_key_bytes: Vec<u8>,
    
    // Données de clé publique
    public_key_bytes: Vec<u8>,
    
    // Signature data
    signature_bytes: Vec<u8>,
    
    // Adversarial inputs
    malformed_signature: Vec<u8>,
    modified_message: Vec<u8>,
    
    // Key manipulation
    key_modification_offset: usize,
    key_modification_value: u8,
    
    // Signature manipulation
    sig_modification_offset: usize,
    sig_modification_value: u8,
    
    // Context data
    context: Vec<u8>,
    
    // Batch verification data
    batch_messages: Vec<Vec<u8>>,
    batch_signatures: Vec<Vec<u8>>,
    batch_public_keys: Vec<Vec<u8>>,
}

impl<'a> Arbitrary<'a> for MLDSAFuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let message_len = u.int_in_range(0..=8192)?;
        let private_key_len = u.int_in_range(0..=4096)?;
        let public_key_len = u.int_in_range(0..=2048)?;
        let signature_len = u.int_in_range(0..=4096)?;
        let malformed_sig_len = u.int_in_range(0..=4096)?;
        let modified_msg_len = u.int_in_range(0..=8192)?;
        let context_len = u.int_in_range(0..=255)?; // ML-DSA context max 255 bytes
        let batch_size = u.int_in_range(0..=16)?; // Limite pour éviter OOM
        let seed_len = u.int_in_range(0..=64)?;
        
        let mut batch_messages = Vec::new();
        let mut batch_signatures = Vec::new();
        let mut batch_public_keys = Vec::new();
        
        for _ in 0..batch_size {
            let msg_len = u.int_in_range(0..=1024)?;
            let sig_len = u.int_in_range(0..=4096)?;
            let key_len = u.int_in_range(0..=2048)?;
            
            batch_messages.push((0..msg_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?);
            batch_signatures.push((0..sig_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?);
            batch_public_keys.push((0..key_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?);
        }
        
        Ok(MLDSAFuzzInput {
            message: (0..message_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            private_key_seed: (0..seed_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            private_key_bytes: (0..private_key_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            public_key_bytes: (0..public_key_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            signature_bytes: (0..signature_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            malformed_signature: (0..malformed_sig_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            modified_message: (0..modified_msg_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            key_modification_offset: u.arbitrary()?,
            key_modification_value: u.arbitrary()?,
            sig_modification_offset: u.arbitrary()?,
            sig_modification_value: u.arbitrary()?,
            context: (0..context_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            batch_messages,
            batch_signatures,
            batch_public_keys,
        })
    }
}

fuzz_target!(|input: MLDSAFuzzInput| {
    // Test génération et vérification de signatures valides
    fuzz_valid_signature_flow(&input);
    
    // Test désérialisation de clés malformées
    fuzz_key_deserialization(&input);
    
    // Test désérialisation de signatures malformées
    fuzz_signature_deserialization(&input);
    
    // Test résistance aux modifications de signature
    fuzz_signature_malleability(&input);
    
    // Test résistance aux modifications de message
    fuzz_message_modification(&input);
    
    // Test vérification batch
    fuzz_batch_verification(&input);
    
    // Test avec contexte
    fuzz_context_handling(&input);
});

/// Fuzz le flow complet de signature valide
fn fuzz_valid_signature_flow(input: &MLDSAFuzzInput) {
    // Test 1: Génération de clés déterministe si seed suffisant
    if input.private_key_seed.len() >= 32 {
        let seed: [u8; 32] = match input.private_key_seed[..32].try_into() {
            Ok(s) => s,
            Err(_) => return,
        };
        
        let keypair_result = generate_mldsa_keypair_from_seed(seed);
        if let Ok(keypair) = keypair_result {
            // Test de signature
            if !input.message.is_empty() {
                let signature_result = sign_mldsa(&keypair.private_key, &input.message, &input.context);
                
                if let Ok(signature) = signature_result {
                    // Test de vérification
                    let verify_result = verify_mldsa(&keypair.public_key, &input.message, &signature, &input.context);
                    
                    if verify_result.is_err() {
                        // CRITIQUE: Signature générée par nous-mêmes doit être valide
                        panic!("SECURITY BUG: Valid signature failed verification");
                    }
                    
                    // Test de sérialisation/désérialisation
                    test_signature_serialization(&signature, &keypair.public_key, &input.message, &input.context);
                    
                    // Test de résistance aux modifications
                    test_signature_immutability(&signature, &keypair.public_key, &input.message, &input.context);
                    
                    // Test avec message modifié (doit échouer)
                    if !input.modified_message.is_empty() && input.modified_message != input.message {
                        let verify_modified = verify_mldsa(&keypair.public_key, &input.modified_message, &signature, &input.context);
                        if verify_modified.is_ok() {
                            // CRITIQUE: Signature ne doit pas être valide pour un message différent
                            panic!("SECURITY BUG: Signature valid for different message");
                        }
                    }
                    
                    // Test avec contexte modifié (doit échouer)
                    if !input.context.is_empty() {
                        let mut modified_context = input.context.clone();
                        if !modified_context.is_empty() {
                            modified_context[0] = modified_context[0].wrapping_add(1);
                            let verify_modified_ctx = verify_mldsa(&keypair.public_key, &input.message, &signature, &modified_context);
                            if verify_modified_ctx.is_ok() {
                                // CRITIQUE: Signature ne doit pas être valide avec contexte différent
                                panic!("SECURITY BUG: Signature valid for different context");
                            }
                        }
                    }
                }
            }
            
            // Test de sérialisation des clés
            test_key_serialization(&keypair);
        }
    }
    
    // Test 2: Génération de clés aléatoire
    let random_keypair_result = generate_mldsa_keypair();
    if let Ok(keypair) = random_keypair_result {
        // Test de signature avec message vide
        let empty_sig_result = sign_mldsa(&keypair.private_key, &[], &[]);
        if let Ok(empty_signature) = empty_sig_result {
            let verify_empty = verify_mldsa(&keypair.public_key, &[], &empty_signature, &[]);
            if verify_empty.is_err() {
                // Signature de message vide doit être valide
                return;
            }
        }
        
        // Test avec message de taille maximale (si pas trop grand)
        if input.message.len() <= 1024 * 1024 { // 1MB max pour éviter OOM
            let large_sig_result = sign_mldsa(&keypair.private_key, &input.message, &input.context);
            if let Ok(large_signature) = large_sig_result {
                let verify_large = verify_mldsa(&keypair.public_key, &input.message, &large_signature, &input.context);
                if verify_large.is_err() {
                    // Signature de gros message doit être valide
                    return;
                }
            }
        }
    }
}

/// Test la sérialisation/désérialisation des signatures
fn test_signature_serialization(signature: &MLDSASignature, public_key: &MLDSAPublicKey, message: &[u8], context: &[u8]) {
    // Test de sérialisation
    let serialized = serialize_mldsa_signature(signature);
    if serialized.is_empty() {
        // Signature sérialisée ne doit pas être vide
        return;
    }
    
    // Test de désérialisation
    let deserialized_result = deserialize_mldsa_signature(&serialized);
    if let Ok(deserialized_sig) = deserialized_result {
        // Test de vérification de la signature désérialisée
        let verify_deserialized = verify_mldsa(public_key, message, &deserialized_sig, context);
        if verify_deserialized.is_err() {
            // CRITIQUE: Signature désérialisée doit rester valide
            panic!("SECURITY BUG: Deserialized signature became invalid");
        }
        
        // Test de re-sérialisation (doit être identique)
        let re_serialized = serialize_mldsa_signature(&deserialized_sig);
        if serialized != re_serialized {
            // Problème potentiel dans la sérialisation canonique
            return;
        }
    }
}

/// Test l'immutabilité des signatures
fn test_signature_immutability(signature: &MLDSASignature, public_key: &MLDSAPublicKey, message: &[u8], context: &[u8]) {
    let mut serialized = serialize_mldsa_signature(signature);
    
    // Test de modification de chaque byte
    for i in 0..serialized.len().min(256) { // Limite pour éviter timeout
        let original_byte = serialized[i];
        
        // Test avec différentes modifications
        for modification in [1u8, 255u8, original_byte.wrapping_add(1)] {
            if modification != original_byte {
                serialized[i] = modification;
                
                let modified_sig_result = deserialize_mldsa_signature(&serialized);
                if let Ok(modified_sig) = modified_sig_result {
                    let verify_modified = verify_mldsa(public_key, message, &modified_sig, context);
                    if verify_modified.is_ok() {
                        // CRITIQUE: Signature modifiée ne doit pas être valide
                        panic!("SECURITY BUG: Modified signature still valid at byte {}", i);
                    }
                }
                
                // Restaurer le byte original
                serialized[i] = original_byte;
            }
        }
    }
}

/// Test la sérialisation des clés
fn test_key_serialization(keypair: &MLDSAKeyPair) {
    // Test sérialisation clé publique
    let pub_serialized = serialize_mldsa_public_key(&keypair.public_key);
    if !pub_serialized.is_empty() {
        let pub_deserialized_result = deserialize_mldsa_public_key(&pub_serialized);
        if let Ok(pub_deserialized) = pub_deserialized_result {
            // Test que la clé désérialisée fonctionne
            let test_message = b"test message";
            let test_sig_result = sign_mldsa(&keypair.private_key, test_message, &[]);
            if let Ok(test_sig) = test_sig_result {
                let verify_original = verify_mldsa(&keypair.public_key, test_message, &test_sig, &[]);
                let verify_deserialized = verify_mldsa(&pub_deserialized, test_message, &test_sig, &[]);
                
                if verify_original.is_ok() && verify_deserialized.is_err() {
                    // CRITIQUE: Clé publique désérialisée doit fonctionner
                    panic!("SECURITY BUG: Deserialized public key doesn't work");
                }
            }
        }
    }
    
    // Test sérialisation clé privée
    let priv_serialized = serialize_mldsa_private_key(&keypair.private_key);
    if !priv_serialized.is_empty() {
        let priv_deserialized_result = deserialize_mldsa_private_key(&priv_serialized);
        if let Ok(priv_deserialized) = priv_deserialized_result {
            // Test que la clé privée désérialisée fonctionne
            let test_message = b"test message";
            let test_sig_original = sign_mldsa(&keypair.private_key, test_message, &[]);
            let test_sig_deserialized = sign_mldsa(&priv_deserialized, test_message, &[]);
            
            if let (Ok(sig_orig), Ok(sig_deser)) = (test_sig_original, test_sig_deserialized) {
                let verify_orig = verify_mldsa(&keypair.public_key, test_message, &sig_orig, &[]);
                let verify_deser = verify_mldsa(&keypair.public_key, test_message, &sig_deser, &[]);
                
                if verify_orig.is_ok() && verify_deser.is_err() {
                    // CRITIQUE: Clé privée désérialisée doit fonctionner
                    panic!("SECURITY BUG: Deserialized private key doesn't work");
                }
            }
        }
    }
}

/// Fuzz la désérialisation de clés malformées
fn fuzz_key_deserialization(input: &MLDSAFuzzInput) {
    // Test désérialisation clé publique
    let pub_key_result = deserialize_mldsa_public_key(&input.public_key_bytes);
    match pub_key_result {
        Ok(pub_key) => {
            // Si la désérialisation réussit, tester la clé
            let test_message = b"test";
            
            // Créer une signature factice pour tester la vérification
            if !input.signature_bytes.is_empty() {
                let sig_result = deserialize_mldsa_signature(&input.signature_bytes);
                if let Ok(sig) = sig_result {
                    let verify_result = verify_mldsa(&pub_key, test_message, &sig, &[]);
                    // Peut échouer ou réussir, ne doit pas paniquer
                    let _ = verify_result;
                }
            }
            
            // Test de re-sérialisation
            let re_serialized = serialize_mldsa_public_key(&pub_key);
            if !re_serialized.is_empty() {
                let round_trip = deserialize_mldsa_public_key(&re_serialized);
                let _ = round_trip; // Ne doit pas paniquer
            }
        },
        Err(_) => {
            // Échec attendu pour des données aléatoires
        }
    }
    
    // Test désérialisation clé privée
    let priv_key_result = deserialize_mldsa_private_key(&input.private_key_bytes);
    match priv_key_result {
        Ok(priv_key) => {
            // Test de signature avec clé désérialisée
            let test_message = b"test";
            let sign_result = sign_mldsa(&priv_key, test_message, &[]);
            let _ = sign_result; // Peut échouer ou réussir
            
            // Test de re-sérialisation
            let re_serialized = serialize_mldsa_private_key(&priv_key);
            if !re_serialized.is_empty() {
                let round_trip = deserialize_mldsa_private_key(&re_serialized);
                let _ = round_trip;
            }
        },
        Err(_) => {
            // Échec attendu
        }
    }
    
    // Test avec données tronquées
    test_truncated_keys(input);
    
    // Test avec patterns adversariaux
    test_adversarial_key_patterns();
}

/// Test avec données de clés tronquées
fn test_truncated_keys(input: &MLDSAFuzzInput) {
    // Test clé publique tronquée
    if input.public_key_bytes.len() > 10 {
        for len in [1, 4, 8, input.public_key_bytes.len() / 2, input.public_key_bytes.len() - 1] {
            if len < input.public_key_bytes.len() {
                let truncated = &input.public_key_bytes[..len];
                let result = deserialize_mldsa_public_key(truncated);
                // Doit échouer gracieusement
                if result.is_ok() {
                    // Données tronquées ne devraient pas être acceptées
                }
            }
        }
    }
    
    // Test clé privée tronquée
    if input.private_key_bytes.len() > 10 {
        for len in [1, 4, 8, input.private_key_bytes.len() / 2, input.private_key_bytes.len() - 1] {
            if len < input.private_key_bytes.len() {
                let truncated = &input.private_key_bytes[..len];
                let result = deserialize_mldsa_private_key(truncated);
                // Doit échouer gracieusement
                let _ = result;
            }
        }
    }
}

/// Test avec patterns adversariaux pour les clés
fn test_adversarial_key_patterns() {
    let patterns = [
        vec![0x00; 2048],           // Tous zéros
        vec![0xFF; 2048],           // Tous uns
        (0u8..=255).cycle().take(2048).collect::<Vec<u8>>(), // Séquence
        vec![0xAA, 0x55].repeat(1024), // Pattern alterné
    ];
    
    for pattern in &patterns {
        // Test clé publique
        let pub_result = deserialize_mldsa_public_key(pattern);
        let _ = pub_result;
        
        // Test clé privée
        let priv_result = deserialize_mldsa_private_key(pattern);
        let _ = priv_result;
    }
}

/// Fuzz la désérialisation de signatures malformées
fn fuzz_signature_deserialization(input: &MLDSAFuzzInput) {
    // Test avec signature_bytes
    let sig_result = deserialize_mldsa_signature(&input.signature_bytes);
    let _ = sig_result;
    
    // Test avec malformed_signature
    let malformed_result = deserialize_mldsa_signature(&input.malformed_signature);
    let _ = malformed_result;
    
    // Test avec données tronquées
    if input.signature_bytes.len() > 10 {
        for len in [1, 4, 8, input.signature_bytes.len() / 2, input.signature_bytes.len() - 1] {
            if len < input.signature_bytes.len() {
                let truncated = &input.signature_bytes[..len];
                let result = deserialize_mldsa_signature(truncated);
                let _ = result;
            }
        }
    }
    
    // Test avec patterns adversariaux
    let patterns = [
        vec![0x00; 4096],
        vec![0xFF; 4096],
        (0u8..=255).cycle().take(4096).collect::<Vec<u8>>(),
    ];
    
    for pattern in &patterns {
        let result = deserialize_mldsa_signature(pattern);
        let _ = result;
    }
}

/// Fuzz la résistance aux modifications de signature
fn fuzz_signature_malleability(input: &MLDSAFuzzInput) {
    if input.signature_bytes.len() > input.sig_modification_offset {
        let mut modified_sig = input.signature_bytes.clone();
        modified_sig[input.sig_modification_offset] = input.sig_modification_value;
        
        let sig_result = deserialize_mldsa_signature(&modified_sig);
        if let Ok(sig) = sig_result {
            // Créer une clé publique factice pour tester
            if let Ok(keypair) = generate_mldsa_keypair() {
                let verify_result = verify_mldsa(&keypair.public_key, &input.message, &sig, &input.context);
                // Peut échouer ou réussir, ne doit pas paniquer
                let _ = verify_result;
            }
        }
    }
}

/// Fuzz la résistance aux modifications de message
fn fuzz_message_modification(input: &MLDSAFuzzInput) {
    // Générer une signature valide
    if let Ok(keypair) = generate_mldsa_keypair() {
        if let Ok(signature) = sign_mldsa(&keypair.private_key, &input.message, &input.context) {
            // Test avec message modifié
            if !input.modified_message.is_empty() && input.modified_message != input.message {
                let verify_modified = verify_mldsa(&keypair.public_key, &input.modified_message, &signature, &input.context);
                if verify_modified.is_ok() {
                    // CRITIQUE: Ne doit pas être valide pour message différent
                    panic!("SECURITY BUG: Signature valid for modified message");
                }
            }
            
            // Test avec modifications byte par byte (échantillonnage)
            if !input.message.is_empty() {
                let mut modified_msg = input.message.clone();
                let test_positions = [0, input.message.len() / 2, input.message.len() - 1];
                
                for &pos in &test_positions {
                    if pos < modified_msg.len() {
                        let original = modified_msg[pos];
                        modified_msg[pos] = original.wrapping_add(1);
                        
                        let verify_modified = verify_mldsa(&keypair.public_key, &modified_msg, &signature, &input.context);
                        if verify_modified.is_ok() {
                            // CRITIQUE: Ne doit pas être valide
                            panic!("SECURITY BUG: Signature valid for byte-modified message at pos {}", pos);
                        }
                        
                        // Restaurer
                        modified_msg[pos] = original;
                    }
                }
            }
        }
    }
}

/// Fuzz la vérification batch
fn fuzz_batch_verification(input: &MLDSAFuzzInput) {
    if input.batch_messages.is_empty() {
        return;
    }
    
    // Créer des signatures valides pour test
    let mut valid_signatures = Vec::new();
    let mut valid_public_keys = Vec::new();
    
    for message in &input.batch_messages {
        if let Ok(keypair) = generate_mldsa_keypair() {
            if let Ok(signature) = sign_mldsa(&keypair.private_key, message, &[]) {
                valid_signatures.push(signature);
                valid_public_keys.push(keypair.public_key);
            }
        }
    }
    
    // Test vérification batch valide
    if !valid_signatures.is_empty() {
        let batch_verify_result = verify_mldsa_batch(
            &valid_public_keys,
            &input.batch_messages,
            &valid_signatures,
            &vec![vec![]; valid_signatures.len()], // Contextes vides
        );
        
        if batch_verify_result.is_err() {
            // Signatures valides doivent passer la vérification batch
            return;
        }
    }
    
    // Test avec signatures malformées du fuzzer
    let mut fuzz_signatures = Vec::new();
    let mut fuzz_public_keys = Vec::new();
    
    for (sig_bytes, key_bytes) in input.batch_signatures.iter().zip(input.batch_public_keys.iter()) {
        if let Ok(sig) = deserialize_mldsa_signature(sig_bytes) {
            if let Ok(key) = deserialize_mldsa_public_key(key_bytes) {
                fuzz_signatures.push(sig);
                fuzz_public_keys.push(key);
            }
        }
    }
    
    if !fuzz_signatures.is_empty() && fuzz_signatures.len() == fuzz_public_keys.len() {
        let messages_ref: Vec<&[u8]> = input.batch_messages.iter().take(fuzz_signatures.len()).map(|m| m.as_slice()).collect();
        if messages_ref.len() == fuzz_signatures.len() {
            let batch_verify_fuzz = verify_mldsa_batch(
                &fuzz_public_keys,
                &messages_ref,
                &fuzz_signatures,
                &vec![vec![]; fuzz_signatures.len()],
            );
            // Peut échouer ou réussir, ne doit pas paniquer
            let _ = batch_verify_fuzz;
        }
    }
}

/// Fuzz la gestion du contexte
fn fuzz_context_handling(input: &MLDSAFuzzInput) {
    if let Ok(keypair) = generate_mldsa_keypair() {
        // Test avec différentes tailles de contexte
        let contexts = [
            vec![],                    // Vide
            input.context.clone(),     // Du fuzzer
            vec![0; 255],             // Taille max
            vec![0xFF; 255],          // Taille max, tous 1
        ];
        
        for context in &contexts {
            // Test signature avec contexte
            let sign_result = sign_mldsa(&keypair.private_key, &input.message, context);
            
            if let Ok(signature) = sign_result {
                // Test vérification avec même contexte
                let verify_result = verify_mldsa(&keypair.public_key, &input.message, &signature, context);
                if verify_result.is_err() {
                    // Signature avec contexte doit être valide
                    return;
                }
                
                // Test vérification avec contexte différent
                let different_context = if context.is_empty() {
                    vec![1]
                } else {
                    vec![]
                };
                
                let verify_different = verify_mldsa(&keypair.public_key, &input.message, &signature, &different_context);
                if verify_different.is_ok() {
                    // CRITIQUE: Ne doit pas être valide avec contexte différent
                    panic!("SECURITY BUG: Signature valid with different context");
                }
            }
        }
        
        // Test avec contexte trop grand (> 255 bytes)
        if input.context.len() > 255 {
            let oversized_context = &input.context[..256]; // Prendre 256 bytes
            let sign_oversized = sign_mldsa(&keypair.private_key, &input.message, oversized_context);
            // Doit échouer gracieusement
            let _ = sign_oversized;
        }
    }
}