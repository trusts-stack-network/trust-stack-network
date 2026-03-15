//! Fuzzer pour les fonctions crypto vulnérables
//! Détecte les panics, overflows et comportements non déterministes

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use tsn_crypto::vulnerable::{
    insecure_compare, InsecureCtrMode, PredictableRng,
    remove_pkcs7_padding, naive_kdf
};
use tsn_crypto::vulnerable_ops::VulnerableCrypto;

#[derive(Arbitrary, Debug)]
enum VulnerableCryptoOp {
    InsecureCompare {
        a: Vec<u8>,
        b: Vec<u8>,
    },
    CtrModeEncrypt {
        key: [u8; 16],
        nonce: [u8; 16],
        plaintext: Vec<u8>,
    },
    PredictableRng {
        seed: u64,
        output_len: u8, // 0-255 bytes
    },
    RemovePkcs7Padding {
        data: Vec<u8>,
    },
    NaiveKdf {
        password: Vec<u8>,
    },
    VerifyMacVulnerable {
        calculated: Vec<u8>,
        expected: Vec<u8>,
    },
    EncryptAesGcmStaticNonce {
        key: [u8; 32],
        plaintext: Vec<u8>,
    },
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    
    // Générer une opération crypto vulnérable
    if let Ok(op) = VulnerableCryptoOp::arbitrary(&mut u) {
        match op {
            VulnerableCryptoOp::InsecureCompare { a, b } => {
                // Test de la fonction de comparaison vulnérable
                let _ = insecure_compare(&a, &b);
                
                // Propriété: doit être symétrique
                assert_eq!(
                    insecure_compare(&a, &b),
                    insecure_compare(&b, &a)
                );
                
                // Propriété: réflexivité
                assert!(insecure_compare(&a, &a));
                assert!(insecure_compare(&b, &b));
            }
            
            VulnerableCryptoOp::CtrModeEncrypt { key, nonce, plaintext } => {
                // Limiter la taille pour éviter les timeouts
                if plaintext.len() > 1024 {
                    return;
                }
                
                let mut cipher = InsecureCtrMode::new(key, nonce);
                let ciphertext = cipher.encrypt(&plaintext);
                
                // Propriété: taille préservée
                assert_eq!(ciphertext.len(), plaintext.len());
                
                // Propriété: déterminisme (même input = même output)
                let mut cipher2 = InsecureCtrMode::new(key, nonce);
                let ciphertext2 = cipher2.encrypt(&plaintext);
                assert_eq!(ciphertext, ciphertext2);
            }
            
            VulnerableCryptoOp::PredictableRng { seed, output_len } => {
                let mut rng = PredictableRng::new(seed);
                let mut buf = vec![0u8; output_len as usize];
                rng.next_bytes(&mut buf);
                
                // Propriété: déterminisme
                let mut rng2 = PredictableRng::new(seed);
                let mut buf2 = vec![0u8; output_len as usize];
                rng2.next_bytes(&mut buf2);
                assert_eq!(buf, buf2);
            }
            
            VulnerableCryptoOp::RemovePkcs7Padding { data } => {
                let result = remove_pkcs7_padding(&data);
                
                // Propriété: si succès, résultat plus court que l'input
                if let Some(unpadded) = result {
                    assert!(unpadded.len() <= data.len());
                }
                
                // Propriété: padding valide doit être détecté
                if data.len() >= 16 {
                    let mut valid_padded = data.clone();
                    let pad_len = 4u8;
                    valid_padded.truncate(data.len() - pad_len as usize);
                    for _ in 0..pad_len {
                        valid_padded.push(pad_len);
                    }
                    
                    let result = remove_pkcs7_padding(&valid_padded);
                    assert!(result.is_some());
                }
            }
            
            VulnerableCryptoOp::NaiveKdf { password } => {
                // Limiter la taille du mot de passe
                if password.len() > 1024 {
                    return;
                }
                
                let hash = naive_kdf(&password);
                
                // Propriété: taille fixe
                assert_eq!(hash.len(), 32);
                
                // Propriété: déterminisme
                let hash2 = naive_kdf(&password);
                assert_eq!(hash, hash2);
                
                // Propriété: différents passwords = différents hashes (probabiliste)
                if !password.is_empty() {
                    let mut different_password = password.clone();
                    different_password[0] = different_password[0].wrapping_add(1);
                    let different_hash = naive_kdf(&different_password);
                    assert_ne!(hash, different_hash);
                }
            }
            
            VulnerableCryptoOp::VerifyMacVulnerable { calculated, expected } => {
                let result = VulnerableCrypto::verify_mac_vulnerable(&calculated, &expected);
                
                // Propriété: symétrie
                assert_eq!(
                    result,
                    VulnerableCrypto::verify_mac_vulnerable(&expected, &calculated)
                );
                
                // Propriété: réflexivité
                assert!(VulnerableCrypto::verify_mac_vulnerable(&calculated, &calculated));
                assert!(VulnerableCrypto::verify_mac_vulnerable(&expected, &expected));
            }
            
            VulnerableCryptoOp::EncryptAesGcmStaticNonce { key, plaintext } => {
                // Limiter la taille pour éviter les timeouts
                if plaintext.len() > 1024 {
                    return;
                }
                
                let ciphertext = VulnerableCrypto::encrypt_aes_gcm_static_nonce(&key, &plaintext);
                
                // Propriété: ciphertext non vide pour plaintext non vide
                if !plaintext.is_empty() {
                    assert!(!ciphertext.is_empty());
                }
                
                // Propriété: déterminisme (VULNÉRABILITÉ avec nonce statique)
                let ciphertext2 = VulnerableCrypto::encrypt_aes_gcm_static_nonce(&key, &plaintext);
                assert_eq!(ciphertext, ciphertext2);
            }
        }
    }
});

// Fuzzer spécialisé pour les timing attacks
fuzz_target!(|data: &[u8]| -> libfuzzer_sys::Corpus {
    if data.len() < 2 {
        return libfuzzer_sys::Corpus::Reject;
    }
    
    let split_point = data.len() / 2;
    let a = &data[..split_point];
    let b = &data[split_point..];
    
    // Mesurer le timing de la comparaison
    let start = std::time::Instant::now();
    let result = insecure_compare(a, b);
    let duration = start.elapsed();
    
    // Détecter les variations de timing anormales
    if duration.as_nanos() > 1_000_000 { // > 1ms
        // Timing anormalement long détecté
        eprintln!("Timing anomaly detected: {:?} for inputs len=({}, {})", 
                 duration, a.len(), b.len());
    }
    
    // Vérifier la cohérence
    let result2 = insecure_compare(a, b);
    assert_eq!(result, result2, "Non-deterministic behavior detected");
    
    libfuzzer_sys::Corpus::Keep
});

// Fuzzer pour détecter les integer overflows
fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    
    let seed = u64::from_le_bytes([
        data[0], data[1], data[2], data[3],
        data[4], data[5], data[6], data[7]
    ]);
    
    let mut rng = PredictableRng::new(seed);
    
    // Tester avec différentes tailles de buffer
    for size in [1, 16, 256, 1024, 4096] {
        let mut buf = vec![0u8; size];
        rng.next_bytes(&mut buf);
        
        // Vérifier qu'aucun overflow ne s'est produit
        // (le fuzzer détectera les panics automatiquement)
    }
});

// Fuzzer pour les padding oracles
fuzz_target!(|data: &[u8]| {
    let result = remove_pkcs7_padding(data);
    
    // Si le padding est accepté, vérifier la cohérence
    if let Some(unpadded) = result {
        assert!(unpadded.len() <= data.len());
        
        // Le padding retiré doit être valide
        let pad_len = data.len() - unpadded.len();
        if pad_len > 0 && pad_len <= 16 {
            for i in 0..pad_len {
                assert_eq!(data[data.len() - 1 - i], pad_len as u8);
            }
        }
    }
});

// Fuzzer pour détecter les fuites de mémoire ou comportements non déterministes
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    
    // Test du KDF avec différentes tailles d'input
    let hash1 = naive_kdf(data);
    let hash2 = naive_kdf(data);
    
    // Doit être déterministe
    assert_eq!(hash1, hash2);
    
    // Test avec préfixe/suffixe
    if data.len() > 1 {
        let prefix = &data[..data.len()-1];
        let suffix = &data[1..];
        
        let hash_prefix = naive_kdf(prefix);
        let hash_suffix = naive_kdf(suffix);
        
        // Différents inputs doivent donner différents hashes
        assert_ne!(hash1, hash_prefix);
        assert_ne!(hash1, hash_suffix);
    }
});