// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
//! Tests de sécurité pour auditer et démontrer les vulnérabilités crypto
//! Ces tests DOIVENT échouer avec le code vulnérable actuel

use proptest::prelude::*;
use std::time::{Duration, Instant};
use tsn_crypto::vulnerable::{
    insecure_compare, InsecureCtrMode, PredictableRng, 
    remove_pkcs7_padding, naive_kdf
};
use tsn_crypto::vulnerable_ops::{VulnerableCrypto, DecryptionError};

/// Test de régression: Timing attack sur comparaison
#[test]
fn test_timing_attack_vulnerability() {
    let correct_mac = b"secret_mac_value_32_bytes_long!!";
    let mut wrong_mac = *correct_mac;
    
    // Mesurer timing pour MAC complètement faux
    wrong_mac[0] = !wrong_mac[0];
    let start = Instant::now();
    let _ = insecure_compare(correct_mac, &wrong_mac);
    let duration_wrong_first = start.elapsed();
    
    // Mesurer timing pour MAC avec premier byte correct
    wrong_mac[0] = correct_mac[0];
    wrong_mac[31] = !wrong_mac[31];
    let start = Instant::now();
    let _ = insecure_compare(correct_mac, &wrong_mac);
    let duration_wrong_last = start.elapsed();
    
    // VULNÉRABILITÉ: Le timing devrait être différent
    // (ce test échoue avec l'implémentation sécurisée)
    println!("Timing wrong first byte: {:?}", duration_wrong_first);
    println!("Timing wrong last byte: {:?}", duration_wrong_last);
    
    // Avec l'implémentation vulnérable, wrong_first est plus rapide
    assert!(duration_wrong_first < duration_wrong_last);
}

/// Test de régression: Nonce reuse catastrophique
#[test]
fn test_nonce_reuse_vulnerability() {
    let key = [0x42; 16];
    let nonce = [0x13; 16];
    let mut cipher = InsecureCtrMode::new(key, nonce);
    
    let plaintext1 = b"Secret message 1";
    let plaintext2 = b"Secret message 2";
    
    let ciphertext1 = cipher.encrypt(plaintext1);
    
    // Reset counter pour réutiliser le même keystream
    cipher.counter = 0;
    let ciphertext2 = cipher.encrypt(plaintext2);
    
    // VULNÉRABILITÉ: XOR des ciphertexts révèle XOR des plaintexts
    let xor_ciphers: Vec<u8> = ciphertext1.iter()
        .zip(ciphertext2.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    
    let xor_plains: Vec<u8> = plaintext1.iter()
        .zip(plaintext2.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    
    // Avec nonce reuse, XOR(C1, C2) = XOR(P1, P2)
    assert_eq!(xor_ciphers, xor_plains);
}

/// Test de régression: RNG prévisible
#[test]
fn test_predictable_rng_vulnerability() {
    let seed = 0x1337;
    let mut rng1 = PredictableRng::new(seed);
    let mut rng2 = PredictableRng::new(seed);
    
    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];
    
    rng1.next_bytes(&mut buf1);
    rng2.next_bytes(&mut buf2);
    
    // VULNÉRABILITÉ: Même seed = même output
    assert_eq!(buf1, buf2);
    
    // Test de prédictibilité
    let mut rng3 = PredictableRng::new(seed);
    let mut buf3 = [0u8; 32];
    rng3.next_bytes(&mut buf3);
    
    assert_eq!(buf1, buf3);
}

/// Test de régression: Padding oracle
#[test]
fn test_padding_oracle_vulnerability() {
    // Données avec padding PKCS#7 valide
    let valid_data = b"Hello world!\x04\x04\x04\x04";
    let invalid_data = b"Hello world!\x04\x04\x04\x03";
    
    let start = Instant::now();
    let result1 = remove_pkcs7_padding(valid_data);
    let duration_valid = start.elapsed();
    
    let start = Instant::now();
    let result2 = remove_pkcs7_padding(invalid_data);
    let duration_invalid = start.elapsed();
    
    assert!(result1.is_some());
    assert!(result2.is_none());
    
    // VULNÉRABILITÉ: Timing différent selon la validité
    println!("Valid padding timing: {:?}", duration_valid);
    println!("Invalid padding timing: {:?}", duration_invalid);
    
    // L'implémentation vulnérable a des timings différents
    // (ce test peut être flaky selon la charge système)
}

/// Test de régression: KDF faible
#[test]
fn test_weak_kdf_vulnerability() {
    let password = b"password123";
    
    // VULNÉRABILITÉ: Même password = même hash (pas de sel)
    let hash1 = naive_kdf(password);
    let hash2 = naive_kdf(password);
    
    assert_eq!(hash1, hash2);
    
    // VULNÉRABILITÉ: Hashes prévisibles pour mots de passe communs
    let common_passwords = [
        b"password".as_slice(),
        b"123456".as_slice(),
        b"admin".as_slice(),
    ];
    
    let mut hashes = Vec::new();
    for pwd in &common_passwords {
        hashes.push(naive_kdf(pwd));
    }
    
    // Ces hashes peuvent être précalculés (rainbow table)
    assert_eq!(hashes.len(), 3);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]
    
    /// Property test: MAC timing attack
    #[test]
    fn prop_mac_timing_attack(
        mac1: Vec<u8>,
        mac2: Vec<u8>
    ) {
        prop_assume!(mac1.len() == mac2.len());
        prop_assume!(mac1.len() > 0);
        prop_assume!(mac1 != mac2);
        
        // Mesurer timing pour différentes positions d'erreur
        let mut mac_wrong_first = mac1.clone();
        mac_wrong_first[0] = !mac_wrong_first[0];
        
        let start = Instant::now();
        let _ = VulnerableCrypto::verify_mac_vulnerable(&mac1, &mac_wrong_first);
        let duration_first = start.elapsed();
        
        if mac1.len() > 1 {
            let mut mac_wrong_last = mac1.clone();
            mac_wrong_last[mac1.len() - 1] = !mac_wrong_last[mac1.len() - 1];
            
            let start = Instant::now();
            let _ = VulnerableCrypto::verify_mac_vulnerable(&mac1, &mac_wrong_last);
            let duration_last = start.elapsed();
            
            // VULNÉRABILITÉ: Timing leak détectable
            if duration_first.as_nanos() > 0 && duration_last.as_nanos() > 0 {
                let ratio = duration_last.as_nanos() as f64 / duration_first.as_nanos() as f64;
                // Avec l'implémentation vulnérable, ratio > 1
                prop_assert!(ratio > 1.0);
            }
        }
    }
    
    /// Property test: Nonce statique catastrophique
    #[test]
    fn prop_static_nonce_catastrophe(
        plaintext1: Vec<u8>,
        plaintext2: Vec<u8>
    ) {
        prop_assume!(plaintext1.len() > 0 && plaintext1.len() < 1000);
        prop_assume!(plaintext2.len() > 0 && plaintext2.len() < 1000);
        prop_assume!(plaintext1 != plaintext2);
        
        let key = [0x42; 32];
        
        let ciphertext1 = VulnerableCrypto::encrypt_aes_gcm_static_nonce(&key, &plaintext1);
        let ciphertext2 = VulnerableCrypto::encrypt_aes_gcm_static_nonce(&key, &plaintext2);
        
        // VULNÉRABILITÉ: Nonce statique = ciphertexts liés
        // (En AES-GCM, c'est catastrophique - révèle la clé)
        prop_assert_ne!(ciphertext1, ciphertext2);
        
        // Test additionnel: même plaintext = même ciphertext (catastrophique)
        let ciphertext1_bis = VulnerableCrypto::encrypt_aes_gcm_static_nonce(&key, &plaintext1);
        prop_assert_eq!(ciphertext1, ciphertext1_bis);
    }
}

/// Test d'intégration: Exploitation complète d'un timing attack
#[test]
fn test_complete_timing_attack_exploitation() {
    let secret_token = b"super_secret_auth_token_32_bytes";
    
    // Simulation d'attaque: deviner le token byte par byte
    let mut guessed_token = vec![0u8; secret_token.len()];
    
    for pos in 0..secret_token.len() {
        let mut best_byte = 0u8;
        let mut max_duration = Duration::from_nanos(0);
        
        // Tester chaque byte possible
        for candidate in 0..=255u8 {
            guessed_token[pos] = candidate;
            
            let start = Instant::now();
            let _ = insecure_compare(secret_token, &guessed_token);
            let duration = start.elapsed();
            
            // Le byte correct prend plus de temps (va plus loin dans la boucle)
            if duration > max_duration {
                max_duration = duration;
                best_byte = candidate;
            }
        }
        
        guessed_token[pos] = best_byte;
    }
    
    // VULNÉRABILITÉ: Token complètement deviné via timing
    assert_eq!(&guessed_token, secret_token);
}

/// Test de régression: Padding oracle différentiation
#[test]
fn test_padding_oracle_error_differentiation() {
    let key = b"test_key_16_byte";
    
    // Différents types d'erreurs de padding
    let invalid_length = b"short";
    let invalid_padding_value = b"data_with_bad_pad\x11"; // 17 > 16
    let invalid_padding_bytes = b"data_with_bad_pad\x04\x04\x04\x03";
    
    let result1 = VulnerableCrypto::decrypt_pkcs7_vulnerable(key, invalid_length);
    let result2 = VulnerableCrypto::decrypt_pkcs7_vulnerable(key, invalid_padding_value);
    let result3 = VulnerableCrypto::decrypt_pkcs7_vulnerable(key, invalid_padding_bytes);
    
    // VULNÉRABILITÉ: Erreurs différentiables = oracle
    match (result1, result2, result3) {
        (
            Err(DecryptionError::InvalidLength),
            Err(DecryptionError::InvalidPadding),
            Err(DecryptionError::InvalidPaddingByte(_))
        ) => {
            // L'attaquant peut distinguer les types d'erreurs
            assert!(true);
        }
        _ => panic!("Expected differentiated errors"),
    }
}

#[cfg(test)]
mod benchmarks {
    use super::*;
    use std::hint::black_box;
    
    /// Benchmark pour détecter les timing leaks
    #[test]
    fn benchmark_timing_attacks() {
        let iterations = 10000;
        let secret = b"secret_value_for_timing_analysis";
        
        // Test avec premier byte faux
        let mut wrong_first = *secret;
        wrong_first[0] = !wrong_first[0];
        
        let start = Instant::now();
        for _ in 0..iterations {
            black_box(insecure_compare(secret, &wrong_first));
        }
        let duration_first = start.elapsed();
        
        // Test avec dernier byte faux
        let mut wrong_last = *secret;
        wrong_last[secret.len() - 1] = !wrong_last[secret.len() - 1];
        
        let start = Instant::now();
        for _ in 0..iterations {
            black_box(insecure_compare(secret, &wrong_last));
        }
        let duration_last = start.elapsed();
        
        println!("Timing analysis over {} iterations:", iterations);
        println!("Wrong first byte: {:?}", duration_first);
        println!("Wrong last byte: {:?}", duration_last);
        println!("Ratio: {:.2}", duration_last.as_nanos() as f64 / duration_first.as_nanos() as f64);
        
        // VULNÉRABILITÉ détectable: ratio significativement > 1
        assert!(duration_last > duration_first);
    }
}
