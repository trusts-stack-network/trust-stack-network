//! Fuzz targets pour les modules crypto vulnérables
//! 
//! Ces fuzzers testent la robustesse des fonctions crypto contre
//! des entrées malformées et adversariales.

#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn::crypto::vulnerable::*;
use tsn::crypto::secure_impl::*;

/// Structure pour les données de fuzzing
#[derive(Debug)]
struct FuzzInput {
    data1: Vec<u8>,
    data2: Vec<u8>,
    key: [u8; 32],
    nonce: [u8; 12],
    password: Vec<u8>,
    salt: Vec<u8>,
}

impl<'a> arbitrary::Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let data1_len = u.int_in_range(0..=1024)?;
        let data2_len = u.int_in_range(0..=1024)?;
        let password_len = u.int_in_range(0..=256)?;
        let salt_len = u.int_in_range(0..=64)?;
        
        Ok(FuzzInput {
            data1: (0..data1_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            data2: (0..data2_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            key: u.arbitrary()?,
            nonce: u.arbitrary()?,
            password: (0..password_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            salt: (0..salt_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
        })
    }
}

fuzz_target!(|input: FuzzInput| {
    // Test des fonctions de comparaison
    fuzz_compare_functions(&input.data1, &input.data2);
    
    // Test du mode CTR vulnérable
    fuzz_ctr_mode(&input.key[..16].try_into().unwrap(), &input.data1);
    
    // Test du RNG prévisible
    fuzz_predictable_rng(&input.data1);
    
    // Test du padding PKCS#7
    fuzz_pkcs7_padding(&input.data1);
    
    // Test des KDF
    if !input.password.is_empty() {
        fuzz_kdf_functions(&input.password, &input.salt);
    }
    
    // Test de l'AEAD sécurisé
    fuzz_secure_aead(&input.key, &input.nonce, &input.data1);
});

/// Fuzz les fonctions de comparaison
fn fuzz_compare_functions(data1: &[u8], data2: &[u8]) {
    // Test que les deux fonctions donnent le même résultat logique
    let insecure_result = insecure_compare(data1, data2);
    let secure_result = secure_compare(data1, data2);
    
    // Invariant: Les deux fonctions doivent donner le même résultat
    assert_eq!(insecure_result, secure_result, 
        "insecure_compare et secure_compare doivent donner le même résultat logique");
    
    // Test de réflexivité
    assert!(insecure_compare(data1, data1), "Comparaison doit être réflexive");
    assert!(secure_compare(data1, data1), "Comparaison sécurisée doit être réflexive");
    
    // Test de symétrie
    assert_eq!(insecure_compare(data1, data2), insecure_compare(data2, data1),
        "Comparaison doit être symétrique");
    assert_eq!(secure_compare(data1, data2), secure_compare(data2, data1),
        "Comparaison sécurisée doit être symétrique");
}

/// Fuzz le mode CTR vulnérable
fn fuzz_ctr_mode(key: &[u8; 16], plaintext: &[u8]) {
    if plaintext.is_empty() {
        return;
    }
    
    let mut ctr = InsecureCtrMode::new(*key);
    
    // Test que l'encryption ne panic pas
    let ciphertext = ctr.encrypt(plaintext);
    
    // Invariants de base
    assert!(!ciphertext.is_empty(), "Ciphertext ne doit pas être vide");
    
    // Test avec des plaintexts de différentes tailles
    let short_plaintext = &plaintext[..std::cmp::min(1, plaintext.len())];
    let short_ciphertext = ctr.encrypt(short_plaintext);
    assert!(!short_ciphertext.is_empty(), "Ciphertext court ne doit pas être vide");
}

/// Fuzz le RNG prévisible
fn fuzz_predictable_rng(seed_data: &[u8]) {
    if seed_data.is_empty() {
        return;
    }
    
    // Utilise les premiers bytes comme seed
    let seed = u64::from_le_bytes(
        seed_data.iter()
            .cycle()
            .take(8)
            .cloned()
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    );
    
    let mut rng = PredictableRng::new(seed);
    
    // Génère une séquence et vérifie qu'elle ne panic pas
    let mut sequence = Vec::new();
    for _ in 0..100 {
        sequence.push(rng.next());
    }
    
    // Test de déterminisme
    let mut rng2 = PredictableRng::new(seed);
    for expected in sequence {
        assert_eq!(rng2.next(), expected, "RNG doit être déterministe");
    }
}

/// Fuzz le padding PKCS#7
fn fuzz_pkcs7_padding(data: &[u8]) {
    // Test que la fonction ne panic pas sur des entrées arbitraires
    let result = remove_pkcs7_padding(data);
    
    // Si le résultat est Some, vérifier les invariants
    if let Some(unpadded) = result {
        assert!(unpadded.len() <= data.len(), 
            "Données dépadées ne peuvent pas être plus longues que l'original");
        
        // Vérifier que les données dépadées sont un préfixe de l'original
        assert_eq!(&data[..unpadded.len()], unpadded,
            "Données dépadées doivent être un préfixe de l'original");
    }
    
    // Test avec des données modifiées
    if !data.is_empty() {
        let mut modified = data.to_vec();
        modified[0] = modified[0].wrapping_add(1);
        let _ = remove_pkcs7_padding(&modified);
    }
}

/// Fuzz les fonctions KDF
fn fuzz_kdf_functions(password: &[u8], salt: &[u8]) {
    // Test du KDF naïf
    let naive_hash = naive_kdf(password);
    
    // Invariants
    assert_eq!(naive_hash.len(), 32, "Hash naïf doit faire 32 bytes");
    
    // Test de déterminisme
    let naive_hash2 = naive_kdf(password);
    assert_eq!(naive_hash, naive_hash2, "KDF naïf doit être déterministe");
    
    // Test du KDF sécurisé (si on a un salt)
    if !salt.is_empty() {
        let strong_hash = strong_kdf(password, salt);
        assert_eq!(strong_hash.len(), 32, "Hash fort doit faire 32 bytes");
        
        // Test de déterminisme avec salt
        let strong_hash2 = strong_kdf(password, salt);
        assert_eq!(strong_hash, strong_hash2, "KDF fort doit être déterministe avec même salt");
        
        // Test avec salt différent
        if salt.len() > 1 {
            let mut different_salt = salt.to_vec();
            different_salt[0] = different_salt[0].wrapping_add(1);
            let different_hash = strong_kdf(password, &different_salt);
            
            // Note: On ne peut pas garantir que les hashes soient différents
            // car il pourrait y avoir des collisions, mais c'est très improbable
            if strong_hash == different_hash {
                eprintln!("ATTENTION: Collision potentielle détectée dans strong_kdf");
            }
        }
    }
}

/// Fuzz l'AEAD sécurisé
fn fuzz_secure_aead(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) {
    let aead = SecureAead::new(*key);
    
    // Test d'encryption
    let ciphertext = aead.encrypt(nonce, plaintext);
    
    // Invariants
    assert!(ciphertext.len() >= plaintext.len(), 
        "Ciphertext doit être au moins aussi long que plaintext (à cause du tag)");
    
    // Test de roundtrip
    let decrypted = aead.decrypt(nonce, &ciphertext);
    assert_eq!(decrypted, Some(plaintext.to_vec()),
        "Déchiffrement doit récupérer le plaintext original");
    
    // Test avec ciphertext corrompu
    if !ciphertext.is_empty() {
        let mut corrupted = ciphertext.clone();
        corrupted[0] = corrupted[0].wrapping_add(1);
        
        let corrupted_result = aead.decrypt(nonce, &corrupted);
        assert_eq!(corrupted_result, None,
            "Ciphertext corrompu doit être rejeté");
    }
    
    // Test avec nonce différent
    let mut different_nonce = *nonce;
    different_nonce[0] = different_nonce[0].wrapping_add(1);
    
    let wrong_nonce_result = aead.decrypt(&different_nonce, &ciphertext);
    assert_eq!(wrong_nonce_result, None,
        "Mauvais nonce doit faire échouer le déchiffrement");
    
    // Test avec ciphertext tronqué
    if ciphertext.len() > 1 {
        let truncated = &ciphertext[..ciphertext.len() - 1];
        let truncated_result = aead.decrypt(nonce, truncated);
        assert_eq!(truncated_result, None,
            "Ciphertext tronqué doit être rejeté");
    }
}

/// Tests spécifiques pour les edge cases
#[cfg(test)]
mod fuzz_edge_cases {
    use super::*;
    
    #[test]
    fn test_empty_inputs() {
        let input = FuzzInput {
            data1: vec![],
            data2: vec![],
            key: [0; 32],
            nonce: [0; 12],
            password: vec![],
            salt: vec![],
        };
        
        // Test que les fonctions ne paniquent pas avec des entrées vides
        fuzz_compare_functions(&input.data1, &input.data2);
        fuzz_pkcs7_padding(&input.data1);
        fuzz_secure_aead(&input.key, &input.nonce, &input.data1);
    }
    
    #[test]
    fn test_large_inputs() {
        let large_data = vec![0xAA; 10000];
        let input = FuzzInput {
            data1: large_data.clone(),
            data2: large_data,
            key: [0x55; 32],
            nonce: [0x33; 12],
            password: vec![0x77; 1000],
            salt: vec![0x99; 64],
        };
        
        // Test avec des entrées volumineuses
        fuzz_compare_functions(&input.data1, &input.data2);
        fuzz_kdf_functions(&input.password, &input.salt);
        // Note: On évite les gros plaintexts pour l'AEAD pour éviter les timeouts
    }
    
    #[test]
    fn test_adversarial_patterns() {
        // Patterns adversariaux connus
        let patterns = vec![
            vec![0x00; 256],           // Tous zéros
            vec![0xFF; 256],           // Tous uns
            (0..=255).collect(),       // Séquence croissante
            (0..=255).rev().collect(), // Séquence décroissante
            vec![0xAA, 0x55].repeat(128), // Pattern alterné
        ];
        
        for pattern in patterns {
            fuzz_compare_functions(&pattern, &pattern);
            fuzz_pkcs7_padding(&pattern);
            
            if pattern.len() >= 32 {
                let key: [u8; 32] = pattern[..32].try_into().unwrap();
                let nonce: [u8; 12] = pattern[..12].try_into().unwrap();
                fuzz_secure_aead(&key, &nonce, &pattern[32..]);
            }
        }
    }
}