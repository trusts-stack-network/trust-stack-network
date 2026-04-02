//! Audit final des panics - Trust Stack Network
//!
//! Ce fichier documente l'audit complet des unwrap(), expect() et panic!()
//! dans le codebase TSN et fournit des tests de non-régression.
//!
//! ## Historique de l'audit
//!
//! Date: 2024
//! Auditeur: Marcus.R (Security & QA Engineer)
//!
//! ### Fichiers audités
//!
//! - `src/crypto/keys.rs` - ✅ Aucun unwrap/expect non justifié
//! - `src/crypto/poseidon.rs` - ✅ Aucun unwrap/expect non justifié
//! - `src/consensus/pow.rs` - ✅ Aucun unwrap/expect non justifié
//! - `src/network/sync.rs` - ✅ Gestion d'erreurs appropriée
//!
//! ### Résultat
//!
//! ✅ AUDIT PASSÉ - Aucun panic non justifié détecté dans le code critique.

use std::fs;
use std::path::Path;

/// Liste des patterns dangereux à rechercher
const DANGEROUS_PATTERNS: &[&str] = &[
    ".unwrap()",
    ".expect(\"",
    "panic!(",
];

/// Liste des fichiers critiques à surveiller
const CRITICAL_FILES: &[&str] = &[
    "src/crypto/keys.rs",
    "src/crypto/poseidon.rs",
    "src/crypto/signature.rs",
    "src/crypto/proof.rs",
    "src/consensus/pow.rs",
    "src/consensus/difficulty.rs",
    "src/core/block.rs",
    "src/core/transaction.rs",
    "src/network/sync.rs",
];

/// Vérifie qu'un fichier ne contient pas de patterns dangereux
fn check_file_for_panics(path: &str) -> Result<(), String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Impossible de lire {}: {}", path, e))?;
    
    for pattern in DANGEROUS_PATTERNS {
        if content.contains(pattern) {
            // Vérifier si c'est dans un commentaire ou un test
            for (line_num, line) in content.lines().enumerate() {
                if line.contains(pattern) {
                    let trimmed = line.trim();
                    // Ignorer les commentaires
                    if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("/*") {
                        continue;
                    }
                    // Ignorer les tests (contiennent souvent des expects légitimes)
                    if path.contains("tests/") || path.contains("benches/") {
                        continue;
                    }
                    return Err(format!(
                        "Pattern dangereux '{}' trouvé dans {}:{} - {}",
                        pattern, path, line_num + 1, line.trim()
                    ));
                }
            }
        }
    }
    
    Ok(())
}

#[test]
fn audit_no_unwrap_in_crypto_keys() {
    // Vérifie que keys.rs n'a pas de unwrap/expect non justifié
    let result = check_file_for_panics("src/crypto/keys.rs");
    assert!(
        result.is_ok(),
        "PANIC DÉTECTÉ dans keys.rs: {:?}",
        result.err()
    );
}

#[test]
fn audit_no_unwrap_in_crypto_poseidon() {
    // Vérifie que poseidon.rs n'a pas de unwrap/expect non justifié
    let result = check_file_for_panics("src/crypto/poseidon.rs");
    assert!(
        result.is_ok(),
        "PANIC DÉTECTÉ dans poseidon.rs: {:?}",
        result.err()
    );
}

#[test]
fn audit_no_unwrap_in_consensus_pow() {
    // Vérifie que pow.rs n'a pas de unwrap/expect non justifié
    let result = check_file_for_panics("src/consensus/pow.rs");
    assert!(
        result.is_ok(),
        "PANIC DÉTECTÉ dans pow.rs: {:?}",
        result.err()
    );
}

#[test]
fn audit_no_unwrap_in_network_sync() {
    // Vérifie que sync.rs n'a pas de unwrap/expect non justifié
    let result = check_file_for_panics("src/network/sync.rs");
    assert!(
        result.is_ok(),
        "PANIC DÉTECTÉ dans sync.rs: {:?}",
        result.err()
    );
}

#[test]
fn audit_all_critical_files() {
    // Audit complet de tous les fichiers critiques
    let mut failures = Vec::new();
    
    for file in CRITICAL_FILES {
        if Path::new(file).exists() {
            if let Err(e) = check_file_for_panics(file) {
                failures.push(e);
            }
        }
    }
    
    assert!(
        failures.is_empty(),
        "Panics détectés dans les fichiers critiques:\n{}",
        failures.join("\n")
    );
}

/// Test que les fonctions crypto retournent des Result au lieu de paniquer
#[test]
fn test_crypto_error_handling() {
    use tsn::crypto::keys::{MlKeyPair, MlPublicKey, MlSignature};
    
    // Test: keygen_from_seed avec seed invalide
    let invalid_seed = vec![0u8; 10]; // Trop court
    let result = MlKeyPair::keygen_from_seed(&invalid_seed);
    // Doit retourner une erreur, pas paniquer
    assert!(result.is_err(), "keygen_from_seed doit retourner Err avec seed invalide");
    
    // Test: signature avec message vide
    let seed = vec![0u8; 32];
    let keypair = MlKeyPair::keygen_from_seed(&seed).expect("keygen valide");
    let empty_msg: &[u8] = b"";
    let sig_result = keypair.sign(empty_msg);
    // Doit fonctionner même avec message vide
    assert!(sig_result.is_ok(), "sign doit fonctionner avec message vide");
}

/// Test que les fonctions de hash retournent des Result
#[test]
fn test_poseidon_error_handling() {
    use tsn::crypto::poseidon::poseidon_hash;
    
    // Test: hash avec entrées vides
    let empty: Vec<[u8; 32]> = vec![];
    let result = poseidon_hash(&empty);
    // Doit retourner une erreur ou un résultat valide, pas paniquer
    match result {
        Ok(_) => {}, // Acceptable
        Err(_) => {}, // Aussi acceptable - l'important c'est pas de panic
    }
    
    // Test: hash avec entrées valides
    let inputs = vec![[1u8; 32], [2u8; 32]];
    let result = poseidon_hash(&inputs);
    assert!(result.is_ok(), "poseidon_hash doit fonctionner avec entrées valides");
}

/// Test de résistance aux entrées malformées
#[test]
fn test_malformed_input_resistance() {
    use tsn::crypto::keys::{MlPublicKey, MlSignature};
    
    // Test: deserialization de clé publique malformée
    let malformed_pk = vec![0xffu8; 100]; // Données aléatoires
    let result = MlPublicKey::from_bytes(&malformed_pk);
    assert!(result.is_err(), "from_bytes doit retourner Err avec données malformées");
    
    // Test: deserialization de signature malformée
    let malformed_sig = vec![0xffu8; 100];
    let result = MlSignature::from_bytes(&malformed_sig);
    assert!(result.is_err(), "signature from_bytes doit retourner Err avec données malformées");
}

/// Documentation des décisions d'audit
#[test]
fn audit_documentation() {
    // Ce test sert de documentation vivante des décisions d'audit
    
    // Les expects suivants ont été identifiés et justifiés:
    //
    // 1. benches/throughput_bench.rs - expects légitimes dans les benchmarks
    //    Justification: Les benchmarks utilisent des données de test contrôlées
    //
    // 2. plonky2-wasm/src/lib.rs - expects dans le wrapper WASM
    //    Justification: Code externe, pas dans le code TSN critique
    //
    // Tous les expects dans src/ ont été remplacés par une gestion d'erreurs
    // appropriée avec Result<T, E>.
    
    assert!(true, "Documentation d'audit");
}
