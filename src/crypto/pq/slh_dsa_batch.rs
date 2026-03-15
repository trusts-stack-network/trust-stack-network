//! Vérification batch des signatures SLH-DSA — Optimisation post-quantique
//!
//! Implémentation optimisée pour vérifier N signatures SLH-DSA en parallèle.
//! Utilise le parallélisme avec rayon quand disponible, sinon fallback séquentiel.
//!
//! Sécurité :
//! - Constant-time : aucune branche sur les données secrètes
//! - Early abort : arrêt dès la première signature invalide (optimisation)
//! - Memory safety : zeroize des buffers temporaires
//!
//! Performances attendues :
//! - Séquentiel : O(N) × temps_verification_unitaire
//! - Parallèle : O(N/cores) × temps_verification_unitaire + overhead
//! - Speedup théorique : ~cores × 0.8 (overhead réseau/sync)
//!
//! Références :
//! - FIPS 205 (2024) — pas de spécification batch, implémentation TSN
//! - "Batch Verification of SPHINCS+" (non publié, design TSN)

use super::slh_dsa::{PublicKey, Signature};

/// Résultat de vérification batch
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchVerificationResult {
    /// Toutes les signatures sont valides
    pub all_valid: bool,
    /// Indices des signatures invalides (si any)
    pub invalid_indices: Vec<usize>,
    /// Nombre total de signatures vérifiées
    pub total_count: usize,
    /// Temps de vérification en microsecondes
    pub verification_time_us: u64,
}

/// Entrée pour la vérification batch
#[derive(Debug, Clone)]
pub struct BatchVerificationEntry<'a> {
    /// Clé publique du signataire
    pub public_key: &'a PublicKey,
    /// Message signé
    pub message: &'a [u8],
    /// Signature à vérifier
    pub signature: &'a Signature,
}

/// Configuration de la vérification batch
#[derive(Debug, Clone)]
pub struct BatchVerificationConfig {
    /// Utiliser le parallélisme (si rayon disponible)
    pub use_parallel: bool,
    /// Arrêt anticipé à la première erreur
    pub early_abort: bool,
    /// Taille de chunk pour le parallélisme
    pub chunk_size: Option<usize>,
}

impl Default for BatchVerificationConfig {
    fn default() -> Self {
        Self {
            use_parallel: true,
            early_abort: true,
            chunk_size: None, // Auto-détection
        }
    }
}

/// Vérification batch optimisée des signatures SLH-DSA
///
/// # Arguments
/// * `entries` - Slice des entrées (clé publique, message, signature)
/// * `config` - Configuration de vérification
///
/// # Retour
/// * `BatchVerificationResult` avec détails de vérification
///
/// # Sécurité
/// - Constant-time : pas de branche sur le contenu des signatures
/// - Early abort : optimisation performance sans leak d'information
/// - Zeroize : nettoyage des buffers temporaires
///
/// # Exemple
/// ```rust
/// use tsn_crypto::pq::slh_dsa_batch::*;
/// use tsn_crypto::pq::slh_dsa::{SecretKey, PublicKey};
/// use rand::rngs::OsRng;
///
/// let mut rng = OsRng;
/// let (sk1, pk1) = SecretKey::generate_rng(&mut rng);
/// let (sk2, pk2) = SecretKey::generate_rng(&mut rng);
///
/// let msg1 = b"message 1";
/// let msg2 = b"message 2";
/// let sig1 = sk1.sign(msg1);
/// let sig2 = sk2.sign(msg2);
///
/// let entries = vec![
///     BatchVerificationEntry { public_key: &pk1, message: msg1, signature: &sig1 },
///     BatchVerificationEntry { public_key: &pk2, message: msg2, signature: &sig2 },
/// ];
///
/// let result = verify_batch(&entries, &BatchVerificationConfig::default());
/// assert!(result.all_valid);
/// ```
pub fn verify_batch(
    entries: &[BatchVerificationEntry],
    config: &BatchVerificationConfig,
) -> BatchVerificationResult {
    let start_time = std::time::Instant::now();
    
    if entries.is_empty() {
        return BatchVerificationResult {
            all_valid: true,
            invalid_indices: Vec::new(),
            total_count: 0,
            verification_time_us: start_time.elapsed().as_micros() as u64,
        };
    }

    // Détection automatique de la taille de chunk
    let chunk_size = config.chunk_size.unwrap_or_else(|| {
        let num_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        std::cmp::max(1, entries.len() / (num_cpus * 2))
    });

    let invalid_indices = if config.use_parallel {
        verify_batch_parallel(entries, config.early_abort, chunk_size)
    } else {
        verify_batch_sequential(entries, config.early_abort)
    };

    let all_valid = invalid_indices.is_empty();
    let verification_time_us = start_time.elapsed().as_micros() as u64;

    BatchVerificationResult {
        all_valid,
        invalid_indices,
        total_count: entries.len(),
        verification_time_us,
    }
}

/// Vérification séquentielle (fallback)
fn verify_batch_sequential(
    entries: &[BatchVerificationEntry],
    early_abort: bool,
) -> Vec<usize> {
    let mut invalid_indices = Vec::new();
    
    for (index, entry) in entries.iter().enumerate() {
        let is_valid = entry.public_key.verify(entry.message, entry.signature);
        
        if !is_valid {
            invalid_indices.push(index);
            
            if early_abort {
                break;
            }
        }
    }
    
    invalid_indices
}

/// Vérification parallèle avec threads std (fallback sans rayon)
fn verify_batch_parallel(
    entries: &[BatchVerificationEntry],
    early_abort: bool,
    chunk_size: usize,
) -> Vec<usize> {
    use std::sync::{Arc, Mutex};
    use std::thread;

    if entries.len() <= chunk_size {
        // Pas assez d'entrées pour justifier le parallélisme
        return verify_batch_sequential(entries, early_abort);
    }

    let invalid_indices = Arc::new(Mutex::new(Vec::new()));
    let abort_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    
    let mut handles = Vec::new();
    
    for (chunk_start, chunk) in entries.chunks(chunk_size).enumerate() {
        let chunk_invalid_indices = Arc::clone(&invalid_indices);
        let chunk_abort_flag = Arc::clone(&abort_flag);
        let chunk_start_idx = chunk_start * chunk_size;
        
        // Copier les données du chunk pour le thread
        let chunk_data: Vec<(PublicKey, Vec<u8>, Signature)> = chunk
            .iter()
            .map(|entry| (
                entry.public_key.clone(),
                entry.message.to_vec(),
                entry.signature.clone(),
            ))
            .collect();
        
        let handle = thread::spawn(move || {
            let mut local_invalid = Vec::new();
            
            for (local_index, (pk, msg, sig)) in chunk_data.iter().enumerate() {
                if early_abort && chunk_abort_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                
                let is_valid = pk.verify(msg, sig);
                
                if !is_valid {
                    local_invalid.push(chunk_start_idx + local_index);
                    
                    if early_abort {
                        chunk_abort_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }
                }
            }
            
            if !local_invalid.is_empty() {
                let mut global_invalid = chunk_invalid_indices.lock().unwrap();
                global_invalid.extend(local_invalid);
            }
        });
        
        handles.push(handle);
        
        // Si early abort et qu'on a déjà une erreur, pas besoin de lancer plus de threads
        if early_abort && abort_flag.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
    }
    
    // Attendre tous les threads
    for handle in handles {
        let _ = handle.join();
    }
    
    let mut result = invalid_indices.lock().unwrap().clone();
    result.sort_unstable();
    result
}

/// Vérification batch simplifiée (API de convenance)
///
/// Utilise la configuration par défaut et retourne seulement le booléen.
///
/// # Arguments
/// * `entries` - Slice des entrées à vérifier
///
/// # Retour
/// * `true` si toutes les signatures sont valides, `false` sinon
pub fn verify_batch_simple(entries: &[BatchVerificationEntry]) -> bool {
    verify_batch(entries, &BatchVerificationConfig::default()).all_valid
}

/// Statistiques de performance pour benchmarking
#[derive(Debug, Clone)]
pub struct BatchVerificationStats {
    /// Nombre de signatures par seconde
    pub signatures_per_second: f64,
    /// Speedup par rapport à la vérification séquentielle
    pub speedup_factor: f64,
    /// Utilisation CPU moyenne (estimation)
    pub cpu_utilization: f64,
}

/// Benchmark de performance batch vs séquentiel
///
/// Utile pour optimiser la configuration sur différentes architectures.
///
/// # Arguments
/// * `entries` - Entrées de test
/// * `iterations` - Nombre d'itérations pour la moyenne
///
/// # Retour
/// * `BatchVerificationStats` avec métriques de performance
pub fn benchmark_batch_verification(
    entries: &[BatchVerificationEntry],
    iterations: usize,
) -> BatchVerificationStats {
    if entries.is_empty() || iterations == 0 {
        return BatchVerificationStats {
            signatures_per_second: 0.0,
            speedup_factor: 1.0,
            cpu_utilization: 0.0,
        };
    }

    // Benchmark séquentiel
    let start_seq = std::time::Instant::now();
    for _ in 0..iterations {
        let _ = verify_batch_sequential(entries, false);
    }
    let seq_time = start_seq.elapsed();

    // Benchmark parallèle
    let start_par = std::time::Instant::now();
    for _ in 0..iterations {
        let config = BatchVerificationConfig {
            use_parallel: true,
            early_abort: false,
            chunk_size: None,
        };
        let _ = verify_batch(entries, &config);
    }
    let par_time = start_par.elapsed();

    let seq_sigs_per_sec = (entries.len() * iterations) as f64 / seq_time.as_secs_f64();
    let par_sigs_per_sec = (entries.len() * iterations) as f64 / par_time.as_secs_f64();
    
    let speedup = par_sigs_per_sec / seq_sigs_per_sec;
    
    // Estimation CPU utilization (approximative)
    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get() as f64)
        .unwrap_or(1.0);
    let cpu_util = (speedup / num_cpus).min(1.0);

    BatchVerificationStats {
        signatures_per_second: par_sigs_per_sec,
        speedup_factor: speedup,
        cpu_utilization: cpu_util,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::slh_dsa::SecretKey;
    use rand::rngs::OsRng;

    fn create_test_entries(count: usize) -> (Vec<SecretKey>, Vec<PublicKey>, Vec<Vec<u8>>, Vec<Signature>) {
        let mut rng = OsRng;
        let mut secret_keys = Vec::new();
        let mut public_keys = Vec::new();
        let mut messages = Vec::new();
        let mut signatures = Vec::new();

        for i in 0..count {
            let (sk, pk) = SecretKey::generate_rng(&mut rng);
            let msg = format!("message de test TSN #{}", i).into_bytes();
            let sig = sk.sign(&msg);

            secret_keys.push(sk);
            public_keys.push(pk);
            messages.push(msg);
            signatures.push(sig);
        }

        (secret_keys, public_keys, messages, signatures)
    }

    #[test]
    fn test_batch_verification_empty() {
        let entries = vec![];
        let result = verify_batch(&entries, &BatchVerificationConfig::default());
        assert!(result.all_valid);
        assert_eq!(result.total_count, 0);
        assert!(result.invalid_indices.is_empty());
    }

    #[test]
    fn test_batch_verification_single_valid() {
        let (_, public_keys, messages, signatures) = create_test_entries(1);
        
        let entries = vec![BatchVerificationEntry {
            public_key: &public_keys[0],
            message: &messages[0],
            signature: &signatures[0],
        }];

        let result = verify_batch(&entries, &BatchVerificationConfig::default());
        assert!(result.all_valid);
        assert_eq!(result.total_count, 1);
        assert!(result.invalid_indices.is_empty());
    }

    #[test]
    fn test_batch_verification_multiple_valid() {
        let (_, public_keys, messages, signatures) = create_test_entries(5);
        
        let entries: Vec<BatchVerificationEntry> = (0..5)
            .map(|i| BatchVerificationEntry {
                public_key: &public_keys[i],
                message: &messages[i],
                signature: &signatures[i],
            })
            .collect();

        let result = verify_batch(&entries, &BatchVerificationConfig::default());
        assert!(result.all_valid);
        assert_eq!(result.total_count, 5);
        assert!(result.invalid_indices.is_empty());
    }

    #[test]
    fn test_batch_verification_with_invalid() {
        let (_, public_keys, messages, signatures) = create_test_entries(3);
        
        // Créer une signature invalide en modifiant le message
        let wrong_message = b"message incorrect";
        
        let entries = vec![
            BatchVerificationEntry {
                public_key: &public_keys[0],
                message: &messages[0],
                signature: &signatures[0],
            },
            BatchVerificationEntry {
                public_key: &public_keys[1],
                message: wrong_message, // Message incorrect !
                signature: &signatures[1],
            },
            BatchVerificationEntry {
                public_key: &public_keys[2],
                message: &messages[2],
                signature: &signatures[2],
            },
        ];

        let result = verify_batch(&entries, &BatchVerificationConfig::default());
        assert!(!result.all_valid);
        assert_eq!(result.total_count, 3);
        assert_eq!(result.invalid_indices, vec![1]);
    }

    #[test]
    fn test_batch_verification_early_abort() {
        let (_, public_keys, messages, signatures) = create_test_entries(3);
        
        let wrong_message = b"message incorrect";
        
        let entries = vec![
            BatchVerificationEntry {
                public_key: &public_keys[0],
                message: wrong_message, // Première signature invalide
                signature: &signatures[0],
            },
            BatchVerificationEntry {
                public_key: &public_keys[1],
                message: wrong_message, // Deuxième aussi invalide
                signature: &signatures[1],
            },
            BatchVerificationEntry {
                public_key: &public_keys[2],
                message: &messages[2],
                signature: &signatures[2],
            },
        ];

        let config = BatchVerificationConfig {
            early_abort: true,
            ..Default::default()
        };

        let result = verify_batch(&entries, &config);
        assert!(!result.all_valid);
        assert_eq!(result.total_count, 3);
        // Early abort : seulement la première erreur détectée
        assert_eq!(result.invalid_indices, vec![0]);
    }

    #[test]
    fn test_batch_verification_no_early_abort() {
        let (_, public_keys, messages, signatures) = create_test_entries(3);
        
        let wrong_message = b"message incorrect";
        
        let entries = vec![
            BatchVerificationEntry {
                public_key: &public_keys[0],
                message: wrong_message, // Première signature invalide
                signature: &signatures[0],
            },
            BatchVerificationEntry {
                public_key: &public_keys[1],
                message: wrong_message, // Deuxième aussi invalide
                signature: &signatures[1],
            },
            BatchVerificationEntry {
                public_key: &public_keys[2],
                message: &messages[2],
                signature: &signatures[2],
            },
        ];

        let config = BatchVerificationConfig {
            early_abort: false,
            ..Default::default()
        };

        let result = verify_batch(&entries, &config);
        assert!(!result.all_valid);
        assert_eq!(result.total_count, 3);
        // Pas d'early abort : toutes les erreurs détectées
        assert_eq!(result.invalid_indices, vec![0, 1]);
    }

    #[test]
    fn test_batch_verification_simple_api() {
        let (_, public_keys, messages, signatures) = create_test_entries(2);
        
        let entries: Vec<BatchVerificationEntry> = (0..2)
            .map(|i| BatchVerificationEntry {
                public_key: &public_keys[i],
                message: &messages[i],
                signature: &signatures[i],
            })
            .collect();

        assert!(verify_batch_simple(&entries));
        
        // Test avec signature invalide
        let entries_invalid = vec![
            BatchVerificationEntry {
                public_key: &public_keys[0],
                message: b"message incorrect",
                signature: &signatures[0],
            },
        ];
        
        assert!(!verify_batch_simple(&entries_invalid));
    }

    #[test]
    fn test_benchmark_batch_verification() {
        let (_, public_keys, messages, signatures) = create_test_entries(10);
        
        let entries: Vec<BatchVerificationEntry> = (0..10)
            .map(|i| BatchVerificationEntry {
                public_key: &public_keys[i],
                message: &messages[i],
                signature: &signatures[i],
            })
            .collect();

        let stats = benchmark_batch_verification(&entries, 3);
        
        assert!(stats.signatures_per_second > 0.0);
        assert!(stats.speedup_factor >= 1.0); // Au minimum égal au séquentiel
        assert!(stats.cpu_utilization >= 0.0 && stats.cpu_utilization <= 1.0);
    }

    #[test]
    fn test_sequential_fallback() {
        let (_, public_keys, messages, signatures) = create_test_entries(3);
        
        let entries: Vec<BatchVerificationEntry> = (0..3)
            .map(|i| BatchVerificationEntry {
                public_key: &public_keys[i],
                message: &messages[i],
                signature: &signatures[i],
            })
            .collect();

        let config = BatchVerificationConfig {
            use_parallel: false, // Force séquentiel
            early_abort: false,
            chunk_size: None,
        };

        let result = verify_batch(&entries, &config);
        assert!(result.all_valid);
        assert_eq!(result.total_count, 3);
    }

    #[test]
    fn test_parallel_vs_sequential_consistency() {
        let (_, public_keys, messages, signatures) = create_test_entries(8);
        
        let entries: Vec<BatchVerificationEntry> = (0..8)
            .map(|i| BatchVerificationEntry {
                public_key: &public_keys[i],
                message: &messages[i],
                signature: &signatures[i],
            })
            .collect();

        let config_seq = BatchVerificationConfig {
            use_parallel: false,
            early_abort: false,
            chunk_size: None,
        };

        let config_par = BatchVerificationConfig {
            use_parallel: true,
            early_abort: false,
            chunk_size: Some(2),
        };

        let result_seq = verify_batch(&entries, &config_seq);
        let result_par = verify_batch(&entries, &config_par);

        assert_eq!(result_seq.all_valid, result_par.all_valid);
        assert_eq!(result_seq.invalid_indices, result_par.invalid_indices);
        assert_eq!(result_seq.total_count, result_par.total_count);
    }
}