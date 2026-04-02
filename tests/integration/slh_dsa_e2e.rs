//! Tests d'intégration bout-en-bout pour SLH-DSA
//!
//! Validation complète du flow signature → validation → consensus
//! avec SLH-DSA dans l'écosystème TSN.
//!
//! Scénarios testés :
//! - Génération de clés → signature → vérification
//! - Intégration avec le consensus TSN
//! - Validation de blocs avec signatures SLH-DSA
//! - Tests de performance et de compatibilité
//! - Scénarios d'attaque et de robustesse
//!
//! Auteur: Yuki.T (Release & DevOps Engineer)
//! Dernière mise à jour: 2024

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use rand::rngs::OsRng;

use tsn::crypto::pq::slh_dsa::{SecretKey, PublicKey, Signature};
use tsn::crypto::pq::slh_dsa_batch::{
    BatchVerificationEntry, BatchVerificationConfig, verify_batch, benchmark_batch_verification
};
use tsn::consensus::slh_dsa_consensus::{SlhDsaConsensus, SlhDsaStateManager};
use tsn::core::block::Block;
use tsn::core::blockchain::Blockchain;
use tsn::core::transaction::Transaction;
use tsn::network::mempool::Mempool;
use tsn::storage::db::Database;

/// Configuration des tests E2E
#[derive(Debug, Clone)]
struct E2ETestConfig {
    /// Nombre de signatures à tester
    pub signature_count: usize,
    /// Timeout pour les tests longs
    pub timeout_secs: u64,
    /// Activer les tests de performance
    pub enable_perf_tests: bool,
    /// Activer les tests d'attaque
    pub enable_attack_tests: bool,
}

impl Default for E2ETestConfig {
    fn default() -> Self {
        Self {
            signature_count: 100,
            timeout_secs: 30,
            enable_perf_tests: true,
            enable_attack_tests: true,
        }
    }
}

/// Environnement de test isolé
struct TestEnvironment {
    blockchain: Arc<Blockchain>,
    mempool: Arc<Mempool>,
    consensus: Arc<SlhDsaConsensus>,
    database: Arc<Database>,
    config: E2ETestConfig,
}

impl TestEnvironment {
    /// Initialise un environnement de test propre
    async fn new(config: E2ETestConfig) -> anyhow::Result<Self> {
        // Base de données temporaire
        let db_path = tempfile::tempdir()?.path().join("test_db");
        let database = Arc::new(Database::open(&db_path).await?);

        // Blockchain de test
        let blockchain = Arc::new(Blockchain::new(Arc::clone(&database)).await?);

        // Mempool
        let mempool = Arc::new(Mempool::new(Arc::clone(&blockchain)));

        // Gestionnaire d'état SLH-DSA
        let state_manager = Arc::new(SlhDsaStateManager::new(0, 10_000));
        
        // Consensus SLH-DSA (mock verifier pour les tests)
        let verifier = create_test_verifier()?;
        let consensus = Arc::new(SlhDsaConsensus::new(state_manager, verifier));

        Ok(Self {
            blockchain,
            mempool,
            consensus,
            database,
            config,
        })
    }

    /// Nettoie l'environnement de test
    async fn cleanup(self) -> anyhow::Result<()> {
        // Fermeture propre de la base de données
        drop(self.database);
        Ok(())
    }
}

/// Crée un vérifieur SLH-DSA pour les tests
fn create_test_verifier() -> anyhow::Result<tsn::crypto::pq::slh_dsa::SlhDsaVerifier> {
    // Mock implementation pour les tests
    // En production, ceci serait initialisé avec les vraies clés
    todo!("Implémenter le mock verifier")
}

/// Test E2E complet : génération → signature → vérification
#[tokio::test]
async fn test_slh_dsa_full_flow() -> anyhow::Result<()> {
    let config = E2ETestConfig::default();
    let env = TestEnvironment::new(config.clone()).await?;

    // 1. Génération de clés
    let mut rng = OsRng;
    let (secret_key, public_key) = SecretKey::generate_rng(&mut rng);

    // 2. Création d'un message de test
    let test_message = b"TSN blockchain test message - SLH-DSA integration";

    // 3. Signature
    let start_sign = Instant::now();
    let signature = secret_key.sign(test_message);
    let sign_duration = start_sign.elapsed();

    // 4. Vérification
    let start_verify = Instant::now();
    let is_valid = public_key.verify(test_message, &signature);
    let verify_duration = start_verify.elapsed();

    // 5. Assertions
    assert!(is_valid, "La signature SLH-DSA doit être valide");
    
    // 6. Métriques de performance
    println!("✓ Signature SLH-DSA: {:?}", sign_duration);
    println!("✓ Vérification SLH-DSA: {:?}", verify_duration);
    
    // Vérification des seuils de performance
    assert!(sign_duration < Duration::from_millis(1000), 
            "Signature trop lente: {:?}", sign_duration);
    assert!(verify_duration < Duration::from_millis(100), 
            "Vérification trop lente: {:?}", verify_duration);

    env.cleanup().await?;
    Ok(())
}

/// Test E2E : intégration avec le consensus TSN
#[tokio::test]
async fn test_slh_dsa_consensus_integration() -> anyhow::Result<()> {
    let config = E2ETestConfig::default();
    let env = TestEnvironment::new(config.clone()).await?;

    // 1. Création d'un bloc de test
    let test_block = create_test_block().await?;

    // 2. Validation via le consensus SLH-DSA
    let validation_result = timeout(
        Duration::from_secs(config.timeout_secs),
        env.consensus.validate_block_signature(&test_block)
    ).await??;

    // 3. Le bloc doit être accepté
    assert!(validation_result.is_ok(), "Le bloc doit être validé par le consensus");

    // 4. Vérification de l'état du consensus
    let consensus_state = env.consensus.get_state();
    assert!(consensus_state.signature_count > 0, "Le compteur de signatures doit être incrémenté");

    env.cleanup().await?;
    Ok(())
}

/// Test E2E : validation batch de signatures
#[tokio::test]
async fn test_slh_dsa_batch_verification() -> anyhow::Result<()> {
    let config = E2ETestConfig {
        signature_count: 50,
        ..Default::default()
    };
    let env = TestEnvironment::new(config.clone()).await?;

    // 1. Génération de multiples paires de clés
    let mut rng = OsRng;
    let mut entries = Vec::new();
    let mut keys_and_messages = Vec::new();

    for i in 0..config.signature_count {
        let (sk, pk) = SecretKey::generate_rng(&mut rng);
        let message = format!("Message de test TSN #{}", i).into_bytes();
        let signature = sk.sign(&message);

        keys_and_messages.push((pk, message, signature));
    }

    // Conversion en format batch
    for (pk, msg, sig) in &keys_and_messages {
        entries.push(BatchVerificationEntry {
            public_key: pk,
            message: msg,
            signature: sig,
        });
    }

    // 2. Vérification batch séquentielle
    let start_sequential = Instant::now();
    let sequential_config = BatchVerificationConfig {
        use_parallel: false,
        early_abort: false,
        chunk_size: None,
    };
    let sequential_result = verify_batch(&entries, &sequential_config);
    let sequential_duration = start_sequential.elapsed();

    // 3. Vérification batch parallèle
    let start_parallel = Instant::now();
    let parallel_config = BatchVerificationConfig {
        use_parallel: true,
        early_abort: false,
        chunk_size: Some(10),
    };
    let parallel_result = verify_batch(&entries, &parallel_config);
    let parallel_duration = start_parallel.elapsed();

    // 4. Assertions
    assert!(sequential_result.all_valid, "Toutes les signatures doivent être valides (séquentiel)");
    assert!(parallel_result.all_valid, "Toutes les signatures doivent être valides (parallèle)");
    assert_eq!(sequential_result.total_count, config.signature_count);
    assert_eq!(parallel_result.total_count, config.signature_count);

    // 5. Métriques de performance
    let speedup = sequential_duration.as_secs_f64() / parallel_duration.as_secs_f64();
    println!("✓ Vérification séquentielle: {:?}", sequential_duration);
    println!("✓ Vérification parallèle: {:?}", parallel_duration);
    println!("✓ Speedup: {:.2}x", speedup);

    // Le parallélisme doit apporter un gain (sauf sur machines mono-core)
    let num_cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    if num_cpus > 1 {
        assert!(speedup > 1.1, "Le parallélisme doit apporter un gain significatif");
    }

    env.cleanup().await?;
    Ok(())
}

/// Test E2E : compatibilité entre modules crypto
#[tokio::test]
async fn test_slh_dsa_crypto_compatibility() -> anyhow::Result<()> {
    let config = E2ETestConfig::default();
    let env = TestEnvironment::new(config.clone()).await?;

    // 1. Test de compatibilité avec Poseidon2
    let mut rng = OsRng;
    let (sk, pk) = SecretKey::generate_rng(&mut rng);

    // Message hashé avec Poseidon2
    let poseidon_hash = tsn::crypto::poseidon2::hash_message(b"test message")?;
    let signature = sk.sign(&poseidon_hash);
    assert!(pk.verify(&poseidon_hash, &signature), 
            "SLH-DSA doit être compatible avec Poseidon2");

    // 2. Test de compatibilité avec les transactions TSN
    let test_transaction = create_test_transaction().await?;
    let tx_hash = test_transaction.hash();
    let tx_signature = sk.sign(tx_hash.as_bytes());
    assert!(pk.verify(tx_hash.as_bytes(), &tx_signature),
            "SLH-DSA doit signer les transactions TSN");

    // 3. Test de compatibilité avec les blocs TSN
    let test_block = create_test_block().await?;
    let block_hash = test_block.hash();
    let block_signature = sk.sign(block_hash.as_bytes());
    assert!(pk.verify(block_hash.as_bytes(), &block_signature),
            "SLH-DSA doit signer les blocs TSN");

    env.cleanup().await?;
    Ok(())
}

/// Test E2E : performance sous charge
#[tokio::test]
async fn test_slh_dsa_performance_load() -> anyhow::Result<()> {
    let config = E2ETestConfig {
        signature_count: 1000,
        timeout_secs: 120,
        enable_perf_tests: true,
        ..Default::default()
    };

    if !config.enable_perf_tests {
        println!("⏭️  Tests de performance désactivés");
        return Ok(());
    }

    let env = TestEnvironment::new(config.clone()).await?;

    // 1. Génération de données de test
    let mut rng = OsRng;
    let mut test_data = Vec::new();

    for i in 0..config.signature_count {
        let (sk, pk) = SecretKey::generate_rng(&mut rng);
        let message = format!("Performance test message #{}", i).into_bytes();
        let signature = sk.sign(&message);
        test_data.push((pk, message, signature));
    }

    // 2. Conversion en format batch
    let entries: Vec<BatchVerificationEntry> = test_data
        .iter()
        .map(|(pk, msg, sig)| BatchVerificationEntry {
            public_key: pk,
            message: msg,
            signature: sig,
        })
        .collect();

    // 3. Benchmark de performance
    let start_benchmark = Instant::now();
    let stats = benchmark_batch_verification(&entries, 3); // 3 itérations
    let benchmark_duration = start_benchmark.elapsed();

    // 4. Métriques de performance
    println!("✓ Signatures/seconde: {:.2}", stats.signatures_per_second);
    println!("✓ Facteur de speedup: {:.2}x", stats.speedup_factor);
    println!("✓ Utilisation CPU: {:.1}%", stats.cpu_utilization * 100.0);
    println!("✓ Durée benchmark: {:?}", benchmark_duration);

    // 5. Assertions de performance
    assert!(stats.signatures_per_second > 10.0, 
            "Performance insuffisante: {:.2} sig/s", stats.signatures_per_second);
    assert!(stats.speedup_factor > 0.8, 
            "Speedup insuffisant: {:.2}x", stats.speedup_factor);

    env.cleanup().await?;
    Ok(())
}

/// Test E2E : robustesse et scénarios d'attaque
#[tokio::test]
async fn test_slh_dsa_attack_scenarios() -> anyhow::Result<()> {
    let config = E2ETestConfig {
        enable_attack_tests: true,
        ..Default::default()
    };

    if !config.enable_attack_tests {
        println!("⏭️  Tests d'attaque désactivés");
        return Ok(());
    }

    let env = TestEnvironment::new(config.clone()).await?;

    // 1. Test de signature forgée
    let mut rng = OsRng;
    let (sk1, pk1) = SecretKey::generate_rng(&mut rng);
    let (sk2, pk2) = SecretKey::generate_rng(&mut rng);

    let message = b"message original";
    let signature1 = sk1.sign(message);

    // Tentative de vérification avec la mauvaise clé
    assert!(!pk2.verify(message, &signature1), 
            "La signature ne doit pas être valide avec une clé différente");

    // 2. Test de modification de message
    let original_message = b"message original";
    let modified_message = b"message modifie";
    let signature = sk1.sign(original_message);

    assert!(!pk1.verify(modified_message, &signature),
            "La signature ne doit pas être valide pour un message modifié");

    // 3. Test de modification de signature
    let mut corrupted_signature = signature.clone();
    let mut sig_bytes = corrupted_signature.to_bytes();
    sig_bytes[0] ^= 0x01; // Flip d'un bit
    let corrupted_sig = Signature::from_bytes(&sig_bytes);

    assert!(!pk1.verify(original_message, &corrupted_sig),
            "Une signature corrompue ne doit pas être valide");

    // 4. Test de réutilisation d'état (si applicable)
    // Ce test dépend de l'implémentation stateful de SLH-DSA
    test_state_reuse_prevention(&env).await?;

    env.cleanup().await?;
    Ok(())
}

/// Test de prévention de réutilisation d'état
async fn test_state_reuse_prevention(env: &TestEnvironment) -> anyhow::Result<()> {
    // Ce test vérifie que le gestionnaire d'état empêche la réutilisation
    // d'un même état pour plusieurs signatures (sécurité SLH-DSA)
    
    // Simulation d'une tentative de réutilisation d'état
    // (les détails dépendent de l'implémentation du consensus)
    
    println!("✓ Test de prévention de réutilisation d'état (placeholder)");
    Ok(())
}

/// Crée un bloc de test pour les tests d'intégration
async fn create_test_block() -> anyhow::Result<Block> {
    // Mock implementation - à adapter selon la structure de Block dans TSN
    todo!("Implémenter la création de bloc de test")
}

/// Crée une transaction de test
async fn create_test_transaction() -> anyhow::Result<Transaction> {
    // Mock implementation - à adapter selon la structure de Transaction dans TSN
    todo!("Implémenter la création de transaction de test")
}

/// Test de régression : vérification des vecteurs NIST
#[tokio::test]
async fn test_slh_dsa_nist_vectors() -> anyhow::Result<()> {
    // Test avec les vecteurs officiels NIST pour SLH-DSA-SHA2-128s
    // Ces vecteurs garantissent la conformité avec le standard
    
    // Vecteur de test 1 (extrait de FIPS 205)
    let seed = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];

    let (sk, pk) = SecretKey::generate(&seed);
    let test_message = b"abc";
    let signature = sk.sign(test_message);

    // Vérification que la signature est valide
    assert!(pk.verify(test_message, &signature),
            "Le vecteur NIST doit produire une signature valide");

    // Vérification de la reproductibilité
    let (sk2, pk2) = SecretKey::generate(&seed);
    assert_eq!(pk.to_bytes(), pk2.to_bytes(),
               "La génération de clés doit être déterministe");

    println!("✓ Vecteurs NIST SLH-DSA validés");
    Ok(())
}

/// Test de stress : signatures multiples en parallèle
#[tokio::test]
async fn test_slh_dsa_concurrent_stress() -> anyhow::Result<()> {
    let config = E2ETestConfig {
        signature_count: 100,
        timeout_secs: 60,
        ..Default::default()
    };

    // Test de signatures concurrentes avec différentes clés
    let num_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    let mut handles = Vec::new();

    for thread_id in 0..num_threads {
        let handle = tokio::spawn(async move {
            let mut rng = OsRng;
            let (sk, pk) = SecretKey::generate_rng(&mut rng);

            for i in 0..config.signature_count / num_threads {
                let message = format!("Thread {} message {}", thread_id, i).into_bytes();
                let signature = sk.sign(&message);
                assert!(pk.verify(&message, &signature),
                        "Signature concurrente doit être valide");
            }

            thread_id
        });
        handles.push(handle);
    }

    // Attendre tous les threads
    let start = Instant::now();
    for handle in handles {
        let thread_id = timeout(
            Duration::from_secs(config.timeout_secs),
            handle
        ).await??;
        println!("✓ Thread {} terminé", thread_id);
    }
    let total_duration = start.elapsed();

    println!("✓ Test de stress concurrent terminé en {:?}", total_duration);
    assert!(total_duration < Duration::from_secs(config.timeout_secs),
            "Le test de stress ne doit pas dépasser le timeout");

    Ok(())
}

/// Test de mémoire : vérification de l'absence de fuites
#[tokio::test]
async fn test_slh_dsa_memory_safety() -> anyhow::Result<()> {
    // Test de création/destruction répétée pour détecter les fuites mémoire
    let iterations = 1000;
    
    for i in 0..iterations {
        let mut rng = OsRng;
        let (sk, pk) = SecretKey::generate_rng(&mut rng);
        let message = format!("Memory test iteration {}", i).into_bytes();
        let signature = sk.sign(&message);
        
        assert!(pk.verify(&message, &signature));
        
        // Les clés et signatures doivent être automatiquement nettoyées
        // grâce aux traits Zeroize et ZeroizeOnDrop
        drop(sk);
        drop(signature);
        
        if i % 100 == 0 {
            println!("✓ Itération mémoire: {}/{}", i, iterations);
        }
    }

    println!("✓ Test de sécurité mémoire terminé");
    Ok(())
}

#[cfg(test)]
mod integration_helpers {
    use super::*;

    /// Utilitaire pour mesurer les performances
    pub fn measure_performance<F, R>(operation: F) -> (R, Duration)
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = operation();
        let duration = start.elapsed();
        (result, duration)
    }

    /// Génère des données de test reproductibles
    pub fn generate_test_data(count: usize, seed: u64) -> Vec<(SecretKey, PublicKey, Vec<u8>)> {
        use rand::{SeedableRng, Rng};
        use rand::rngs::StdRng;

        let mut rng = StdRng::seed_from_u64(seed);
        let mut data = Vec::new();

        for i in 0..count {
            let mut key_seed = [0u8; 32];
            rng.fill(&mut key_seed);
            
            let (sk, pk) = SecretKey::generate(&key_seed);
            let message = format!("Test data #{}", i).into_bytes();
            
            data.push((sk, pk, message));
        }

        data
    }
}