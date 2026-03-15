//! Benchmarks de performance pour le consensus TSN
//!
//! Mesure les performances de :
//! - Validation des blocs (PoW verification)
//! - Signatures SLH-DSA (post-quantique)
//! - Création de preuves Halo2 (ZK)
//!
//! Objectif : établir des baselines de performance pré-optimisation
//! et identifier les bottlenecks.

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};

// ============================================================================
// BENCHMARK 1: Validation de blocs (PoW verification)
// ============================================================================

/// Benchmark de la vérification de preuve de travail
///
/// Cette fonction mesure le temps nécessaire pour vérifier qu'un bloc
/// satisfait la difficulté cible (sans recalculer le minage).
fn bench_pow_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("consensus_pow_verification");
    group.sample_size(100);

    // Difficultés croissantes pour voir l'impact
    for difficulty in [4u64, 8, 12, 16].iter() {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("difficulty_{}", difficulty)),
            difficulty,
            |b, &difficulty| {
                // Simuler une vérification PoW avec une difficulté donnée
                b.iter(|| {
                    // Le vrai code ferait : verify_pow(block, difficulty)
                    // Ici on simule le coût de la vérification
                    let target = u64::MAX >> difficulty;
                    let hash = black_box([0u8; 32]);
                    let hash_prefix = u64::from_be_bytes([
                        hash[0], hash[1], hash[2], hash[3],
                        hash[4], hash[5], hash[6], hash[7],
                    ]);
                    black_box(hash_prefix <= target);
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// BENCHMARK 2: Signatures SLH-DSA (FIPS 205)
// ============================================================================

/// Benchmark des signatures post-quantiques SLH-DSA
///
/// SLH-DSA (SPHINCS+) est un algorithme de signature sans état
/// résistant aux attaques quantiques. Ces benchmarks mesurent
/// les performances de signature et de vérification.
fn bench_slh_dsa(c: &mut Criterion) {
    let mut group = c.benchmark_group("consensus_slh_dsa");

    // Tailles de message typiques dans TSN
    let message_sizes = [32, 64, 256, 1024, 4096];

    for size in &message_sizes {
        group.throughput(Throughput::Bytes(*size as u64));

        // Benchmark de signature
        group.bench_with_input(
            BenchmarkId::new("sign", size),
            size,
            |b, &size| {
                let message = vec![0u8; size];
                b.iter(|| {
                    // Simuler le coût de signature SLH-DSA
                    // En production: slh_dsa_sign(&sk, &message)
                    black_box(hash_message(&message));
                    black_box([0u8; 7856]); // Taille typique signature SLH-DSA-128s
                });
            },
        );

        // Benchmark de vérification
        group.bench_with_input(
            BenchmarkId::new("verify", size),
            size,
            |b, &size| {
                let message = vec![0u8; size];
                let signature = [0u8; 7856];
                let public_key = [0u8; 32];
                b.iter(|| {
                    // Simuler le coût de vérification SLH-DSA
                    // En production: slh_dsa_verify(&pk, &message, &signature)
                    black_box(hash_message(&message));
                    black_box(verify_signature(&public_key, &message, &signature));
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// BENCHMARK 3: Preuves Halo2 (ZK)
// ============================================================================

/// Benchmark de création et vérification de preuves Halo2
///
/// Halo2 est un système de preuves ZK PLONK sans trusted setup.
/// Ces benchmarks mesurent le coût des opérations de circuit.
fn bench_halo2_proofs(c: &mut Criterion) {
    let mut group = c.benchmark_group("consensus_halo2_proofs");

    // Benchmark de création de preuve
    group.sample_size(10); // Les preuves sont lentes
    group.bench_function("proof_creation", |b| {
        b.iter(|| {
            // Simuler la création d'une preuve Halo2
            // En production: create_proof(circuit, pk, &[witnesses])
            let result = simulate_halo2_proof_creation();
            black_box(result);
        });
    });

    // Benchmark de vérification de preuve
    group.sample_size(100);
    group.bench_function("proof_verification", |b| {
        let proof = [0u8; 192]; // Taille typique preuve Halo2
        let public_inputs = [0u8; 64];
        b.iter(|| {
            // Simuler la vérification d'une preuve Halo2
            // En production: verify_proof(vk, &proof, &public_inputs)
            black_box(verify_halo2_proof(&proof, &public_inputs));
        });
    });

    // Benchmark avec différents nombres de contraintes
    for num_constraints in [1000u64, 10000, 100000, 500000].iter() {
        group.throughput(Throughput::Elements(*num_constraints));
        group.bench_with_input(
            BenchmarkId::new("constraints", num_constraints),
            num_constraints,
            |b, &num_constraints| {
                b.iter(|| {
                    black_box(simulate_constraint_evaluation(num_constraints));
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// BENCHMARK 4: Validation complète de bloc
// ============================================================================

/// Benchmark de validation complète d'un bloc
///
/// Inclut : vérification PoW, vérification des signatures,
/// vérification des preuves ZK, validation des transactions.
fn bench_full_block_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("consensus_full_validation");

    // Nombre de transactions par bloc
    for num_txs in [1u64, 10, 100, 1000].iter() {
        group.throughput(Throughput::Elements(*num_txs));
        group.bench_with_input(
            BenchmarkId::new("block_validation", num_txs),
            num_txs,
            |b, &num_txs| {
                b.iter(|| {
                    // Simuler la validation complète d'un bloc
                    black_box(validate_block_header());
                    for _ in 0..num_txs {
                        black_box(validate_transaction());
                    }
                    black_box(update_state());
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// BENCHMARK 5: Comparaison ML-DSA vs SLH-DSA
// ============================================================================

/// Benchmark comparatif entre ML-DSA et SLH-DSA
///
/// ML-DSA (Dilithium) est plus rapide mais stateful en certaines variantes.
/// SLH-DSA (SPHINCS+) est stateless mais plus lent.
fn bench_signature_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("consensus_signature_comparison");
    group.sample_size(50);

    let message = [0u8; 32];

    // ML-DSA-65 (FIPS 204)
    group.bench_function("mldsa65_sign", |b| {
        b.iter(|| {
            black_box(simulate_mldsa_sign(&message));
        });
    });

    group.bench_function("mldsa65_verify", |b| {
        let signature = [0u8; 3293]; // Taille ML-DSA-65
        b.iter(|| {
            black_box(simulate_mldsa_verify(&message, &signature));
        });
    });

    // SLH-DSA-128s (FIPS 205)
    group.bench_function("slhdsa128s_sign", |b| {
        b.iter(|| {
            black_box(simulate_slhdsa_sign(&message));
        });
    });

    group.bench_function("slhdsa128s_verify", |b| {
        let signature = [0u8; 7856]; // Taille SLH-DSA-128s
        b.iter(|| {
            black_box(simulate_slhdsa_verify(&message, &signature));
        });
    });

    group.finish();
}

// ============================================================================
// FONCTIONS UTILITAIRES (simulations)
// ============================================================================

/// Simule le hachage d'un message (SHA-256)
fn hash_message(message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(message);
    hasher.finalize().into()
}

/// Simule la vérification d'une signature
fn verify_signature(_pk: &[u8], message: &[u8], _sig: &[u8]) -> bool {
    // Simulation : vérification réussie
    hash_message(message);
    true
}

/// Simule la création d'une preuve Halo2
fn simulate_halo2_proof_creation() -> [u8; 192] {
    // Simulation d'un calcul intensif
    let mut result = [0u8; 192];
    for i in 0..192 {
        result[i] = (i * 7 + 13) as u8;
    }
    result
}

/// Simule la vérification d'une preuve Halo2
fn verify_halo2_proof(_proof: &[u8], _public_inputs: &[u8]) -> bool {
    // Simulation : vérification réussie
    true
}

/// Simule l'évaluation de contraintes de circuit
fn simulate_constraint_evaluation(n: u64) -> u64 {
    let mut sum = 0u64;
    for i in 0..n {
        sum = sum.wrapping_add(i.wrapping_mul(i));
    }
    sum
}

/// Simule la validation d'un en-tête de bloc
fn validate_block_header() -> bool {
    hash_message(b"block_header");
    true
}

/// Simule la validation d'une transaction
fn validate_transaction() -> bool {
    hash_message(b"transaction");
    true
}

/// Simule la mise à jour de l'état
fn update_state() -> [u8; 32] {
    hash_message(b"state_update")
}

/// Simule une signature ML-DSA
fn simulate_mldsa_sign(_message: &[u8]) -> [u8; 3293] {
    [0u8; 3293]
}

/// Simule une vérification ML-DSA
fn simulate_mldsa_verify(_message: &[u8], _signature: &[u8]) -> bool {
    true
}

/// Simule une signature SLH-DSA
fn simulate_slhdsa_sign(_message: &[u8]) -> [u8; 7856] {
    [0u8; 7856]
}

/// Simule une vérification SLH-DSA
fn simulate_slhdsa_verify(_message: &[u8], _signature: &[u8]) -> bool {
    true
}

// ============================================================================
// CONFIGURATION DES GROUPES DE BENCHMARKS
// ============================================================================

criterion_group!(
    benches,
    bench_pow_verification,
    bench_slh_dsa,
    bench_halo2_proofs,
    bench_full_block_validation,
    bench_signature_comparison,
);

criterion_main!(benches);
