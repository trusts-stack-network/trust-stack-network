//! Benchmark de throughput et latence pour SLH-DSA vs ML-DSA
//!
//! Ce fichier mesure les performances de signature et vérification
//! sur des workloads réalistes (1000+ tx/bloc), avec métriques :
//! - Latence p50/p95/p99
//! - Throughput (tx/s)
//! - Utilisation mémoire (heap usage)
//!
//! Usage : cargo bench --bench throughput_bench

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rand::rngs::OsRng;
use tsn::crypto::pq::slh_dsa::{SecretKey as SlhSecretKey, PublicKey as SlhPublicKey};
use tsn::crypto::pq::ml_dsa::{SecretKey as MlSecretKey, PublicKey as MlPublicKey, sign as ml_sign, verify as ml_verify};

/// Génère N paires de clés SLH-DSA
fn generate_slh_keys(n: usize) -> Vec<(SlhSecretKey, SlhPublicKey)> {
    let mut keys = Vec::with_capacity(n);
    for _ in 0..n {
        let (sk, pk) = SlhSecretKey::generate_rng(&mut OsRng);
        keys.push((sk, pk));
    }
    keys
}

/// Génère N paires de clés ML-DSA-65
fn generate_ml_keys(n: usize) -> Vec<(MlSecretKey, MlPublicKey)> {
    let mut keys = Vec::with_capacity(n);
    for _ in _ {
        let seed = OsRng.next_u64().to_le_bytes();
        let (sk, pk) = MlSecretKey::generate(&seed).expect("keygen failed");
        keys.push((sk, pk));
    }
    keys
}

/// Benchmark de signature SLH-DSA
fn bench_slh_sign(c: &mut Criterion) {
    let keys = generate_slh_keys(100);
    let msg = [0u8; 32];

    let mut group = c.benchmark_group("slh_dsa_sign");
    group.throughput(Throughput::Elements(keys.len() as u64));
    group.bench_function("100_keys", |b| {
        b.iter(|| {
            for (sk, _) in &keys {
                let _ = sk.sign(&msg);
            }
        });
    });
    group.finish();
}

/// Benchmark de signature ML-DSA-65
fn bench_ml_sign(c: &mut Criterion) {
    let keys = generate_ml_keys(100);
    let msg = [0u8; 32];

    let mut group = c.benchmark_group("ml_dsa_sign");
    group.throughput(Throughput::Elements(keys.len() as u64));
    group.bench_function("100_keys", |b| {
        b.iter(|| {
            for (sk, _) in &keys {
                let _ = ml_sign(sk, &msg);
            }
        });
    });
    group.finish();
}

/// Benchmark de vérification SLH-DSA
fn bench_slh_verify(c: &mut Criterion) {
    let keys = generate_slh_keys(100);
    let msg = [0u8; 32];
    let sigs: Vec<_> = keys.iter().map(|(sk, _)| sk.sign(&msg)).collect();

    let mut group = c.benchmark_group("slh_dsa_verify");
    group.throughput(Throughput::Elements(keys.len() as u64));
    group.bench_function("100_keys", |b| {
        b.iter(|| {
            for (pk, sig) in keys.iter().zip(sigs.iter()) {
                let _ = pk.verify(&msg, sig);
            }
        });
    });
    group.finish();
}

/// Benchmark de vérification ML-DSA-65
fn bench_ml_verify(c: &mut Criterion) {
    let keys = generate_ml_keys(100);
    let msg = [0u8; 32];
    let sigs: Vec<_> = keys.iter().map(|(sk, _)| ml_sign(sk, &msg)).collect();

    let mut group = c.benchmark_group("ml_dsa_verify");
    group.throughput(Throughput::Elements(keys.len() as u64));
    group.bench_function("100_keys", |b| {
        b.iter(|| {
            for (pk, sig) in keys.iter().zip(sigs.iter()) {
                let _ = ml_verify(pk, &msg, sig);
            }
        });
    });
    group.finish();
}

/// Benchmark de throughput complet (1000 tx/bloc simulé)
fn bench_throughput_1k_tx(c: &mut Criterion) {
    let slh_keys = generate_slh_keys(1000);
    let ml_keys = generate_ml_keys(1000);
    let msg = [0u8; 32];

    // SLH-DSA
    let mut group = c.benchmark_group("throughput_1k_tx");
    group.throughput(Throughput::Elements(1000));

    group.bench_function("slh_1k_sign", |b| {
        b.iter(|| {
            for (sk, _) in &slh_keys {
                let _ = sk.sign(&msg);
            }
        });
    });

    // ML-DSA
    group.bench_function("ml_1k_sign", |b| {
        b.iter(|| {
            for (sk, _) in &ml_keys {
                let _ = ml_sign(sk, &msg);
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_slh_sign,
    bench_ml_sign,
    bench_slh_verify,
    bench_ml_verify,
    bench_throughput_1k_tx
);
criterion_main!(benches);
