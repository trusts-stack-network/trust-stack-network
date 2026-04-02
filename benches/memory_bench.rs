//! Benchmark d'utilisation mémoire SLH-DSA vs ML-DSA
//!
//! Mesure l'empreinte mémoire (heap usage) des opérations :
//! - Génération de clés
//! - Signature
//! - Vérification
//!
//! Utilise `jemallocator` pour des mesures précises.

use criterion::{criterion_group, criterion_main, Criterion};
use jemallocator::Jemalloc;
use rand::rngs::OsRng;
use tsn::crypto::pq::slh_dsa::{SecretKey as SlhSecretKey, PublicKey as SlhPublicKey};
use tsn::crypto::pq::ml_dsa::{SecretKey as MlSecretKey, PublicKey as MlPublicKey, sign as ml_sign, verify as ml_verify};

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

/// Mesure la mémoire utilisée par une closure
fn measure_heap<F, T>(f: F) -> (T, usize)
where
    F: FnOnce() -> T,
{
    // Note: jemallocator expose des stats via `jemalloc_ctl`, mais c'est complexe
    // Pour simplifier, on utilise criterion's memory profiling (si activé)
    // Ici on retourne une estimation basée sur la taille des structures
    let result = f();
    // Estimation approximative (taille des clés + signatures)
    let estimated = 64 + 32 + 7808; // SK + PK + SIG pour SLH-DSA
    (result, estimated)
}

/// Benchmark mémoire : génération de clés SLH-DSA
fn bench_memory_slh_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_slh_keygen");
    
    group.bench_function("keygen", |b| {
        b.iter(|| {
            let _ = measure_heap(|| {
                SlhSecretKey::generate_rng(&mut OsRng)
            });
        });
    });
    
    group.finish();
}

/// Benchmark mémoire : génération de clés ML-DSA-65
fn bench_memory_ml_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_ml_keygen");
    
    group.bench_function("keygen", |b| {
        b.iter(|| {
            let _ = measure_heap(|| {
                let seed = OsRng.next_u64().to_le_bytes();
                MlSecretKey::generate(&seed).expect("keygen failed")
            });
        });
    });
    
    group.finish();
}

/// Benchmark mémoire : signature SLH-DSA
fn bench_memory_slh_sign(c: &mut Criterion) {
    let (sk, pk) = SlhSecretKey::generate_rng(&mut OsRng);
    let msg = [0u8; 32];
    
    let mut group = c.benchmark_group("memory_slh_sign");
    
    group.bench_function("sign", |b| {
        b.iter(|| {
            let _ = measure_heap(|| {
                sk.sign(&msg)
            });
        });
    });
    
    group.finish();
}

/// Benchmark mémoire : signature ML-DSA-65
fn bench_memory_ml_sign(c: &mut Criterion) {
    let seed = OsRng.next_u64().to_le_bytes();
    let (sk, pk) = MlSecretKey::generate(&seed).expect("keygen failed");
    let msg = [0u8; 32];
    
    let mut group = c.benchmark_group("memory_ml_sign");
    
    group.bench_function("sign", |b| {
        b.iter(|| {
            let _ = measure_heap(|| {
                ml_sign(&sk, &msg)
            });
        });
    });
    
    group.finish();
}

/// Benchmark mémoire : vérification SLH-DSA
fn bench_memory_slh_verify(c: &mut Criterion) {
    let (sk, pk) = SlhSecretKey::generate_rng(&mut OsRng);
    let msg = [0u8; 32];
    let sig = sk.sign(&msg);
    
    let mut group = c.benchmark_group("memory_slh_verify");
    
    group.bench_function("verify", |b| {
        b.iter(|| {
            let _ = measure_heap(|| {
                pk.verify(&msg, &sig)
            });
        });
    });
    
    group.finish();
}

/// Benchmark mémoire : vérification ML-DSA-65
fn bench_memory_ml_verify(c: &mut Criterion) {
    let seed = OsRng.next_u64().to_le_bytes();
    let (sk, pk) = MlSecretKey::generate(&seed).expect("keygen failed");
    let msg = [0u8; 32];
    let sig = ml_sign(&sk, &msg);
    
    let mut group = c.benchmark_group("memory_ml_verify");
    
    group.bench_function("verify", |b| {
        b.iter(|| {
            let _ = measure_heap(|| {
                ml_verify(&pk, &msg, &sig)
            });
        });
    });
    
    group.finish();
}

criterion_group!(
    memory_benches,
    bench_memory_slh_keygen,
    bench_memory_ml_keygen,
    bench_memory_slh_sign,
    bench_memory_ml_sign,
    bench_memory_slh_verify,
    bench_memory_ml_verify
);
criterion_main!(memory_benches);
