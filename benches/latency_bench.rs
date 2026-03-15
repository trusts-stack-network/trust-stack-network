//! Benchmark de latence SLH-DSA vs ML-DSA (p50/p95/p99)
//!
//! Mesure la latence individuelle des opérations sur 1000+ itérations
//! pour calculer les percentiles (p50, p95, p99).

use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;
use tsn::crypto::pq::slh_dsa::{SecretKey as SlhSecretKey, PublicKey as SlhPublicKey};
use tsn::crypto::pq::ml_dsa::{SecretKey as MlSecretKey, PublicKey as MlPublicKey, sign as ml_sign, verify as ml_verify};

/// Mesure la latence d'une opération répétée N fois
fn measure_latency<F, T>(mut f: F, n: usize) -> Vec<u64>
where
    F: FnMut() -> T,
{
    let mut latencies = Vec::with_capacity(n);
    for _ in 0..n {
        let start = std::time::Instant::now();
        let _ = f();
        let elapsed = start.elapsed();
        latencies.push(elapsed.as_micros() as u64);
    }
    latencies
}

/// Calcul des percentiles
fn percentile(data: &[u64], p: f64) -> u64 {
    let mut sorted = data.to_vec();
    sorted.sort_unstable();
    let idx = ((p / 100.0) * (sorted.len() - 1) as f64) as usize;
    sorted[idx]
}

/// Benchmark latence : signature SLH-DSA (1000 itérations)
fn bench_latency_slh_sign(c: &mut Criterion) {
    let (sk, _) = SlhSecretKey::generate_rng(&mut OsRng);
    let msg = [0u8; 32];
    
    let mut group = c.benchmark_group("latency_slh_sign");
    
    group.bench_function("1000_iterations", |b| {
        b.iter(|| {
            let latencies = measure_latency(|| sk.sign(&msg), 1000);
            let p50 = percentile(&latencies, 50.0);
            let p95 = percentile(&latencies, 95.0);
            let p99 = percentile(&latencies, 99.0);
            criterion::black_box((p50, p95, p99));
        });
    });
    
    group.finish();
}

/// Benchmark latence : signature ML-DSA-65 (1000 itérations)
fn bench_latency_ml_sign(c: &mut Criterion) {
    let seed = OsRng.next_u64().to_le_bytes();
    let (sk, _) = MlSecretKey::generate(&seed).expect("keygen failed");
    let msg = [0u8; 32];
    
    let mut group = c.benchmark_group("latency_ml_sign");
    
    group.bench_function("1000_iterations", |b| {
        b.iter(|| {
            let latencies = measure_latency(|| ml_sign(&sk, &msg), 1000);
            let p50 = percentile(&latencies, 50.0);
            let p95 = percentile(&latencies, 95.0);
            let p99 = percentile(&latencies, 99.0);
            criterion::black_box((p50, p95, p99));
        });
    });
    
    group.finish();
}

/// Benchmark latence : vérification SLH-DSA (1000 itérations)
fn bench_latency_slh_verify(c: &mut Criterion) {
    let (sk, pk) = SlhSecretKey::generate_rng(&mut OsRng);
    let msg = [0u8; 32];
    let sig = sk.sign(&msg);
    
    let mut group = c.benchmark_group("latency_slh_verify");
    
    group.bench_function("1000_iterations", |b| {
        b.iter(|| {
            let latencies = measure_latency(|| pk.verify(&msg, &sig), 1000);
            let p50 = percentile(&latencies, 50.0);
            let p95 = percentile(&latencies, 95.0);
            let p99 = percentile(&latencies, 99.0);
            criterion::black_box((p50, p95, p99));
        });
    });
    
    group.finish();
}

/// Benchmark latence : vérification ML-DSA-65 (1000 itérations)
fn bench_latency_ml_verify(c: &mut Criterion) {
    let seed = OsRng.next_u64().to_le_bytes();
    let (sk, pk) = MlSecretKey::generate(&seed).expect("keygen failed");
    let msg = [0u8; 32];
    let sig = ml_sign(&sk, &msg);
    
    let mut group = c.benchmark_group("latency_ml_verify");
    
    group.bench_function("1000_iterations", |b| {
        b.iter(|| {
            let latencies = measure_latency(|| ml_verify(&pk, &msg, &sig), 1000);
            let p50 = percentile(&latencies, 50.0);
            let p95 = percentile(&latencies, 95.0);
            let p99 = percentile(&latencies, 99.0);
            criterion::black_box((p50, p95, p99));
        });
    });
    
    group.finish();
}

criterion_group!(
    latency_benches,
    bench_latency_slh_sign,
    bench_latency_ml_sign,
    bench_latency_slh_verify,
    bench_latency_ml_verify
);
criterion_main!(latency_benches);
