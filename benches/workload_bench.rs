//! Benchmark de charge réelle : validation de blocs complets (1000+ tx/bloc)
//!
//! Simule la validation d'un bloc avec :
//! - 1000+ transactions
//! - Chaque transaction contient plusieurs signatures SLH-DSA/ML-DSA
//! - Mesure de latence, throughput, et mémoire

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rand::rngs::OsRng;
use tsn::crypto::pq::slh_dsa::{SecretKey as SlhSecretKey, PublicKey as SlhPublicKey};
use tsn::crypto::pq::ml_dsa::{SecretKey as MlSecretKey, PublicKey as MlPublicKey, sign as ml_sign, verify as ml_verify};

/// Structure simulée de transaction
struct SimulatedTransaction {
    inputs: Vec<(SlhSecretKey, SlhPublicKey)>,
    outputs: Vec<(SlhSecretKey, SlhPublicKey)>,
    ml_signatures: Vec<(MlSecretKey, MlPublicKey)>,
}

/// Génère un bloc simulé avec N transactions
fn generate_block(num_tx: usize) -> Vec<SimulatedTransaction> {
    let mut block = Vec::with_capacity(num_tx);
    let msg = [0u8; 32];
    
    for _ in 0..num_tx {
        // 2 inputs SLH-DSA
        let input1 = SlhSecretKey::generate_rng(&mut OsRng);
        let input2 = SlhSecretKey::generate_rng(&mut OsRng);
        
        // 2 outputs SLH-DSA
        let output1 = SlhSecretKey::generate_rng(&mut OsRng);
        let output2 = SlhSecretKey::generate_rng(&mut OsRng);
        
        // 1 signature ML-DSA
        let seed = OsRng.next_u64().to_le_bytes();
        let ml_sk = MlSecretKey::generate(&seed).expect("keygen failed");
        let ml_pk = MlPublicKey::from(&ml_sk.0);
        let ml_sig = ml_sign(&ml_sk, &msg);
        
        block.push(SimulatedTransaction {
            inputs: vec![input1, input2],
            outputs: vec![output1, output2],
            ml_signatures: vec![(ml_sk, ml_pk)],
        });
    }
    
    block
}

/// Simule la validation d'un bloc (vérification de toutes les signatures)
fn validate_block(block: &[SimulatedTransaction]) -> bool {
    let msg = [0u8; 32];
    
    for tx in block {
        // Vérifier inputs SLH-DSA
        for (sk, pk) in &tx.inputs {
            let sig = sk.sign(&msg);
            if !pk.verify(&msg, &sig) {
                return false;
            }
        }
        
        // Vérifier outputs SLH-DSA
        for (sk, pk) in &tx.outputs {
            let sig = sk.sign(&msg);
            if !pk.verify(&msg, &sig) {
                return false;
            }
        }
        
        // Vérifier ML-DSA
        for (sk, pk) in &tx.ml_signatures {
            let sig = ml_sign(sk, &msg);
            if !ml_verify(pk, &msg, &sig) {
                return false;
            }
        }
    }
    
    true
}

/// Benchmark de validation de bloc (1000 tx)
fn bench_block_validation_1k(c: &mut Criterion) {
    let block = generate_block(1000);
    
    let mut group = c.benchmark_group("block_validation_1k");
    group.throughput(Throughput::Elements(1000));
    
    group.bench_function("validate", |b| {
        b.iter(|| {
            let _ = validate_block(&block);
        });
    });
    
    group.finish();
}

/// Benchmark de validation de bloc (5000 tx)
fn bench_block_validation_5k(c: &mut Criterion) {
    let block = generate_block(5000);
    
    let mut group = c.benchmark_group("block_validation_5k");
    group.throughput(Throughput::Elements(5000));
    
    group.bench_function("validate", |b| {
        b.iter(|| {
            let _ = validate_block(&block);
        });
    });
    
    group.finish();
}

/// Benchmark de validation de bloc (10000 tx)
fn bench_block_validation_10k(c: &mut Criterion) {
    let block = generate_block(10000);
    
    let mut group = c.benchmark_group("block_validation_10k");
    group.throughput(Throughput::Elements(10000));
    
    group.bench_function("validate", |b| {
        b.iter(|| {
            let _ = validate_block(&block);
        });
    });
    
    group.finish();
}

criterion_group!(
    workload_benches,
    bench_block_validation_1k,
    bench_block_validation_5k,
    bench_block_validation_10k
);
criterion_main!(workload_benches);
