//! Benchmarks for TSN ZK proving systems
//! 
//! Compares:
//! - Halo2 (PLONK, no trusted setup, 128-bit security)
//! - Plonky2 (STARKs, FRI-based, post-quantum)
//! 
//! Security context:
//! - All benchmarks use 128-bit security parameters
//! - Benchmarks are designed to be reproducible across hardware
//! 
//! Usage:
//! ```bash
//! cargo bench --bench halo2_plonky2_comparison
//! ```

use criterion::{black_box, criterion_group, criterion_main, Criterion};

// Import benchmark modules
mod halo2_commitment_bench;
mod plonky2_bench;
mod memory_bench;

/// Main benchmark group for TSN ZK systems
fn tsn_zk_benches(c: &mut Criterion) {
    // Halo2 benchmarks
    halo2_commitment_bench::halo2_commitment_benches(c);
    
    // Plonky2 benchmarks
    plonky2_bench::plonky2_benches(c);
    
    // Memory benchmarks
    memory_bench::memory_benches(c);
}

criterion_group!(
    name = tsn_zk_comparison_benches;
    config = Criterion::default()
        .sample_size(10)  // Reduced for faster CI runs
        .measurement_time(std::time::Duration::from_secs(60));
    targets = tsn_zk_benches
);

criterion_main!(tsn_zk_comparison_benches);
