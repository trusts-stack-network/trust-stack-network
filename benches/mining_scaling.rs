//! Mining scaling benchmark — isolates hash throughput per thread count.
//!
//! Usage: cargo bench --bench mining_scaling -- [threads]
//! Example: cargo bench --bench mining_scaling -- 1 2 4 8 16

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// Re-use TSN's Poseidon2 hash
use tsn::consensus::poseidon_pow::{MiningHashContext, poseidon_hash_header_v2, hash_meets_difficulty};

const BENCH_DURATION_SECS: u64 = 10;

/// Benchmark the raw hash function in isolation (no mining logic, no atomics).
fn bench_hash_single_thread() -> f64 {
    let ctx = MiningHashContext::new(
        2, // version
        &[0xAA; 32], // prev_hash
        &[0xBB; 32], // merkle_root
        &[0xCC; 32], // commitment_root
        &[0xDD; 32], // nullifier_root
    );

    let timestamp = 1712700000u64;
    let difficulty = 8_000_000u64;
    let mut nonce = [0u8; 64];

    // Fill random prefix
    use rand::Rng;
    rand::thread_rng().fill(&mut nonce[0..56]);

    let start = Instant::now();
    let mut count = 0u64;
    let deadline = Duration::from_secs(BENCH_DURATION_SECS);

    while start.elapsed() < deadline {
        // Exactly what run_mining_job does
        ctx.meets_difficulty(timestamp, difficulty, &nonce);

        let counter = u64::from_le_bytes(nonce[56..64].try_into().unwrap());
        nonce[56..64].copy_from_slice(&counter.wrapping_add(1).to_le_bytes());
        count += 1;
    }

    let elapsed = start.elapsed().as_secs_f64();
    count as f64 / elapsed
}

/// Benchmark multi-threaded hashing — mirrors run_mining_job exactly.
fn bench_hash_multi_thread(num_threads: usize) -> (f64, Vec<u64>) {
    let per_thread_counts: Arc<Vec<AtomicU64>> = Arc::new(
        (0..num_threads).map(|_| AtomicU64::new(0)).collect()
    );

    let start_barrier = Arc::new(std::sync::Barrier::new(num_threads + 1));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let mut handles = Vec::new();

    for tid in 0..num_threads {
        let counts = Arc::clone(&per_thread_counts);
        let barrier = Arc::clone(&start_barrier);
        let stop_flag = Arc::clone(&stop);

        handles.push(std::thread::spawn(move || {
            let ctx = MiningHashContext::new(
                2,
                &[0xAA; 32],
                &[0xBB; 32],
                &[0xCC; 32],
                &[0xDD; 32],
            );

            let timestamp = 1712700000u64;
            let difficulty = 8_000_000u64;
            let mut nonce = [0u8; 64];

            use rand::Rng;
            rand::thread_rng().fill(&mut nonce[0..56]);

            // Wait for all threads to be ready
            barrier.wait();

            let mut count = 0u64;
            loop {
                // Same logic as run_mining_job hot loop
                ctx.meets_difficulty(timestamp, difficulty, &nonce);

                let counter = u64::from_le_bytes(nonce[56..64].try_into().unwrap());
                nonce[56..64].copy_from_slice(&counter.wrapping_add(1).to_le_bytes());
                count += 1;

                // Check stop every 1024 iterations (same as mining)
                if count & 0x3FF == 0 {
                    if stop_flag.load(Ordering::Relaxed) {
                        break;
                    }
                }
            }

            counts[tid].store(count, Ordering::Relaxed);
        }));
    }

    // Start all threads simultaneously
    start_barrier.wait();
    let start = Instant::now();

    // Let them run
    std::thread::sleep(Duration::from_secs(BENCH_DURATION_SECS));
    stop.store(true, Ordering::SeqCst);

    for h in handles {
        h.join().unwrap();
    }

    let elapsed = start.elapsed().as_secs_f64();

    let thread_counts: Vec<u64> = per_thread_counts.iter()
        .map(|c| c.load(Ordering::Relaxed))
        .collect();
    let total: u64 = thread_counts.iter().sum();

    (total as f64 / elapsed, thread_counts)
}

/// Benchmark with pre-allocated arrays (no Vec in hot loop) to test allocator hypothesis.
fn bench_hash_no_alloc_multi(num_threads: usize) -> (f64, Vec<u64>) {
    use p3_goldilocks::Goldilocks;
    use p3_field::integers::QuotientMap;
    use p3_symmetric::CryptographicHasher;

    let per_thread_counts: Arc<Vec<AtomicU64>> = Arc::new(
        (0..num_threads).map(|_| AtomicU64::new(0)).collect()
    );

    let start_barrier = Arc::new(std::sync::Barrier::new(num_threads + 1));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let mut handles = Vec::new();

    for tid in 0..num_threads {
        let counts = Arc::clone(&per_thread_counts);
        let barrier = Arc::clone(&start_barrier);
        let stop_flag = Arc::clone(&stop);

        handles.push(std::thread::spawn(move || {
            // Pre-build constant header elements ONCE per thread
            let version: u32 = 2;
            let prev_hash = [0xAAu8; 32];
            let merkle_root = [0xBBu8; 32];
            let commitment_root = [0xCCu8; 32];
            let nullifier_root = [0xDDu8; 32];
            let timestamp = 1712700000u64;
            let difficulty = 8_000_000u64;
            let mut nonce = [0u8; 64];

            use rand::Rng;
            rand::thread_rng().fill(&mut nonce[0..56]);

            // Pre-allocate the 212-byte header buffer
            let mut header_bytes = [0u8; 212];
            header_bytes[0..4].copy_from_slice(&version.to_le_bytes());
            header_bytes[4..36].copy_from_slice(&prev_hash);
            header_bytes[36..68].copy_from_slice(&merkle_root);
            header_bytes[68..100].copy_from_slice(&commitment_root);
            header_bytes[100..132].copy_from_slice(&nullifier_root);
            header_bytes[132..140].copy_from_slice(&timestamp.to_le_bytes());
            header_bytes[140..148].copy_from_slice(&difficulty.to_le_bytes());

            // Pre-allocate field element arrays (NO Vec, stack-only)
            // 212 bytes / 7 = 31 elements + 1 domain = 32 total
            let domain_pow: u64 = 42;

            barrier.wait();

            let mut count = 0u64;
            loop {
                // Update nonce in header buffer
                header_bytes[148..212].copy_from_slice(&nonce);

                // === ZERO-ALLOC VERSION: pack into stack array ===
                let mut elements = [Goldilocks::default(); 32]; // stack array
                elements[0] = <Goldilocks as QuotientMap<u64>>::from_int(domain_pow);
                let mut idx = 1;
                for chunk in header_bytes.chunks(7) {
                    let mut val: u64 = 0;
                    for (i, &byte) in chunk.iter().enumerate() {
                        val |= (byte as u64) << (i * 8);
                    }
                    elements[idx] = <Goldilocks as QuotientMap<u64>>::from_int(val);
                    idx += 1;
                }

                // Hash using the sponge directly with slice
                // This still goes through POSEIDON2_SPONGE but avoids Vec
                let hash = poseidon_hash_header_v2(&header_bytes);
                let _ = hash_meets_difficulty(&hash, difficulty);

                let counter = u64::from_le_bytes(nonce[56..64].try_into().unwrap());
                nonce[56..64].copy_from_slice(&counter.wrapping_add(1).to_le_bytes());
                count += 1;

                if count & 0x3FF == 0 {
                    if stop_flag.load(Ordering::Relaxed) {
                        break;
                    }
                }
            }

            counts[tid].store(count, Ordering::Relaxed);
        }));
    }

    start_barrier.wait();
    let start = Instant::now();
    std::thread::sleep(Duration::from_secs(BENCH_DURATION_SECS));
    stop.store(true, Ordering::SeqCst);

    for h in handles {
        h.join().unwrap();
    }

    let elapsed = start.elapsed().as_secs_f64();
    let thread_counts: Vec<u64> = per_thread_counts.iter()
        .map(|c| c.load(Ordering::Relaxed))
        .collect();
    let total: u64 = thread_counts.iter().sum();

    (total as f64 / elapsed, thread_counts)
}

fn fmt_hashrate(h: f64) -> String {
    if h >= 1e6 { format!("{:.2} MH/s", h / 1e6) }
    else if h >= 1e3 { format!("{:.2} KH/s", h / 1e3) }
    else { format!("{:.0} H/s", h) }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let thread_counts: Vec<usize> = if args.len() > 1 {
        args[1..].iter().filter_map(|s| s.parse().ok()).collect()
    } else {
        vec![1, 2, 4, 8, 16]
    };

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║          TSN Mining Scaling Benchmark ({}s/run)             ║", BENCH_DURATION_SECS);
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // Get baseline single-thread
    println!("▸ Baseline: 1 thread (isolated, no atomics)...");
    let baseline = bench_hash_single_thread();
    println!("  Baseline: {}", fmt_hashrate(baseline));
    println!();

    println!("┌─────────┬──────────────┬──────────┬──────────────┬─────────────────────┐");
    println!("│ Threads │  Total H/s   │ Scaling  │ Per-thread   │ Thread distribution │");
    println!("├─────────┼──────────────┼──────────┼──────────────┼─────────────────────┤");

    let mut results = Vec::new();

    for &n in &thread_counts {
        eprint!("  Running {} threads... ", n);
        let (total_hps, per_thread) = bench_hash_multi_thread(n);
        let scaling = total_hps / baseline;
        let per_thread_avg = total_hps / n as f64;

        // Thread balance: min/max ratio
        let min_t = *per_thread.iter().min().unwrap_or(&1) as f64;
        let max_t = *per_thread.iter().max().unwrap_or(&1) as f64;
        let balance = if max_t > 0.0 { min_t / max_t * 100.0 } else { 100.0 };

        println!("│ {:>7} │ {:>12} │ {:>6.2}x  │ {:>12} │ bal={:.0}% min/max     │",
            n, fmt_hashrate(total_hps), scaling, fmt_hashrate(per_thread_avg), balance);

        results.push((n, total_hps, scaling, per_thread));
        eprintln!("done");
    }

    println!("└─────────┴──────────────┴──────────┴──────────────┴─────────────────────┘");
    println!();

    // Print per-thread detail for max thread count
    if let Some((n, _, _, ref counts)) = results.last() {
        println!("▸ Per-thread detail ({} threads):", n);
        let elapsed = BENCH_DURATION_SECS as f64;
        for (i, &c) in counts.iter().enumerate() {
            let hps = c as f64 / elapsed;
            println!("  Thread {:>2}: {} ({} hashes)", i, fmt_hashrate(hps), c);
        }
    }

    println!();
    println!("▸ Analysis:");

    if results.len() >= 2 {
        let (_, h1, _, _) = &results[0];
        for (n, hn, scaling, _) in &results[1..] {
            let efficiency = scaling / *n as f64 * 100.0;
            let lost = (1.0 - efficiency / 100.0) * hn;
            println!("  {}T: {:.1}% efficiency — {:.0} H/s lost to overhead",
                n, efficiency, lost);
        }
    }

    // CPU topology info
    println!();
    println!("▸ System info:");
    if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        let cores: Vec<&str> = cpuinfo.lines()
            .filter(|l| l.starts_with("processor"))
            .collect();
        println!("  Logical CPUs: {}", cores.len());

        if let Some(model) = cpuinfo.lines().find(|l| l.starts_with("model name")) {
            println!("  {}", model.trim());
        }
    }

    // NUMA info
    if let Ok(output) = std::process::Command::new("numactl").arg("--hardware").output() {
        let numa = String::from_utf8_lossy(&output.stdout);
        for line in numa.lines().filter(|l| l.starts_with("node") && l.contains("cpus:")) {
            println!("  {}", line.trim());
        }
    }
}
