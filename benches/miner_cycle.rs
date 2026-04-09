//! Miner cycle benchmark — measures each phase of the integrated miner loop.
//!
//! Reproduces the exact same sequence as main.rs miner:
//!   1. Create blockchain + mempool (in-memory)
//!   2. For each block:
//!      a. Read mempool
//!      b. Wait for MIN_BLOCK_INTERVAL
//!      c. Create block template
//!      d. Mine (PoW)
//!      e. Add block to chain
//!   3. Measure each phase separately
//!
//! Usage: cargo bench --bench miner_cycle --release

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tsn::consensus::MiningPool;
use tsn::core::ShieldedBlockchain;
use tsn::crypto::note::ViewingKey;
use tsn::config::MIN_BLOCK_INTERVAL_SECS;

const BLOCKS_TO_MINE: usize = 2;

struct CycleMetrics {
    thread_count: usize,
    blocks: Vec<BlockMetrics>,
}

struct BlockMetrics {
    height: u64,
    difficulty: u64,
    template_ms: f64,
    wait_ms: f64,
    pow_ms: f64,
    add_block_ms: f64,
    total_ms: f64,
    attempts: u64,
    raw_hashrate: f64,
}

fn run_miner_cycle(threads: usize) -> CycleMetrics {
    // Create fresh blockchain (in-memory, same as real miner)
    let miner_pk_hash = [0xAA; 32];
    let viewing_key = ViewingKey::from_pk_hash(miner_pk_hash);
    // Use real network difficulty to match production conditions
    let genesis_difficulty = 8_000_000u64;
    let mut blockchain = ShieldedBlockchain::with_miner(genesis_difficulty, miner_pk_hash, &viewing_key);

    let pool = MiningPool::new(threads);

    let mut metrics = CycleMetrics {
        thread_count: threads,
        blocks: Vec::new(),
    };

    let mut last_block_time: Option<u64> = None;

    for _ in 0..BLOCKS_TO_MINE {
        let cycle_start = Instant::now();

        // Phase 1: Wait for MIN_BLOCK_INTERVAL (same order as main.rs:3074-3093)
        let t1 = Instant::now();
        if let Some(prev_ts) = last_block_time {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let earliest = prev_ts + MIN_BLOCK_INTERVAL_SECS;
            if now < earliest {
                let wait = earliest - now;
                std::thread::sleep(Duration::from_secs(wait));
            }
        }
        let wait_ms = t1.elapsed().as_secs_f64() * 1000.0;

        // Phase 2: Create block template (after wait, so timestamp is fresh)
        let t0 = Instant::now();
        let mut block = blockchain.create_block_template_with_v2(miner_pk_hash, &viewing_key, vec![], vec![]);
        let template_ms = t0.elapsed().as_secs_f64() * 1000.0;

        let height = blockchain.height() + 1;
        let difficulty = block.header.difficulty;

        // Phase 3: Mine (PoW)
        let t2 = Instant::now();
        let attempts = pool.mine_block(&mut block);
        let pow_ms = t2.elapsed().as_secs_f64() * 1000.0;

        let raw_hashrate = if pow_ms > 0.0 {
            attempts as f64 / (pow_ms / 1000.0)
        } else {
            0.0
        };

        // Phase 4: Add block to chain
        let t3 = Instant::now();
        blockchain.add_block(block.clone()).expect("add_block failed");
        let add_block_ms = t3.elapsed().as_secs_f64() * 1000.0;

        last_block_time = Some(block.header.timestamp);

        let total_ms = cycle_start.elapsed().as_secs_f64() * 1000.0;

        metrics.blocks.push(BlockMetrics {
            height,
            difficulty,
            template_ms,
            wait_ms,
            pow_ms,
            add_block_ms,
            total_ms,
            attempts,
            raw_hashrate,
        });
    }

    metrics
}

fn fmt_hashrate(h: f64) -> String {
    if h >= 1e6 { format!("{:.2} MH/s", h / 1e6) }
    else if h >= 1e3 { format!("{:.2} KH/s", h / 1e3) }
    else { format!("{:.0} H/s", h) }
}

fn main() {
    let thread_counts: Vec<usize> = {
        let args: Vec<String> = std::env::args().collect();
        let parsed: Vec<usize> = args[1..].iter().filter_map(|s| s.parse().ok()).collect();
        if parsed.is_empty() {
            vec![1, 4, 8, 16]
        } else {
            parsed
        }
    };

    println!("╔══════════════════════════════════════════════════════════════════════════╗");
    println!("║              TSN Miner Cycle Benchmark ({} blocks/run)                  ║", BLOCKS_TO_MINE);
    println!("║  MIN_BLOCK_INTERVAL = {}s                                               ║", MIN_BLOCK_INTERVAL_SECS);
    println!("╚══════════════════════════════════════════════════════════════════════════╝");
    println!();

    // Header
    println!("┌─────────┬──────────────┬───────────┬───────────┬───────────┬───────────┬──────────────┬──────────────┐");
    println!("│ Threads │ Raw hashrate │  PoW avg  │ Wait avg  │ Template  │ AddBlock  │  Cycle avg   │ Blk through. │");
    println!("├─────────┼──────────────┼───────────┼───────────┼───────────┼───────────┼──────────────┼──────────────┤");

    let mut all_results: Vec<(usize, f64, f64, f64, f64, f64, f64)> = Vec::new();

    for &n in &thread_counts {
        eprint!("  Running {} threads ({} blocks)... ", n, BLOCKS_TO_MINE);

        let metrics = run_miner_cycle(n);

        // Compute averages (skip first block — no wait)
        let relevant: Vec<&BlockMetrics> = if metrics.blocks.len() > 1 {
            metrics.blocks[1..].iter().collect()
        } else {
            metrics.blocks.iter().collect()
        };

        let avg_pow_ms = relevant.iter().map(|b| b.pow_ms).sum::<f64>() / relevant.len() as f64;
        let avg_wait_ms = relevant.iter().map(|b| b.wait_ms).sum::<f64>() / relevant.len() as f64;
        let avg_template_ms = relevant.iter().map(|b| b.template_ms).sum::<f64>() / relevant.len() as f64;
        let avg_add_ms = relevant.iter().map(|b| b.add_block_ms).sum::<f64>() / relevant.len() as f64;
        let avg_total_ms = relevant.iter().map(|b| b.total_ms).sum::<f64>() / relevant.len() as f64;
        let avg_hashrate = relevant.iter().map(|b| b.raw_hashrate).sum::<f64>() / relevant.len() as f64;
        let block_throughput = 1000.0 / avg_total_ms; // blocks per second

        println!("│ {:>7} │ {:>12} │ {:>7.1}s  │ {:>7.1}s  │ {:>7.1}ms │ {:>7.1}ms │  {:>8.1}s   │ {:>8.3} b/s  │",
            n,
            fmt_hashrate(avg_hashrate),
            avg_pow_ms / 1000.0,
            avg_wait_ms / 1000.0,
            avg_template_ms,
            avg_add_ms,
            avg_total_ms / 1000.0,
            block_throughput,
        );

        all_results.push((n, avg_hashrate, avg_pow_ms, avg_wait_ms, avg_template_ms, avg_add_ms, avg_total_ms));

        eprintln!("done");

        // Per-block detail
        for b in &metrics.blocks {
            eprintln!("    Block #{}: PoW={:.1}s wait={:.1}s template={:.0}ms add={:.0}ms hashrate={} attempts={}",
                b.height, b.pow_ms/1000.0, b.wait_ms/1000.0, b.template_ms, b.add_block_ms,
                fmt_hashrate(b.raw_hashrate), b.attempts);
        }
    }

    println!("└─────────┴──────────────┴───────────┴───────────┴───────────┴───────────┴──────────────┴──────────────┘");

    // Analysis
    println!();
    println!("▸ Analyse du throttling :");
    for &(n, hashrate, pow_ms, wait_ms, template_ms, add_ms, total_ms) in &all_results {
        let pow_pct = pow_ms / total_ms * 100.0;
        let wait_pct = wait_ms / total_ms * 100.0;
        let overhead_pct = (template_ms + add_ms) / total_ms * 100.0;
        let effective_hashrate = hashrate * pow_pct / 100.0;
        println!("  {:>2}T: PoW={:.0}% wait={:.0}% overhead={:.1}% | raw={} effective={}",
            n, pow_pct, wait_pct, overhead_pct,
            fmt_hashrate(hashrate), fmt_hashrate(effective_hashrate));
    }

    // Optimal thread count
    println!();
    println!("▸ Point optimal :");
    if let Some(&(_, baseline_hr, _, _, _, _, _)) = all_results.first() {
        let per_thread_hr = baseline_hr; // ~111 KH/s from benchmark
        // At current difficulty, find where PoW_time ≈ MIN_BLOCK_INTERVAL
        if let Some(&(_, _, _, _, _, _, _)) = all_results.last() {
            // Use the first run's difficulty (genesis = MIN_DIFFICULTY)
            // For real network: difficulty ~8M
            let real_difficulty = 8_000_000u64;
            let optimal_threads = (real_difficulty as f64 / (MIN_BLOCK_INTERVAL_SECS as f64 * per_thread_hr)).ceil() as usize;
            println!("  Difficulté réseau actuelle : ~{}", real_difficulty);
            println!("  Hashrate par thread : {}", fmt_hashrate(per_thread_hr));
            println!("  Threads optimal ≈ difficulty / (interval × per_thread)");
            println!("                    = {} / ({} × {:.0})", real_difficulty, MIN_BLOCK_INTERVAL_SECS, per_thread_hr);
            println!("                    ≈ {} threads", optimal_threads);
            println!("  Au-delà : CPU gaspillé, le MIN_BLOCK_INTERVAL throttle le débit.");
        }
    }
}
