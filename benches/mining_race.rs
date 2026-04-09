//! Mining race benchmark — simulates competition between two miners with different thread counts.
//!
//! Each "race" runs two MiningPools on the same block template simultaneously.
//! The first to find a valid nonce wins the block. Repeat for N blocks.
//! This measures the REAL win rate, including all effects of MIN_BLOCK_INTERVAL,
//! LWMA difficulty adjustment, thread dispatch overhead, etc.
//!
//! Usage: cargo bench --bench mining_race

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use tsn::consensus::{MiningPool, MIN_DIFFICULTY};
use tsn::consensus::poseidon_pow::MiningHashContext;
use tsn::core::ShieldedBlockchain;
use tsn::crypto::note::ViewingKey;
use tsn::config::MIN_BLOCK_INTERVAL_SECS;

const BLOCKS_PER_RACE: usize = 50;
const DIFFICULTY: u64 = 8_000_000; // Real network difficulty

/// Result of a single block race
struct BlockResult {
    winner: usize, // 0 = miner A, 1 = miner B
    attempts_a: u64,
    attempts_b: u64,
    pow_secs: f64,
}

/// Race two MiningPools against each other on the same block template.
/// Returns which pool found the solution first.
fn race_block(
    pool_a: &MiningPool,
    pool_b: &MiningPool,
    blockchain: &mut ShieldedBlockchain,
    miner_pk_hash: [u8; 32],
    viewing_key: &ViewingKey,
) -> BlockResult {
    // Create identical block template for both miners
    let template = blockchain.create_block_template_with_v2(
        miner_pk_hash, viewing_key, vec![], vec![],
    );

    // Capture thread counts before spawning (avoids borrowing pool refs in 'static closures)
    let n_threads_a = pool_a.jobs();
    let n_threads_b = pool_b.jobs();

    // Shared race state
    let global_found = Arc::new(AtomicBool::new(false));
    let winner = Arc::new(Mutex::new(None::<(usize, tsn::core::ShieldedBlock)>));
    let attempts_a = Arc::new(AtomicU64::new(0));
    let attempts_b = Arc::new(AtomicU64::new(0));

    let start = Instant::now();
    let (done_tx, done_rx) = mpsc::channel::<()>();

    // Spawn miner A
    let template_a = template.clone();
    let found_a = Arc::clone(&global_found);
    let winner_a = Arc::clone(&winner);
    let attempts_a_c = Arc::clone(&attempts_a);
    let done_tx_a = done_tx.clone();
    let handle_a = std::thread::spawn(move || {
        let mut block = template_a;
        let n_threads = n_threads_a;
        let found_local = Arc::new(AtomicBool::new(false));
        let result_local = Arc::new(Mutex::new(None::<tsn::core::ShieldedBlock>));
        let attempts_local = Arc::new(AtomicU64::new(0));

        let mut handles = Vec::new();
        for _tid in 0..n_threads {
            let mut tpl = block.clone();
            let found_g = Arc::clone(&found_a);
            let found_l = Arc::clone(&found_local);
            let result_l = Arc::clone(&result_local);
            let attempts_l = Arc::clone(&attempts_local);

            handles.push(std::thread::spawn(move || {
                let ctx = MiningHashContext::new(
                    tpl.header.version,
                    &tpl.header.prev_hash,
                    &tpl.header.merkle_root,
                    &tpl.header.commitment_root,
                    &tpl.header.nullifier_root,
                );
                let mut nonce = [0u8; 64];
                use rand::Rng;
                rand::thread_rng().fill(&mut nonce[0..56]);

                let mut count = 0u64;
                loop {
                    if found_g.load(Ordering::Relaxed) || found_l.load(Ordering::Relaxed) {
                        break;
                    }

                    if ctx.meets_difficulty(tpl.header.timestamp, tpl.header.difficulty, &nonce) {
                        if !found_l.swap(true, Ordering::SeqCst) {
                            // First thread in THIS pool to find
                            if !found_g.swap(true, Ordering::SeqCst) {
                                // First pool globally to find — WE WIN
                                tpl.header.nonce = nonce;
                                if let Ok(mut guard) = result_l.lock() {
                                    *guard = Some(tpl);
                                }
                            }
                        }
                        break;
                    }

                    let counter = u64::from_le_bytes(nonce[56..64].try_into().unwrap());
                    nonce[56..64].copy_from_slice(&counter.wrapping_add(1).to_le_bytes());
                    count += 1;

                    if count % 1_000_000 == 0 {
                        if let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                            tpl.header.timestamp = d.as_secs();
                        }
                    }
                }
                attempts_l.fetch_add(count, Ordering::Relaxed);
            }));
        }

        for h in handles {
            h.join().ok();
        }

        let total = attempts_local.load(Ordering::Relaxed);
        attempts_a_c.store(total, Ordering::Relaxed);

        // Check if we won
        if let Ok(guard) = result_local.lock() {
            if let Some(ref won_block) = *guard {
                if let Ok(mut w) = winner_a.lock() {
                    if w.is_none() {
                        *w = Some((0, won_block.clone()));
                    }
                }
            }
        }
        let _ = done_tx_a.send(());
    });

    // Spawn miner B (same logic, different pool)
    let template_b = template.clone();
    let found_b = Arc::clone(&global_found);
    let winner_b = Arc::clone(&winner);
    let attempts_b_c = Arc::clone(&attempts_b);
    let done_tx_b = done_tx.clone();
    let handle_b = std::thread::spawn(move || {
        let mut block = template_b;
        let n_threads = n_threads_b;
        let found_local = Arc::new(AtomicBool::new(false));
        let result_local = Arc::new(Mutex::new(None::<tsn::core::ShieldedBlock>));
        let attempts_local = Arc::new(AtomicU64::new(0));

        let mut handles = Vec::new();
        for _tid in 0..n_threads {
            let mut tpl = block.clone();
            let found_g = Arc::clone(&found_b);
            let found_l = Arc::clone(&found_local);
            let result_l = Arc::clone(&result_local);
            let attempts_l = Arc::clone(&attempts_local);

            handles.push(std::thread::spawn(move || {
                let ctx = MiningHashContext::new(
                    tpl.header.version,
                    &tpl.header.prev_hash,
                    &tpl.header.merkle_root,
                    &tpl.header.commitment_root,
                    &tpl.header.nullifier_root,
                );
                let mut nonce = [0u8; 64];
                use rand::Rng;
                rand::thread_rng().fill(&mut nonce[0..56]);

                let mut count = 0u64;
                loop {
                    if found_g.load(Ordering::Relaxed) || found_l.load(Ordering::Relaxed) {
                        break;
                    }

                    if ctx.meets_difficulty(tpl.header.timestamp, tpl.header.difficulty, &nonce) {
                        if !found_l.swap(true, Ordering::SeqCst) {
                            if !found_g.swap(true, Ordering::SeqCst) {
                                tpl.header.nonce = nonce;
                                if let Ok(mut guard) = result_l.lock() {
                                    *guard = Some(tpl);
                                }
                            }
                        }
                        break;
                    }

                    let counter = u64::from_le_bytes(nonce[56..64].try_into().unwrap());
                    nonce[56..64].copy_from_slice(&counter.wrapping_add(1).to_le_bytes());
                    count += 1;

                    if count % 1_000_000 == 0 {
                        if let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                            tpl.header.timestamp = d.as_secs();
                        }
                    }
                }
                attempts_l.fetch_add(count, Ordering::Relaxed);
            }));
        }

        for h in handles {
            h.join().ok();
        }

        let total = attempts_local.load(Ordering::Relaxed);
        attempts_b_c.store(total, Ordering::Relaxed);

        if let Ok(guard) = result_local.lock() {
            if let Some(ref won_block) = *guard {
                if let Ok(mut w) = winner_b.lock() {
                    if w.is_none() {
                        *w = Some((1, won_block.clone()));
                    }
                }
            }
        }
        let _ = done_tx_b.send(());
    });

    drop(done_tx);

    // Wait for both to finish
    let _ = done_rx.recv();
    let _ = done_rx.recv();
    handle_a.join().ok();
    handle_b.join().ok();

    let pow_secs = start.elapsed().as_secs_f64();

    // Determine winner
    let winner_id = {
        let w = winner.lock().unwrap();
        match &*w {
            Some((id, won_block)) => {
                // Add winning block to blockchain for LWMA
                blockchain.add_block(won_block.clone()).ok();
                *id
            }
            None => {
                // Shouldn't happen, but default to 0
                0
            }
        }
    };

    BlockResult {
        winner: winner_id,
        attempts_a: attempts_a.load(Ordering::Relaxed),
        attempts_b: attempts_b.load(Ordering::Relaxed),
        pow_secs,
    }
}

fn fmt_hashrate(h: f64) -> String {
    if h >= 1e6 { format!("{:.2} MH/s", h / 1e6) }
    else if h >= 1e3 { format!("{:.2} KH/s", h / 1e3) }
    else { format!("{:.0} H/s", h) }
}

fn run_race(threads_a: usize, threads_b: usize) {
    let miner_pk_hash = [0xAA; 32];
    let viewing_key = ViewingKey::from_pk_hash(miner_pk_hash);
    let mut blockchain = ShieldedBlockchain::with_miner(DIFFICULTY, miner_pk_hash, &viewing_key);

    // We don't use MiningPool here — we spawn raw threads to control the race.
    // But we need the pool to know the thread count.
    let pool_a = MiningPool::new(threads_a);
    let pool_b = MiningPool::new(threads_b);

    let mut wins_a = 0usize;
    let mut wins_b = 0usize;
    let mut total_attempts_a = 0u64;
    let mut total_attempts_b = 0u64;
    let mut total_pow_secs = 0.0f64;

    let race_start = Instant::now();

    for block_num in 0..BLOCKS_PER_RACE {
        // MIN_BLOCK_INTERVAL enforcement: wait if needed
        if block_num > 0 {
            let chain_height = blockchain.height();
            if let Some(prev_block) = blockchain.get_block_by_height(chain_height) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let earliest = prev_block.header.timestamp + MIN_BLOCK_INTERVAL_SECS;
                if now < earliest {
                    std::thread::sleep(Duration::from_secs(earliest - now));
                }
            }
        }

        let result = race_block(&pool_a, &pool_b, &mut blockchain, miner_pk_hash, &viewing_key);

        if result.winner == 0 {
            wins_a += 1;
        } else {
            wins_b += 1;
        }
        total_attempts_a += result.attempts_a;
        total_attempts_b += result.attempts_b;
        total_pow_secs += result.pow_secs;

        // Progress indicator every 10 blocks
        if (block_num + 1) % 10 == 0 {
            eprint!("  [{}/{}] {}T:{} vs {}T:{} ...\n",
                block_num + 1, BLOCKS_PER_RACE,
                threads_a, wins_a, threads_b, wins_b);
        }
    }

    // Drop pools to stop worker threads
    drop(pool_a);
    drop(pool_b);

    let total_time = race_start.elapsed().as_secs_f64();
    let hr_a = total_attempts_a as f64 / total_pow_secs;
    let hr_b = total_attempts_b as f64 / total_pow_secs;
    let pct_a = wins_a as f64 / BLOCKS_PER_RACE as f64 * 100.0;
    let pct_b = wins_b as f64 / BLOCKS_PER_RACE as f64 * 100.0;
    let expected_pct_a = threads_a as f64 / (threads_a + threads_b) as f64 * 100.0;
    let expected_pct_b = threads_b as f64 / (threads_a + threads_b) as f64 * 100.0;

    println!("│ {:>3}T vs {:>3}T │ {:>12} │ {:>12} │ {:>3}/{:<3} │ {:>5.1}%/{:<5.1}% │ {:>5.1}%/{:<5.1}% │ {:>6.1}s │",
        threads_a, threads_b,
        fmt_hashrate(hr_a), fmt_hashrate(hr_b),
        wins_a, wins_b,
        pct_a, pct_b,
        expected_pct_a, expected_pct_b,
        total_time,
    );
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                    TSN Mining Race — Competition Simulation                                ║");
    println!("║  {} blocks/race | difficulty {} | MIN_BLOCK_INTERVAL={}s                              ║",
        BLOCKS_PER_RACE, DIFFICULTY, MIN_BLOCK_INTERVAL_SECS);
    println!("╚══════════════════════════════════════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Both miners race on the SAME block template simultaneously.");
    println!("  First to find a valid nonce wins. LWMA adjusts difficulty between blocks.");
    println!("  MIN_BLOCK_INTERVAL enforced between blocks (same as production).");
    println!();
    println!("┌───────────────┬──────────────┬──────────────┬─────────┬───────────────┬───────────────┬────────┐");
    println!("│     Race      │  Hashrate A  │  Hashrate B  │ Wins    │  Actual %     │  Expected %   │  Time  │");
    println!("├───────────────┼──────────────┼──────────────┼─────────┼───────────────┼───────────────┼────────┤");

    let races = vec![(4, 32), (4, 64), (4, 128), (4, 256)];
    for (a, b) in races {
        eprint!("Running {}T vs {}T ({} blocks)...\n", a, b, BLOCKS_PER_RACE);
        run_race(a, b);
    }

    println!("└───────────────┴──────────────┴──────────────┴─────────┴───────────────┴───────────────┴────────┘");
    println!();
    println!("▸ Expected % = threads / total_threads (pure hashrate proportional)");
    println!("  Actual % close to Expected % = scaling works correctly");
    println!("  Actual % deviates = MIN_BLOCK_INTERVAL or overhead distorts competition");
}
