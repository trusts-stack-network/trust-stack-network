//! Proof-of-work mining for shielded blocks.
//!
//! Uses Poseidon hash (ZK-friendly) instead of SHA-256.
//! This enables efficient in-circuit verification of PoW proofs.

use crate::core::{BlockHeaderHashPrefix, ShieldedBlock};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc, Mutex,
};
use std::thread::JoinHandle;

/// Mine a block by finding a valid nonce.
///
/// Increments the nonce until the block hash meets the difficulty target.
/// Returns the number of hashes computed.
pub fn mine_block(block: &mut ShieldedBlock) -> u64 {
    mine_block_with_jobs(block, 1)
}

/// Mine a block using multiple threads.
///
/// Each thread searches a disjoint nonce sequence to avoid duplicate hashes.
/// Returns the number of hashes computed.
///
/// Note: this spawns new worker threads each call. For repeated mining,
/// create a `MiningPool` and reuse it across blocks.
pub fn mine_block_with_jobs(block: &mut ShieldedBlock, jobs: usize) -> u64 {
    let jobs = jobs.max(1);
    if jobs == 1 {
        return mine_block_single(block);
    }

    let pool = MiningPool::new(jobs);
    pool.mine_block(block)
}

fn mine_block_single(block: &mut ShieldedBlock) -> u64 {
    let prefix = BlockHeaderHashPrefix::new_with_height(&block.header, block.height());
    let mut attempts = 0u64;

    loop {
        if prefix.meets_difficulty(
            block.header.timestamp,
            block.header.difficulty,
            block.header.nonce,
        ) {
            return attempts;
        }

        block.header.nonce = block.header.nonce.wrapping_add(1);
        attempts += 1;

        // Update timestamp periodically to avoid stale blocks
        if attempts % 1_000_000 == 0 {
            // SECURITY FIX: Remplacement de unwrap() par une gestion d'erreur sécurisée
            // Un panic ici arrêterait le mining complet
            // → Si SystemTime::now() < UNIX_EPOCH (horloge système invalide),
            // on utilise le timestamp actuel du bloc sans le modifier
            if let Ok(duration) = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH) {
                block.header.timestamp = duration.as_secs();
            }
            // Si l'horloge est invalide, on continue avec le timestamp existant
        }
    }
}

enum WorkerCommand {
    Mine(MineJob),
    Stop,
}

/// Optional SIMD mode for mining (legacy, kept for API compatibility).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimdMode {
    Neon,
}

impl SimdMode {
    pub fn is_supported(self) -> bool {
        // Poseidon uses field arithmetic, not bitwise ops — SIMD not applicable
        false
    }
}

struct MineJob {
    template: ShieldedBlock,
    found: Arc<AtomicBool>,
    attempts_total: Arc<AtomicU64>,
    result: Arc<Mutex<Option<ShieldedBlock>>>,
    done_tx: mpsc::Sender<()>,
}

/// Persistent worker threads for mining multiple blocks efficiently.
pub struct MiningPool {
    jobs: usize,
    _simd: Option<SimdMode>,
    senders: Vec<mpsc::Sender<WorkerCommand>>,
    handles: Mutex<Vec<JoinHandle<()>>>,
}

impl MiningPool {
    pub fn new(jobs: usize) -> Self {
        Self::new_with_simd(jobs, None)
    }

    pub fn new_with_simd(jobs: usize, simd: Option<SimdMode>) -> Self {
        let jobs = jobs.max(1);
        let mut senders = Vec::with_capacity(jobs);
        let mut handles = Vec::with_capacity(jobs);

        for _worker_id in 0..jobs {
            let (tx, rx) = mpsc::channel();
            senders.push(tx);

            let handle = std::thread::spawn(move || {
                while let Ok(command) = rx.recv() {
                    match command {
                        WorkerCommand::Mine(job) => run_mining_job(job, _worker_id, jobs),
                        WorkerCommand::Stop => break,
                    }
                }
            });

            handles.push(handle);
        }

        Self {
            jobs,
            _simd: simd,
            senders,
            handles: Mutex::new(handles),
        }
    }

    pub fn jobs(&self) -> usize {
        self.jobs
    }

    pub fn mine_block(&self, block: &mut ShieldedBlock) -> u64 {
        let found = Arc::new(AtomicBool::new(false));
        let attempts_total = Arc::new(AtomicU64::new(0));
        let result = Arc::new(Mutex::new(None));
        let (done_tx, done_rx) = mpsc::channel();

        let template = block.clone();
        let mut active_workers = 0usize;

        for sender in &self.senders {
            let job = MineJob {
                template: template.clone(),
                found: Arc::clone(&found),
                attempts_total: Arc::clone(&attempts_total),
                result: Arc::clone(&result),
                done_tx: done_tx.clone(),
            };

            if sender.send(WorkerCommand::Mine(job)).is_ok() {
                active_workers += 1;
            }
        }

        drop(done_tx);

        for _ in 0..active_workers {
            let _ = done_rx.recv();
        }

        // SECURITY FIX: Remplacement de unwrap() par unwrap_or_default() + log
        // Un panic ici corromprait le résultat du mining
        if let Ok(mut guard) = result.lock() {
            if let Some(winner) = guard.take() {
                *block = winner;
            }
        }

        attempts_total.load(Ordering::Relaxed)
    }
}

impl Drop for MiningPool {
    fn drop(&mut self) {
        for sender in &self.senders {
            let _ = sender.send(WorkerCommand::Stop);
        }

        self.senders.clear();

        // SECURITY FIX: Gestion sécurisée du Mutex poisoning
        if let Ok(mut handles) = self.handles.lock() {
            for handle in handles.drain(..) {
                let _ = handle.join();
            }
        }
    }
}

fn run_mining_job(job: MineJob, worker_id: usize, jobs: usize) {
    let MineJob {
        mut template,
        found,
        attempts_total,
        result,
        done_tx,
    } = job;

    template.header.nonce = template.header.nonce.wrapping_add(worker_id as u64);

    let prefix = BlockHeaderHashPrefix::new_with_height(&template.header, template.height());
    let step = jobs as u64;
    let mut attempts = 0u64;

    loop {
        if found.load(Ordering::Relaxed) {
            break;
        }

        if prefix.meets_difficulty(
            template.header.timestamp,
            template.header.difficulty,
            template.header.nonce,
        ) {
            if !found.swap(true, Ordering::Relaxed) {
                // SECURITY FIX: Gestion sécurisée du Mutex poisoning
                if let Ok(mut guard) = result.lock() {
                    *guard = Some(template.clone());
                }
            }
            break;
        }

        template.header.nonce = template.header.nonce.wrapping_add(step);
        attempts += 1;

        if attempts % 1_000_000 == 0 {
            // SECURITY FIX: Remplacement de unwrap() par une gestion d'erreur sécurisée
            if let Ok(duration) = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH) {
                template.header.timestamp = duration.as_secs();
            }
        }
    }

    attempts_total.fetch_add(attempts, Ordering::Relaxed);
    let _ = done_tx.send(());
}

/// A miner that can be started and stopped.
pub struct Miner {
    running: std::sync::atomic::AtomicBool,
}

impl Miner {
    pub fn new() -> Self {
        Self {
            running: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn stop(&self) {
        self.running
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn start(&self) {
        self.running
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Default for Miner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_miner_state() {
        let miner = Miner::new();

        assert!(!miner.is_running());

        miner.start();
        assert!(miner.is_running());

        miner.stop();
        assert!(!miner.is_running());
    }
}