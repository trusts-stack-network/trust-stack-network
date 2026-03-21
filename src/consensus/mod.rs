mod difficulty;
pub mod poseidon_pow;
mod pow;
pub mod signature_validator;
pub mod upgrade;

pub use difficulty::{
    calculate_next_difficulty, calculate_stats, should_adjust_difficulty,
    DifficultyStats, ADJUSTMENT_INTERVAL, MAX_DIFFICULTY, MIN_DIFFICULTY,
    TARGET_BLOCK_TIME_SECS,
};
pub use poseidon_pow::{
    poseidon_hash_header, poseidon_hash_header_parts,
    poseidon_hash_header_for_height, poseidon_hash_header_legacy,
    hash_meets_difficulty,
};
pub use pow::{mine_block, mine_block_with_jobs, Miner, MiningPool, SimdMode};
