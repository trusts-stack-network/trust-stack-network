/// Difficulty adjustment algorithm for dynamic proof-of-work.
///
/// Uses numeric difficulty where the hash prefix (first 8 bytes as u64 big-endian)
/// must be less than u64::MAX / difficulty. Higher difficulty = harder mining.

/// Target time between blocks in seconds (default: 10 seconds for fast testing).
pub const TARGET_BLOCK_TIME_SECS: u64 = 10;

/// Number of blocks between difficulty adjustments.
pub const ADJUSTMENT_INTERVAL: u64 = 72;

/// Minimum numeric difficulty (prevents instant mining).
pub const MIN_DIFFICULTY: u64 = 1000;

/// Maximum numeric difficulty (prevents impossible mining).
pub const MAX_DIFFICULTY: u64 = u64::MAX / 2;

/// Maximum adjustment factor per interval (prevents wild swings).
/// Difficulty can change by at most ±25% per adjustment.
pub const MAX_ADJUSTMENT_RATIO: f64 = 1.25;

/// Calculate the next difficulty based on the last adjustment window.
///
/// Uses a multiplicative ratio clamped to ±25% per adjustment window.
/// If blocks are too fast, difficulty increases; if too slow, it decreases.
///
/// # Arguments
/// * `current_difficulty` - The current numeric difficulty target
/// * `first_block_time` - Timestamp of the first block in the adjustment window
/// * `last_block_time` - Timestamp of the last block in the adjustment window
/// * `blocks_in_window` - Number of blocks in this window (usually ADJUSTMENT_INTERVAL)
///
/// # Returns
/// The new difficulty value
pub fn calculate_next_difficulty(
    current_difficulty: u64,
    first_block_time: u64,
    last_block_time: u64,
    blocks_in_window: u64,
) -> u64 {
    // Actual time taken for the window
    let actual_time = last_block_time.saturating_sub(first_block_time);

    // Expected time for the window
    let expected_time = blocks_in_window * TARGET_BLOCK_TIME_SECS;

    // Avoid division by zero
    if actual_time == 0 {
        // Blocks are instant — increase difficulty by max ratio
        let new_diff = (current_difficulty as f64 * MAX_ADJUSTMENT_RATIO) as u64;
        return new_diff.clamp(MIN_DIFFICULTY, MAX_DIFFICULTY);
    }

    // Calculate adjustment ratio
    // If blocks are too fast (actual < expected), ratio > 1 → increase difficulty
    // If blocks are too slow (actual > expected), ratio < 1 → decrease difficulty
    let ratio = expected_time as f64 / actual_time as f64;

    // Clamp the ratio to ±25%
    let clamped_ratio = ratio.clamp(1.0 / MAX_ADJUSTMENT_RATIO, MAX_ADJUSTMENT_RATIO);

    // Apply multiplicative adjustment
    let new_difficulty = (current_difficulty as f64 * clamped_ratio) as u64;

    // Clamp to valid range
    new_difficulty.clamp(MIN_DIFFICULTY, MAX_DIFFICULTY)
}

/// Check if a difficulty adjustment is needed at this height.
pub fn should_adjust_difficulty(height: u64) -> bool {
    height > 0 && height % ADJUSTMENT_INTERVAL == 0
}

/// Statistics about recent block times for monitoring.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DifficultyStats {
    pub current_difficulty: u64,
    pub target_block_time: u64,
    pub average_block_time: f64,
    pub blocks_until_adjustment: u64,
    pub hash_rate_estimate: f64,
}

/// Calculate difficulty statistics from recent blocks.
pub fn calculate_stats(
    current_difficulty: u64,
    current_height: u64,
    recent_timestamps: &[u64],
) -> DifficultyStats {
    let blocks_until_adjustment = ADJUSTMENT_INTERVAL - (current_height % ADJUSTMENT_INTERVAL);

    let average_block_time = if recent_timestamps.len() >= 2 {
        let time_span = recent_timestamps.last().unwrap_or(&0)
            .saturating_sub(*recent_timestamps.first().unwrap_or(&0));
        time_span as f64 / (recent_timestamps.len() - 1) as f64
    } else {
        TARGET_BLOCK_TIME_SECS as f64
    };

    // Estimate hash rate: difficulty / average_block_time
    // (on average, `difficulty` hashes are needed to find a valid one)
    let hash_rate_estimate = if average_block_time > 0.0 {
        current_difficulty as f64 / average_block_time
    } else {
        0.0
    };

    DifficultyStats {
        current_difficulty,
        target_block_time: TARGET_BLOCK_TIME_SECS,
        average_block_time,
        blocks_until_adjustment,
        hash_rate_estimate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_difficulty_increase_when_blocks_too_fast() {
        // Blocks are coming twice as fast as expected
        let current_difficulty = 10000;
        let first_time = 1000;
        let last_time = 1360; // 360 seconds for 72 blocks = 5s per block (target is 10s)

        let new_difficulty = calculate_next_difficulty(
            current_difficulty,
            first_time,
            last_time,
            ADJUSTMENT_INTERVAL,
        );

        assert!(new_difficulty > current_difficulty,
            "Difficulty should increase when blocks are too fast: {} vs {}", new_difficulty, current_difficulty);
    }

    #[test]
    fn test_difficulty_decrease_when_blocks_too_slow() {
        // Blocks are coming twice as slow as expected
        let current_difficulty = 10000;
        let first_time = 1000;
        let last_time = 2440; // 1440 seconds for 72 blocks = 20s per block (target is 10s)

        let new_difficulty = calculate_next_difficulty(
            current_difficulty,
            first_time,
            last_time,
            ADJUSTMENT_INTERVAL,
        );

        assert!(new_difficulty < current_difficulty,
            "Difficulty should decrease when blocks are too slow: {} vs {}", new_difficulty, current_difficulty);
    }

    #[test]
    fn test_difficulty_stable_when_on_target() {
        let current_difficulty = 10000;
        let first_time = 1000;
        let last_time = 1720; // 720 seconds for 72 blocks = 10s per block (exactly on target)

        let new_difficulty = calculate_next_difficulty(
            current_difficulty,
            first_time,
            last_time,
            ADJUSTMENT_INTERVAL,
        );

        assert_eq!(new_difficulty, current_difficulty,
            "Difficulty should stay the same when on target");
    }

    #[test]
    fn test_difficulty_respects_minimum() {
        let current_difficulty = MIN_DIFFICULTY;
        let first_time = 1000;
        let last_time = 100000; // Very slow blocks

        let new_difficulty = calculate_next_difficulty(
            current_difficulty,
            first_time,
            last_time,
            ADJUSTMENT_INTERVAL,
        );

        assert!(new_difficulty >= MIN_DIFFICULTY,
            "Difficulty should not go below minimum");
    }

    #[test]
    fn test_difficulty_respects_maximum() {
        let current_difficulty = MAX_DIFFICULTY;
        let first_time = 1000;
        let last_time = 1001; // Extremely fast blocks

        let new_difficulty = calculate_next_difficulty(
            current_difficulty,
            first_time,
            last_time,
            ADJUSTMENT_INTERVAL,
        );

        assert!(new_difficulty <= MAX_DIFFICULTY,
            "Difficulty should not go above maximum");
    }

    #[test]
    fn test_should_adjust_difficulty() {
        assert!(!should_adjust_difficulty(0), "No adjustment at genesis");
        assert!(!should_adjust_difficulty(1));
        assert!(!should_adjust_difficulty(71));
        assert!(should_adjust_difficulty(72));
        assert!(!should_adjust_difficulty(73));
        assert!(should_adjust_difficulty(144));
    }

    #[test]
    fn test_max_adjustment_factor() {
        // Even with extremely fast blocks, difficulty can only increase by 25%
        let current_difficulty = 10000;
        let first_time = 1000;
        let last_time = 1001; // Nearly instant blocks

        let new_difficulty = calculate_next_difficulty(
            current_difficulty,
            first_time,
            last_time,
            ADJUSTMENT_INTERVAL,
        );

        let max_allowed = (current_difficulty as f64 * MAX_ADJUSTMENT_RATIO) as u64;
        assert!(new_difficulty <= max_allowed,
            "Adjustment should be limited by MAX_ADJUSTMENT_RATIO: {} vs max {}", new_difficulty, max_allowed);
    }
}
