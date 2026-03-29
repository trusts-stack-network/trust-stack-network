/// LWMA (Linearly Weighted Moving Average) difficulty adjustment algorithm.
///
/// Inspired by Monero (2018+), Zcash, Beam, Grin.
/// Adjusts difficulty at EVERY block using a weighted moving average where
/// recent blocks have more influence. This provides fast reaction to hashrate
/// changes (~10 min for 100x spike) without oscillation.
///
/// Previous algorithm: Bitcoin-style fixed interval (720 blocks = 2h).
/// Problem: 100x hashrate spike took ~10h (5 cycles) to adjust.
/// LWMA fixes this by adjusting per-block with linear weights.

/// Target time between blocks in seconds.
pub const TARGET_BLOCK_TIME_SECS: u64 = 10;

/// LWMA window size: number of recent blocks to consider.
/// 45 blocks × 10s = 7.5 min of history. Balances reactivity vs stability.
/// Monero uses N=60, we use N=45 for faster reaction during bootstrap phase.
pub const LWMA_WINDOW: u64 = 45;

/// Maximum solvetime per block (prevents timestamp manipulation).
/// Capped at 6× target to limit influence of slow blocks.
pub const SOLVETIME_CAP: u64 = 6 * TARGET_BLOCK_TIME_SECS;

/// Minimum numeric difficulty (prevents instant mining).
/// At 150 KH/s with 1 miner, 1_500_000 yields ~10s blocks.
pub const MIN_DIFFICULTY: u64 = 1_500_000;

/// Maximum numeric difficulty (prevents impossible mining).
pub const MAX_DIFFICULTY: u64 = u64::MAX / 2;

// Legacy exports for backward compatibility with code that references these
pub const ADJUSTMENT_INTERVAL: u64 = LWMA_WINDOW;

/// Calculate the next difficulty using LWMA (per-block adjustment).
///
/// # Arguments
/// * `recent_difficulties` - Difficulties of the last N blocks (oldest first)
/// * `recent_timestamps` - Timestamps of the last N+1 blocks (oldest first)
///   (N+1 because we need the timestamp before the window to compute solvetime of first block)
///
/// # Returns
/// The new difficulty value for the next block.
pub fn calculate_next_difficulty_lwma(
    recent_difficulties: &[u64],
    recent_timestamps: &[u64],
) -> u64 {
    let n = recent_difficulties.len();

    // Not enough data — keep current difficulty
    if n < 3 || recent_timestamps.len() < n + 1 {
        return recent_difficulties.last().copied().unwrap_or(MIN_DIFFICULTY).max(MIN_DIFFICULTY);
    }

    // M5 audit fix: use u128 integer arithmetic instead of f64 to prevent
    // precision loss at high difficulty values (f64 has 53-bit mantissa,
    // u64 values near u64::MAX/2 lose precision).
    let mut weighted_solvetimes: u128 = 0;
    let mut sum_weights: u128 = 0;
    let mut difficulty_sum: u128 = 0;

    for i in 0..n {
        let weight = (i + 1) as u128; // 1, 2, 3, ..., N

        // Solvetime between consecutive blocks, capped to prevent manipulation
        let solvetime = recent_timestamps[i + 1]
            .saturating_sub(recent_timestamps[i])
            .min(SOLVETIME_CAP) as u128;

        weighted_solvetimes += solvetime * weight;
        sum_weights += weight;
        difficulty_sum += recent_difficulties[i] as u128;
    }

    // Avoid division by zero — if blocks are near-instant, max increase 4x
    if weighted_solvetimes == 0 {
        let avg = difficulty_sum / n as u128;
        return (avg.saturating_mul(4)).min(MAX_DIFFICULTY as u128) as u64;
    }

    // New difficulty = (avg_difficulty * target_time * sum_weights) / (weighted_solvetimes * n)
    // Rearranged to avoid intermediate overflow: (difficulty_sum * target * sum_weights) / (weighted_solvetimes * n * n)
    // Simplified: (difficulty_sum * target) / (weighted_solvetimes * n / sum_weights)
    // Actually: new_diff = (difficulty_sum / n) * (target * sum_weights / weighted_solvetimes)
    let target = TARGET_BLOCK_TIME_SECS as u128;
    let n128 = n as u128;

    // avg_difficulty * target / lwma = (difficulty_sum * target * sum_weights) / (n * weighted_solvetimes)
    let numerator = difficulty_sum * target * sum_weights;
    let denominator = n128 * weighted_solvetimes;

    let new_difficulty = numerator / denominator;

    (new_difficulty as u64).clamp(MIN_DIFFICULTY, MAX_DIFFICULTY)
}

/// Legacy wrapper — called by existing code that uses the old interface.
/// This is kept for backward compatibility; new code should call calculate_next_difficulty_lwma.
pub fn calculate_next_difficulty(
    current_difficulty: u64,
    first_block_time: u64,
    last_block_time: u64,
    blocks_in_window: u64,
) -> u64 {
    // Fallback to simple ratio-based adjustment when LWMA data is not available
    let actual_time = last_block_time.saturating_sub(first_block_time);
    let expected_time = blocks_in_window * TARGET_BLOCK_TIME_SECS;

    if actual_time == 0 {
        let new_diff = (current_difficulty as f64 * 4.0) as u64;
        return new_diff.clamp(MIN_DIFFICULTY, MAX_DIFFICULTY);
    }

    let ratio = expected_time as f64 / actual_time as f64;
    let clamped_ratio = ratio.clamp(0.25, 4.0);
    let new_difficulty = (current_difficulty as f64 * clamped_ratio) as u64;
    new_difficulty.clamp(MIN_DIFFICULTY, MAX_DIFFICULTY)
}

/// LWMA adjusts at every block — always returns true (except genesis).
pub fn should_adjust_difficulty(height: u64) -> bool {
    height > 0
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
    _current_height: u64,
    recent_timestamps: &[u64],
) -> DifficultyStats {
    let average_block_time = if recent_timestamps.len() >= 2 {
        let time_span = recent_timestamps.last().unwrap_or(&0)
            .saturating_sub(*recent_timestamps.first().unwrap_or(&0));
        time_span as f64 / (recent_timestamps.len() - 1) as f64
    } else {
        TARGET_BLOCK_TIME_SECS as f64
    };

    let hash_rate_estimate = if average_block_time > 0.0 {
        current_difficulty as f64 / average_block_time
    } else {
        0.0
    };

    DifficultyStats {
        current_difficulty,
        target_block_time: TARGET_BLOCK_TIME_SECS,
        average_block_time,
        blocks_until_adjustment: 1, // LWMA adjusts every block
        hash_rate_estimate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lwma_difficulty_increase_when_blocks_too_fast() {
        // 45 blocks at 5s each (target is 10s) → difficulty should ~double
        let n = 45;
        let base_diff: u64 = 3_000_000;
        let difficulties: Vec<u64> = vec![base_diff; n];
        let timestamps: Vec<u64> = (0..=n).map(|i| 1000 + i as u64 * 5).collect();

        let new_diff = calculate_next_difficulty_lwma(&difficulties, &timestamps);
        assert!(new_diff > base_diff, "Should increase: got {}", new_diff);
        assert!(new_diff > base_diff * 18 / 10, "Should roughly double: got {}", new_diff);
    }

    #[test]
    fn test_lwma_difficulty_decrease_when_blocks_too_slow() {
        // 45 blocks at 20s each (target is 10s) → difficulty should ~halve
        let n = 45;
        let base_diff: u64 = 3_000_000;
        let difficulties: Vec<u64> = vec![base_diff; n];
        let timestamps: Vec<u64> = (0..=n).map(|i| 1000 + i as u64 * 20).collect();

        let new_diff = calculate_next_difficulty_lwma(&difficulties, &timestamps);
        assert!(new_diff < base_diff, "Should decrease: got {}", new_diff);
        assert!(new_diff < base_diff * 6 / 10, "Should roughly halve: got {}", new_diff);
    }

    #[test]
    fn test_lwma_difficulty_stable_when_on_target() {
        // 45 blocks at exactly 10s each → difficulty should stay the same
        let n = 45;
        let base_diff: u64 = 3_000_000;
        let difficulties: Vec<u64> = vec![base_diff; n];
        let timestamps: Vec<u64> = (0..=n).map(|i| 1000 + i as u64 * 10).collect();

        let new_diff = calculate_next_difficulty_lwma(&difficulties, &timestamps);
        assert!((new_diff as i64 - base_diff as i64).abs() < (base_diff as i64 / 100),
            "Should be stable: got {} (expected ~{})", new_diff, base_diff);
    }

    #[test]
    fn test_lwma_respects_minimum() {
        let n = 45;
        let difficulties: Vec<u64> = vec![MIN_DIFFICULTY; n];
        let timestamps: Vec<u64> = (0..=n).map(|i| 1000 + i as u64 * 100).collect();

        let new_diff = calculate_next_difficulty_lwma(&difficulties, &timestamps);
        assert!(new_diff >= MIN_DIFFICULTY, "Should not go below min: got {}", new_diff);
    }

    #[test]
    fn test_lwma_respects_maximum() {
        let n = 45;
        let difficulties: Vec<u64> = vec![MAX_DIFFICULTY; n];
        let timestamps: Vec<u64> = (0..=n).map(|i| 1000 + i as u64 * 1).collect();

        let new_diff = calculate_next_difficulty_lwma(&difficulties, &timestamps);
        assert!(new_diff <= MAX_DIFFICULTY, "Should not exceed max: got {}", new_diff);
    }

    #[test]
    fn test_lwma_recent_blocks_weighted_more() {
        // First 30 blocks at 10s, last 15 at 2s → should increase more than simple average
        let n = 45;
        let base_diff: u64 = 3_000_000;
        let difficulties: Vec<u64> = vec![base_diff; n];
        let mut timestamps: Vec<u64> = Vec::new();
        let mut t = 1000u64;
        timestamps.push(t);
        for i in 0..n {
            t += if i < 30 { 10 } else { 2 };
            timestamps.push(t);
        }

        let new_diff = calculate_next_difficulty_lwma(&difficulties, &timestamps);
        // Recent blocks are fast → LWMA should weight them more → higher difficulty
        assert!(new_diff > base_diff * 12 / 10, "Recent fast blocks should pull difficulty up: got {}", new_diff);
    }

    #[test]
    fn test_should_adjust_difficulty_every_block() {
        assert!(!should_adjust_difficulty(0), "No adjustment at genesis");
        assert!(should_adjust_difficulty(1));
        assert!(should_adjust_difficulty(2));
        assert!(should_adjust_difficulty(100));
        assert!(should_adjust_difficulty(999));
    }

    // Legacy interface test
    #[test]
    fn test_legacy_calculate_next_difficulty() {
        let new_diff = calculate_next_difficulty(10000, 1000, 1360, 72);
        assert!(new_diff > 10000, "Should increase when blocks fast");
    }
}
