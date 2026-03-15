/// Advanced consensus metrics for Trust Stack Network.
///
/// This module provides comprehensive monitoring of consensus health including:
/// - Inter-block timing analysis
/// - Orphan block rate tracking
/// - Difficulty distribution monitoring
/// - Mining efficiency metrics
/// - Hash rate estimation and stability

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

/// Maximum number of blocks to keep in memory for metrics calculation.
const MAX_BLOCKS_HISTORY: usize = 1000;

/// Time window for calculating short-term metrics (in seconds).
const SHORT_TERM_WINDOW_SECS: u64 = 300; // 5 minutes

/// Time window for calculating long-term metrics (in seconds).
const LONG_TERM_WINDOW_SECS: u64 = 3600; // 1 hour

/// Comprehensive consensus metrics structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusMetrics {
    /// Current blockchain height
    pub height: u64,
    
    /// Inter-block timing metrics
    pub timing: BlockTimingMetrics,
    
    /// Orphan block statistics
    pub orphans: OrphanMetrics,
    
    /// Difficulty adjustment metrics
    pub difficulty: DifficultyMetrics,
    
    /// Mining performance metrics
    pub mining: MiningMetrics,
    
    /// Network health indicators
    pub network: NetworkHealthMetrics,
    
    /// Timestamp of last update
    pub last_updated: u64,
}

/// Block timing analysis metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTimingMetrics {
    /// Average time between blocks (seconds)
    pub avg_block_time: f64,
    
    /// Median time between blocks (seconds)
    pub median_block_time: f64,
    
    /// Standard deviation of block times
    pub block_time_stddev: f64,
    
    /// Minimum block time in current window
    pub min_block_time: f64,
    
    /// Maximum block time in current window
    pub max_block_time: f64,
    
    /// Target block time (from difficulty module)
    pub target_block_time: f64,
    
    /// Percentage deviation from target
    pub deviation_from_target: f64,
    
    /// Number of blocks analyzed
    pub sample_size: usize,
}

/// Orphan block tracking metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrphanMetrics {
    /// Total number of orphan blocks detected
    pub total_orphans: u64,
    
    /// Orphan rate (orphans per 100 blocks)
    pub orphan_rate: f64,
    
    /// Recent orphan rate (last hour)
    pub recent_orphan_rate: f64,
    
    /// Average depth of orphan chains
    pub avg_orphan_depth: f64,
    
    /// Longest orphan chain seen
    pub max_orphan_depth: u64,
    
    /// Time since last orphan block
    pub time_since_last_orphan: u64,
}

/// Difficulty adjustment and distribution metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifficultyMetrics {
    /// Current difficulty
    pub current_difficulty: u64,
    
    /// Average difficulty over time window
    pub avg_difficulty: f64,
    
    /// Difficulty volatility (standard deviation)
    pub difficulty_volatility: f64,
    
    /// Number of difficulty adjustments in window
    pub adjustments_count: u32,
    
    /// Average adjustment magnitude
    pub avg_adjustment_magnitude: f64,
    
    /// Largest difficulty increase
    pub max_difficulty_increase: f64,
    
    /// Largest difficulty decrease
    pub max_difficulty_decrease: f64,
    
    /// Time until next adjustment
    pub blocks_until_adjustment: u64,
}

/// Mining performance and efficiency metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningMetrics {
    /// Estimated network hash rate (hashes/second)
    pub estimated_hashrate: f64,
    
    /// Hash rate stability (coefficient of variation)
    pub hashrate_stability: f64,
    
    /// Mining efficiency (blocks per unit time vs expected)
    pub mining_efficiency: f64,
    
    /// Average work per block
    pub avg_work_per_block: f64,
    
    /// Total cumulative work
    pub total_work: f64,
    
    /// Hash rate trend (positive = increasing, negative = decreasing)
    pub hashrate_trend: f64,
    
    /// Distribution of block times (histogram)
    pub block_time_distribution: HashMap<String, u32>,
}

/// Network health and consensus stability metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHealthMetrics {
    /// Chain stability score (0-100)
    pub stability_score: f64,
    
    /// Fork frequency (forks per 100 blocks)
    pub fork_frequency: f64,
    
    /// Average fork resolution time
    pub avg_fork_resolution_time: f64,
    
    /// Consensus participation rate
    pub consensus_participation: f64,
    
    /// Network synchronization health
    pub sync_health: f64,
    
    /// Time since last major reorganization
    pub time_since_last_reorg: u64,
}

/// Historical block data for metrics calculation.
#[derive(Debug, Clone)]
pub struct BlockData {
    pub height: u64,
    pub timestamp: u64,
    pub difficulty: u64,
    pub hash: String,
    pub parent_hash: String,
    pub is_orphan: bool,
    pub work: f64,
}

/// Metrics calculator and aggregator.
pub struct ConsensusMetricsCalculator {
    /// Historical block data
    blocks: VecDeque<BlockData>,
    
    /// Orphan blocks tracking
    orphan_blocks: VecDeque<BlockData>,
    
    /// Difficulty adjustment history
    difficulty_adjustments: VecDeque<(u64, u64, u64)>, // (height, old_diff, new_diff)
    
    /// Fork events tracking
    fork_events: VecDeque<(u64, u64)>, // (timestamp, resolution_time)
}

impl ConsensusMetricsCalculator {
    /// Create a new metrics calculator.
    pub fn new() -> Self {
        Self {
            blocks: VecDeque::with_capacity(MAX_BLOCKS_HISTORY),
            orphan_blocks: VecDeque::with_capacity(MAX_BLOCKS_HISTORY / 10),
            difficulty_adjustments: VecDeque::with_capacity(100),
            fork_events: VecDeque::with_capacity(100),
        }
    }

    /// Add a new block to the metrics calculation.
    pub fn add_block(&mut self, block: BlockData) {
        // Maintain size limit
        if self.blocks.len() >= MAX_BLOCKS_HISTORY {
            self.blocks.pop_front();
        }
        
        self.blocks.push_back(block);
    }

    /// Record an orphan block.
    pub fn add_orphan_block(&mut self, block: BlockData) {
        if self.orphan_blocks.len() >= MAX_BLOCKS_HISTORY / 10 {
            self.orphan_blocks.pop_front();
        }
        
        self.orphan_blocks.push_back(block);
    }

    /// Record a difficulty adjustment.
    pub fn record_difficulty_adjustment(&mut self, height: u64, old_difficulty: u64, new_difficulty: u64) {
        if self.difficulty_adjustments.len() >= 100 {
            self.difficulty_adjustments.pop_front();
        }
        
        self.difficulty_adjustments.push_back((height, old_difficulty, new_difficulty));
    }

    /// Record a fork event.
    pub fn record_fork_event(&mut self, timestamp: u64, resolution_time: u64) {
        if self.fork_events.len() >= 100 {
            self.fork_events.pop_front();
        }
        
        self.fork_events.push_back((timestamp, resolution_time));
    }

    /// Calculate comprehensive consensus metrics.
    pub fn calculate_metrics(&self) -> ConsensusMetrics {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        ConsensusMetrics {
            height: self.blocks.back().map(|b| b.height).unwrap_or(0),
            timing: self.calculate_timing_metrics(),
            orphans: self.calculate_orphan_metrics(),
            difficulty: self.calculate_difficulty_metrics(),
            mining: self.calculate_mining_metrics(),
            network: self.calculate_network_health_metrics(),
            last_updated: now,
        }
    }

    /// Calculate block timing metrics.
    fn calculate_timing_metrics(&self) -> BlockTimingMetrics {
        if self.blocks.len() < 2 {
            return BlockTimingMetrics {
                avg_block_time: 0.0,
                median_block_time: 0.0,
                block_time_stddev: 0.0,
                min_block_time: 0.0,
                max_block_time: 0.0,
                target_block_time: crate::consensus::difficulty::TARGET_BLOCK_TIME_SECS as f64,
                deviation_from_target: 0.0,
                sample_size: 0,
            };
        }

        let mut block_times = Vec::new();
        let blocks: Vec<_> = self.blocks.iter().collect();
        
        for i in 1..blocks.len() {
            let time_diff = blocks[i].timestamp.saturating_sub(blocks[i-1].timestamp);
            if time_diff > 0 && time_diff < 3600 { // Ignore unrealistic times
                block_times.push(time_diff as f64);
            }
        }

        if block_times.is_empty() {
            return BlockTimingMetrics {
                avg_block_time: 0.0,
                median_block_time: 0.0,
                block_time_stddev: 0.0,
                min_block_time: 0.0,
                max_block_time: 0.0,
                target_block_time: crate::consensus::difficulty::TARGET_BLOCK_TIME_SECS as f64,
                deviation_from_target: 0.0,
                sample_size: 0,
            };
        }

        let avg = block_times.iter().sum::<f64>() / block_times.len() as f64;
        
        block_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = if block_times.len() % 2 == 0 {
            (block_times[block_times.len() / 2 - 1] + block_times[block_times.len() / 2]) / 2.0
        } else {
            block_times[block_times.len() / 2]
        };

        let variance = block_times.iter()
            .map(|&x| (x - avg).powi(2))
            .sum::<f64>() / block_times.len() as f64;
        let stddev = variance.sqrt();

        let min_time = block_times.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_time = block_times.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        
        let target = crate::consensus::difficulty::TARGET_BLOCK_TIME_SECS as f64;
        let deviation = ((avg - target) / target * 100.0).abs();

        BlockTimingMetrics {
            avg_block_time: avg,
            median_block_time: median,
            block_time_stddev: stddev,
            min_block_time: min_time,
            max_block_time: max_time,
            target_block_time: target,
            deviation_from_target: deviation,
            sample_size: block_times.len(),
        }
    }

    /// Calculate orphan block metrics.
    fn calculate_orphan_metrics(&self) -> OrphanMetrics {
        let total_orphans = self.orphan_blocks.len() as u64;
        let total_blocks = self.blocks.len() as u64;
        
        let orphan_rate = if total_blocks > 0 {
            (total_orphans as f64 / total_blocks as f64) * 100.0
        } else {
            0.0
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Recent orphan rate (last hour)
        let recent_orphans = self.orphan_blocks.iter()
            .filter(|b| now.saturating_sub(b.timestamp) <= LONG_TERM_WINDOW_SECS)
            .count() as f64;
        
        let recent_blocks = self.blocks.iter()
            .filter(|b| now.saturating_sub(b.timestamp) <= LONG_TERM_WINDOW_SECS)
            .count() as f64;

        let recent_orphan_rate = if recent_blocks > 0.0 {
            (recent_orphans / recent_blocks) * 100.0
        } else {
            0.0
        };

        let time_since_last_orphan = self.orphan_blocks.back()
            .map(|b| now.saturating_sub(b.timestamp))
            .unwrap_or(u64::MAX);

        OrphanMetrics {
            total_orphans,
            orphan_rate,
            recent_orphan_rate,
            avg_orphan_depth: 1.0, // Simplified for now
            max_orphan_depth: 1,   // Simplified for now
            time_since_last_orphan,
        }
    }

    /// Calculate difficulty metrics.
    fn calculate_difficulty_metrics(&self) -> DifficultyMetrics {
        let current_difficulty = self.blocks.back()
            .map(|b| b.difficulty)
            .unwrap_or(crate::consensus::difficulty::MIN_DIFFICULTY);

        let difficulties: Vec<f64> = self.blocks.iter()
            .map(|b| b.difficulty as f64)
            .collect();

        let avg_difficulty = if !difficulties.is_empty() {
            difficulties.iter().sum::<f64>() / difficulties.len() as f64
        } else {
            current_difficulty as f64
        };

        let difficulty_variance = if difficulties.len() > 1 {
            let mean = avg_difficulty;
            difficulties.iter()
                .map(|&x| (x - mean).powi(2))
                .sum::<f64>() / (difficulties.len() - 1) as f64
        } else {
            0.0
        };

        let difficulty_volatility = difficulty_variance.sqrt();

        let adjustments_count = self.difficulty_adjustments.len() as u32;
        
        let avg_adjustment_magnitude = if !self.difficulty_adjustments.is_empty() {
            self.difficulty_adjustments.iter()
                .map(|(_, old, new)| (*new as f64 - *old as f64).abs())
                .sum::<f64>() / adjustments_count as f64
        } else {
            0.0
        };

        let (max_increase, max_decrease) = self.difficulty_adjustments.iter()
            .fold((0.0, 0.0), |(max_inc, max_dec), (_, old, new)| {
                let change = *new as f64 - *old as f64;
                (max_inc.max(change), max_dec.min(change).abs())
            });

        let current_height = self.blocks.back().map(|b| b.height).unwrap_or(0);
        let blocks_until_adjustment = crate::consensus::difficulty::ADJUSTMENT_INTERVAL
            - (current_height % crate::consensus::difficulty::ADJUSTMENT_INTERVAL);

        DifficultyMetrics {
            current_difficulty,
            avg_difficulty,
            difficulty_volatility,
            adjustments_count,
            avg_adjustment_magnitude,
            max_difficulty_increase: max_increase,
            max_difficulty_decrease: max_decrease,
            blocks_until_adjustment,
        }
    }

    /// Calculate mining performance metrics.
    fn calculate_mining_metrics(&self) -> MiningMetrics {
        let timing = self.calculate_timing_metrics();
        
        let estimated_hashrate = if timing.avg_block_time > 0.0 {
            let current_difficulty = self.blocks.back()
                .map(|b| b.difficulty)
                .unwrap_or(crate::consensus::difficulty::MIN_DIFFICULTY);
            2_f64.powi(current_difficulty as i32) / timing.avg_block_time
        } else {
            0.0
        };

        // Calculate hashrate stability using coefficient of variation
        let hashrates: Vec<f64> = self.blocks.windows(2)
            .map(|window| {
                let time_diff = window[1].timestamp.saturating_sub(window[0].timestamp) as f64;
                if time_diff > 0.0 {
                    2_f64.powi(window[1].difficulty as i32) / time_diff
                } else {
                    0.0
                }
            })
            .filter(|&hr| hr > 0.0)
            .collect();

        let hashrate_stability = if hashrates.len() > 1 {
            let mean = hashrates.iter().sum::<f64>() / hashrates.len() as f64;
            let variance = hashrates.iter()
                .map(|&x| (x - mean).powi(2))
                .sum::<f64>() / (hashrates.len() - 1) as f64;
            let stddev = variance.sqrt();
            if mean > 0.0 { stddev / mean } else { 0.0 }
        } else {
            0.0
        };

        let target_time = crate::consensus::difficulty::TARGET_BLOCK_TIME_SECS as f64;
        let mining_efficiency = if timing.avg_block_time > 0.0 {
            target_time / timing.avg_block_time
        } else {
            0.0
        };

        let total_work = self.blocks.iter()
            .map(|b| b.work)
            .sum::<f64>();

        let avg_work_per_block = if !self.blocks.is_empty() {
            total_work / self.blocks.len() as f64
        } else {
            0.0
        };

        // Simple trend calculation (positive = increasing)
        let hashrate_trend = if hashrates.len() >= 10 {
            let recent = &hashrates[hashrates.len()-5..];
            let older = &hashrates[hashrates.len()-10..hashrates.len()-5];
            let recent_avg = recent.iter().sum::<f64>() / recent.len() as f64;
            let older_avg = older.iter().sum::<f64>() / older.len() as f64;
            if older_avg > 0.0 {
                (recent_avg - older_avg) / older_avg
            } else {
                0.0
            }
        } else {
            0.0
        };

        // Create block time distribution histogram
        let mut distribution = HashMap::new();
        let block_times: Vec<u64> = self.blocks.windows(2)
            .map(|w| w[1].timestamp.saturating_sub(w[0].timestamp))
            .collect();

        for &time in &block_times {
            let bucket = match time {
                0..=5 => "0-5s",
                6..=10 => "6-10s",
                11..=20 => "11-20s",
                21..=30 => "21-30s",
                31..=60 => "31-60s",
                _ => ">60s",
            };
            *distribution.entry(bucket.to_string()).or_insert(0) += 1;
        }

        MiningMetrics {
            estimated_hashrate,
            hashrate_stability,
            mining_efficiency,
            avg_work_per_block,
            total_work,
            hashrate_trend,
            block_time_distribution: distribution,
        }
    }

    /// Calculate network health metrics.
    fn calculate_network_health_metrics(&self) -> NetworkHealthMetrics {
        let timing = self.calculate_timing_metrics();
        let orphan = self.calculate_orphan_metrics();
        
        // Stability score based on multiple factors
        let timing_score = if timing.deviation_from_target < 10.0 { 100.0 } 
                          else { (100.0 - timing.deviation_from_target).max(0.0) };
        
        let orphan_score = if orphan.orphan_rate < 1.0 { 100.0 }
                          else { (100.0 - orphan.orphan_rate * 10.0).max(0.0) };
        
        let stability_score = (timing_score + orphan_score) / 2.0;

        let fork_frequency = self.fork_events.len() as f64 / 
                           (self.blocks.len().max(1) as f64) * 100.0;

        let avg_fork_resolution_time = if !self.fork_events.is_empty() {
            self.fork_events.iter()
                .map(|(_, resolution)| *resolution as f64)
                .sum::<f64>() / self.fork_events.len() as f64
        } else {
            0.0
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let time_since_last_reorg = self.fork_events.back()
            .map(|(timestamp, _)| now.saturating_sub(*timestamp))
            .unwrap_or(u64::MAX);

        NetworkHealthMetrics {
            stability_score,
            fork_frequency,
            avg_fork_resolution_time,
            consensus_participation: 95.0, // Placeholder - would need peer data
            sync_health: 98.0,             // Placeholder - would need sync data
            time_since_last_reorg,
        }
    }
}

impl Default for ConsensusMetricsCalculator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_calculator_creation() {
        let calculator = ConsensusMetricsCalculator::new();
        assert_eq!(calculator.blocks.len(), 0);
        assert_eq!(calculator.orphan_blocks.len(), 0);
    }

    #[test]
    fn test_add_block() {
        let mut calculator = ConsensusMetricsCalculator::new();
        
        let block = BlockData {
            height: 1,
            timestamp: 1000,
            difficulty: 16,
            hash: "test_hash".to_string(),
            parent_hash: "parent_hash".to_string(),
            is_orphan: false,
            work: 65536.0,
        };

        calculator.add_block(block);
        assert_eq!(calculator.blocks.len(), 1);
    }

    #[test]
    fn test_timing_metrics_calculation() {
        let mut calculator = ConsensusMetricsCalculator::new();
        
        // Add blocks with 10-second intervals
        for i in 0..10 {
            let block = BlockData {
                height: i,
                timestamp: 1000 + i * 10,
                difficulty: 16,
                hash: format!("hash_{}", i),
                parent_hash: format!("parent_{}", i.saturating_sub(1)),
                is_orphan: false,
                work: 65536.0,
            };
            calculator.add_block(block);
        }

        let timing = calculator.calculate_timing_metrics();
        assert_eq!(timing.avg_block_time, 10.0);
        assert_eq!(timing.median_block_time, 10.0);
        assert_eq!(timing.sample_size, 9);
    }

    #[test]
    fn test_orphan_metrics() {
        let mut calculator = ConsensusMetricsCalculator::new();
        
        // Add normal blocks
        for i in 0..10 {
            let block = BlockData {
                height: i,
                timestamp: 1000 + i * 10,
                difficulty: 16,
                hash: format!("hash_{}", i),
                parent_hash: format!("parent_{}", i.saturating_sub(1)),
                is_orphan: false,
                work: 65536.0,
            };
            calculator.add_block(block);
        }

        // Add orphan block
        let orphan = BlockData {
            height: 5,
            timestamp: 1055,
            difficulty: 16,
            hash: "orphan_hash".to_string(),
            parent_hash: "orphan_parent".to_string(),
            is_orphan: true,
            work: 65536.0,
        };
        calculator.add_orphan_block(orphan);

        let orphan_metrics = calculator.calculate_orphan_metrics();
        assert_eq!(orphan_metrics.total_orphans, 1);
        assert_eq!(orphan_metrics.orphan_rate, 10.0); // 1 orphan out of 10 blocks
    }

    #[test]
    fn test_difficulty_adjustment_tracking() {
        let mut calculator = ConsensusMetricsCalculator::new();
        
        calculator.record_difficulty_adjustment(10, 16, 18);
        calculator.record_difficulty_adjustment(20, 18, 16);
        
        let difficulty_metrics = calculator.calculate_difficulty_metrics();
        assert_eq!(difficulty_metrics.adjustments_count, 2);
        assert_eq!(difficulty_metrics.avg_adjustment_magnitude, 2.0);
    }

    #[test]
    fn test_comprehensive_metrics() {
        let mut calculator = ConsensusMetricsCalculator::new();
        
        // Add some test data
        for i in 0..20 {
            let block = BlockData {
                height: i,
                timestamp: 1000 + i * 10,
                difficulty: 16 + (i % 3), // Varying difficulty
                hash: format!("hash_{}", i),
                parent_hash: format!("parent_{}", i.saturating_sub(1)),
                is_orphan: false,
                work: (65536.0 * (1.0 + i as f64 * 0.1)),
            };
            calculator.add_block(block);
        }

        let metrics = calculator.calculate_metrics();
        assert_eq!(metrics.height, 19);
        assert!(metrics.timing.avg_block_time > 0.0);
        assert!(metrics.mining.estimated_hashrate > 0.0);
        assert!(metrics.network.stability_score > 0.0);
    }
}