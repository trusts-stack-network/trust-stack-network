// ZST — Erreurs du protocole

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StablecoinError {
    #[error("Reserve ratio too low: {current} bps < {minimum} bps")]
    ReserveRatioTooLow { current: u64, minimum: u64 },

    #[error("Reserve ratio too high for ZRS mint: {current} bps > {maximum} bps")]
    ReserveRatioTooHigh { current: u64, maximum: u64 },

    #[error("Reserve ratio too low for ZRS burn: {current} bps < {minimum} bps")]
    ReserveRatioTooLowForBurnZrs { current: u64, minimum: u64 },

    #[error("Oracle price stale: age {age_secs}s > max {max_secs}s")]
    OraclePriceStale { age_secs: u64, max_secs: u64 },

    #[error("Oracle quorum not met: {count}/{required}")]
    OracleQuorumNotMet { count: u8, required: u8 },

    #[error("Oracle price deviation too high: {deviation_bps} bps")]
    OracleDeviationTooHigh { deviation_bps: u64 },

    #[error("Oracle price circuit breaker: {change_bps} bps change in 1h > {max_bps} bps")]
    OracleCircuitBreaker { change_bps: u64, max_bps: u64 },

    #[error("Circuit breaker active until timestamp {until_timestamp}")]
    CircuitBreakerActive { until_timestamp: u64 },

    #[error("Cooldown exceeded: {requested} > {max_allowed} per block")]
    CooldownExceeded { requested: u128, max_allowed: u128 },

    #[error("Slippage exceeded: output {actual} < minimum {expected}")]
    SlippageExceeded { actual: u128, expected: u128 },

    #[error("Invalid proof")]
    InvalidProof,

    #[error("Nullifier already spent: {0:?}")]
    NullifierAlreadySpent([u8; 32]),

    #[error("Invalid oracle signature")]
    InvalidOracleSignature,

    #[error("Mint/burn suspended: oracle unavailable")]
    OracleUnavailable,

    #[error("Arithmetic overflow")]
    ArithmeticOverflow,

    #[error("Zero amount")]
    ZeroAmount,

    #[error("No price available")]
    NoPriceAvailable,

    #[error("Zero supply ZRS: cannot calculate price")]
    ZeroSupplyZrs,

    #[error("Module not activated at height {current}, activation at {activation}")]
    NotActivated { current: u64, activation: u64 },

    #[error("Invalid price reference: block {requested} not found")]
    InvalidPriceReference { requested: u64 },
}
