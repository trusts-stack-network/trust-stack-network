use crate::stablecoin::config::StablecoinConfig;
use crate::stablecoin::errors::StablecoinError;
use crate::stablecoin::oracle::OracleManager;
use crate::stablecoin::types::*;

fn oracle_price(id: u8, xau_usd: u64, tsn_usd: u64, timestamp: u64) -> OraclePrice {
    let mut oracle_id = [0u8; 32];
    oracle_id[0] = id;
    OraclePrice {
        xau_usd,
        tsn_usd,
        timestamp,
        block_height: 100,
        oracle_id,
        signature: vec![],
    }
}

fn testnet_oracle() -> OracleManager {
    OracleManager::new(StablecoinConfig::testnet())
}

fn multi_oracle() -> OracleManager {
    let mut mgr = OracleManager::new(StablecoinConfig::default());
    for i in 0..5 {
        let mut id = [0u8; 32];
        id[0] = i;
        mgr.register_oracle(id);
    }
    mgr
}

// === Tests Soumission ===

#[test]
fn test_submit_price_basic() {
    let mut mgr = testnet_oracle();
    let price = oracle_price(1, 95_000_000, 1_500_000, 1000);
    assert!(mgr.submit_price(price, 1000).is_ok());
    assert_eq!(mgr.active_oracle_count(), 1);
}

#[test]
fn test_submit_price_replaces_same_oracle() {
    let mut mgr = testnet_oracle();
    let p1 = oracle_price(1, 95_000_000, 1_500_000, 1000);
    let p2 = oracle_price(1, 96_000_000, 1_500_000, 1100);
    mgr.submit_price(p1, 1000).unwrap();
    mgr.submit_price(p2, 1100).unwrap();
    assert_eq!(mgr.active_oracle_count(), 1);
}

#[test]
fn test_submit_price_multiple_oracles() {
    let mut mgr = testnet_oracle();
    for i in 1..=5 {
        let price = oracle_price(i, 95_000_000, 1_500_000, 1000);
        mgr.submit_price(price, 1000).unwrap();
    }
    assert_eq!(mgr.active_oracle_count(), 5);
}

#[test]
fn test_submit_price_stale() {
    let mut mgr = testnet_oracle();
    let price = oracle_price(1, 95_000_000, 1_500_000, 100);
    // Prix soumis à t=100, vérifié à t=100+3601 > max_age 3600
    assert!(matches!(
        mgr.submit_price(price, 3702),
        Err(StablecoinError::OraclePriceStale { .. })
    ));
}

#[test]
fn test_submit_price_zero_values() {
    let mut mgr = testnet_oracle();
    let price = oracle_price(1, 0, 1_500_000, 1000);
    assert!(matches!(
        mgr.submit_price(price, 1000),
        Err(StablecoinError::NoPriceAvailable)
    ));
}

// === Tests Agrégation ===

#[test]
fn test_aggregate_single_oracle_testnet() {
    let mut mgr = testnet_oracle();
    // 1g or = $95, 1 TSN = $1.50
    let price = oracle_price(1, 95_000_000, 1_500_000, 1000);
    mgr.submit_price(price, 1000).unwrap();

    let agg = mgr.aggregate_prices(1000).unwrap();
    // tsn_per_xau = 95_000_000 * 1_000_000 / 1_500_000 = 63_333_333
    assert_eq!(agg.tsn_per_xau, 63_333_333);
    assert_eq!(agg.oracle_count, 1);
}

#[test]
fn test_aggregate_quorum_not_met() {
    let mut mgr = multi_oracle();
    // Seulement 2 oracles soumis, quorum = 3
    let p1 = oracle_price(0, 95_000_000, 1_500_000, 1000);
    let p2 = oracle_price(1, 95_000_000, 1_500_000, 1000);
    mgr.submit_price(p1, 1000).unwrap();
    mgr.submit_price(p2, 1000).unwrap();

    assert!(matches!(
        mgr.aggregate_prices(1000),
        Err(StablecoinError::OracleQuorumNotMet { count: 2, required: 3 })
    ));
}

#[test]
fn test_aggregate_median_3_oracles() {
    let mut mgr = multi_oracle();
    // Trois prix différents
    let p1 = oracle_price(0, 94_000_000, 1_500_000, 1000); // 62_666_666
    let p2 = oracle_price(1, 95_000_000, 1_500_000, 1000); // 63_333_333
    let p3 = oracle_price(2, 96_000_000, 1_500_000, 1000); // 64_000_000
    mgr.submit_price(p1, 1000).unwrap();
    mgr.submit_price(p2, 1000).unwrap();
    mgr.submit_price(p3, 1000).unwrap();

    let agg = mgr.aggregate_prices(1000).unwrap();
    // Médiane = 63_333_333
    assert_eq!(agg.tsn_per_xau, 63_333_333);
    assert_eq!(agg.oracle_count, 3);
    assert_eq!(agg.confidence, PriceConfidence::Medium);
}

#[test]
fn test_aggregate_median_4_oracles() {
    let mut mgr = multi_oracle();
    let p1 = oracle_price(0, 94_000_000, 1_500_000, 1000);
    let p2 = oracle_price(1, 95_000_000, 1_500_000, 1000);
    let p3 = oracle_price(2, 96_000_000, 1_500_000, 1000);
    let p4 = oracle_price(3, 97_000_000, 1_500_000, 1000);
    mgr.submit_price(p1, 1000).unwrap();
    mgr.submit_price(p2, 1000).unwrap();
    mgr.submit_price(p3, 1000).unwrap();
    mgr.submit_price(p4, 1000).unwrap();

    let agg = mgr.aggregate_prices(1000).unwrap();
    // Médiane de 4 = (63_333_333 + 64_000_000) / 2 = 63_666_666
    assert_eq!(agg.oracle_count, 4);
    assert_eq!(agg.confidence, PriceConfidence::High);
}

#[test]
fn test_aggregate_deviation_too_high() {
    let mut mgr = multi_oracle();
    // Un oracle donne un prix très différent (>10% déviation)
    let p1 = oracle_price(0, 95_000_000, 1_500_000, 1000);  // 63.33
    let p2 = oracle_price(1, 95_000_000, 1_500_000, 1000);  // 63.33
    let p3 = oracle_price(2, 130_000_000, 1_500_000, 1000); // 86.67 (37% de dév)
    mgr.submit_price(p1, 1000).unwrap();
    mgr.submit_price(p2, 1000).unwrap();
    mgr.submit_price(p3, 1000).unwrap();

    assert!(matches!(
        mgr.aggregate_prices(1000),
        Err(StablecoinError::OracleDeviationTooHigh { .. })
    ));
}

// === Tests TWAP ===

#[test]
fn test_twap_basic() {
    let mut mgr = testnet_oracle();

    // Soumettre plusieurs prix à des moments différents
    for i in 0..5 {
        let xau = 95_000_000 + i * 500_000; // Légère variation
        let price = oracle_price(1, xau, 1_500_000, 1000 + i * 60);
        mgr.submit_price(price, 1000 + i * 60).unwrap();
        mgr.aggregate_prices(1000 + i * 60).unwrap();
    }

    let twap = mgr.calculate_twap();
    assert!(twap.is_some());
    let twap_val = twap.unwrap();
    // Le TWAP devrait être entre le min et le max des prix
    assert!(twap_val > 63_000_000);
    assert!(twap_val < 65_000_000);
}

#[test]
fn test_twap_empty_history() {
    let mgr = testnet_oracle();
    assert!(mgr.calculate_twap().is_none());
}

// === Tests Get Current Price ===

#[test]
fn test_get_current_price_no_data() {
    let mgr = testnet_oracle();
    assert!(matches!(
        mgr.get_current_price(),
        Err(StablecoinError::NoPriceAvailable)
    ));
}

#[test]
fn test_get_current_price_with_data() {
    let mut mgr = testnet_oracle();
    let price = oracle_price(1, 95_000_000, 1_500_000, 1000);
    mgr.submit_price(price, 1000).unwrap();
    mgr.aggregate_prices(1000).unwrap();

    let current = mgr.get_current_price().unwrap();
    assert!(current.tsn_per_xau > 0);
}

// === Tests Price Stale ===

#[test]
fn test_is_price_stale_no_price() {
    let mgr = testnet_oracle();
    assert!(mgr.is_price_stale(1000));
}

#[test]
fn test_is_price_stale_fresh() {
    let mut mgr = testnet_oracle();
    mgr.force_price(63_333_333, 1000);
    assert!(!mgr.is_price_stale(1000));
    assert!(!mgr.is_price_stale(2000));
}

#[test]
fn test_is_price_stale_expired() {
    let mut mgr = testnet_oracle();
    mgr.force_price(63_333_333, 1000);
    assert!(mgr.is_price_stale(1000 + 3601)); // > 3600s (testnet max_age)
}

// === Tests Force Price ===

#[test]
fn test_force_price() {
    let mut mgr = testnet_oracle();
    mgr.force_price(50_000_000, 2000);
    let price = mgr.get_current_price().unwrap();
    assert_eq!(price.tsn_per_xau, 50_000_000);
    assert_eq!(price.timestamp, 2000);
}

// === Tests Oracle Registration ===

#[test]
fn test_register_unregister_oracle() {
    let mut mgr = OracleManager::new(StablecoinConfig::default());
    let id = [42u8; 32];
    mgr.register_oracle(id);
    assert_eq!(mgr.registered_oracles().len(), 1);

    // Double register → pas de duplicata
    mgr.register_oracle(id);
    assert_eq!(mgr.registered_oracles().len(), 1);

    mgr.unregister_oracle(&id);
    assert_eq!(mgr.registered_oracles().len(), 0);
}

#[test]
fn test_unauthorized_oracle_rejected() {
    let mut mgr = OracleManager::new(StablecoinConfig::default());
    let authorized_id = [1u8; 32];
    mgr.register_oracle(authorized_id);

    // Soumission par un oracle non autorisé
    let price = oracle_price(42, 95_000_000, 1_500_000, 1000);
    assert!(matches!(
        mgr.submit_price(price, 1000),
        Err(StablecoinError::InvalidOracleSignature)
    ));
}

// === Tests Oracle Circuit Breaker ===

#[test]
fn test_oracle_circuit_breaker() {
    let mut mgr = multi_oracle();

    // Premier prix
    let p1 = oracle_price(0, 95_000_000, 1_500_000, 1000);
    let p2 = oracle_price(1, 95_000_000, 1_500_000, 1000);
    let p3 = oracle_price(2, 95_000_000, 1_500_000, 1000);
    mgr.submit_price(p1, 1000).unwrap();
    mgr.submit_price(p2, 1000).unwrap();
    mgr.submit_price(p3, 1000).unwrap();
    mgr.aggregate_prices(1000).unwrap();

    // Deuxième prix: variation de 30% (> 25% circuit breaker)
    let p1 = oracle_price(0, 130_000_000, 1_500_000, 1100);
    let p2 = oracle_price(1, 130_000_000, 1_500_000, 1100);
    let p3 = oracle_price(2, 130_000_000, 1_500_000, 1100);
    mgr.submit_price(p1, 1100).unwrap();
    mgr.submit_price(p2, 1100).unwrap();
    mgr.submit_price(p3, 1100).unwrap();

    assert!(matches!(
        mgr.aggregate_prices(1100),
        Err(StablecoinError::OracleCircuitBreaker { .. })
    ));
}
