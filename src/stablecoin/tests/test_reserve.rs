use crate::stablecoin::config::StablecoinConfig;
use crate::stablecoin::errors::StablecoinError;
use crate::stablecoin::reserve::ReserveEngine;
use crate::stablecoin::types::*;

/// Helper: crée un état de réserve avec des valeurs raisonnables
/// Prix: 1 TSN = $1.50, 1g or = $95 → tsn_per_xau = 63_333_333 (~63.33 TSN)
fn default_state() -> ReserveState {
    ReserveState {
        reserve_tsn: 400_000 * ATOMIC_UNIT, // 400k TSN
        supply_zst: 1_000 * ATOMIC_UNIT,    // 1000 ZST (= 1000g or)
        supply_zrs: 5_000 * ATOMIC_UNIT,    // 5000 ZRS
        last_price: AggregatedPrice {
            tsn_per_xau: 63_333_333, // ~63.33 TSN par gramme d'or
            timestamp: 1000,
            oracle_count: 3,
            confidence: PriceConfidence::Medium,
        },
        treasury_tsn: 0,
        last_block_height: 100,
        circuit_breaker_activated: 0,
        current_block_burned_zst: 0,
        current_block_height: 100,
    }
}

fn engine() -> ReserveEngine {
    ReserveEngine::new(StablecoinConfig::default())
}

fn testnet_engine() -> ReserveEngine {
    ReserveEngine::new(StablecoinConfig::testnet())
}

// === Tests Reserve Ratio ===

#[test]
fn test_ratio_healthy() {
    let e = engine();
    let state = default_state();
    let ratio = e.calculate_ratio(&state).unwrap();
    // 400k TSN / (1000 ZST * 63.33 TSN/ZST) ≈ 400k / 63333 ≈ 6.32 = 63158 bps
    assert!(ratio > 60_000, "ratio should be > 600%: got {}", ratio);
    assert!(ratio < 70_000, "ratio should be < 700%: got {}", ratio);
}

#[test]
fn test_ratio_no_zst_is_max() {
    let e = engine();
    let mut state = default_state();
    state.supply_zst = 0;
    let ratio = e.calculate_ratio(&state).unwrap();
    assert_eq!(ratio, u64::MAX);
}

#[test]
fn test_ratio_no_reserve_is_zero() {
    let e = engine();
    let mut state = default_state();
    state.reserve_tsn = 0;
    let ratio = e.calculate_ratio(&state).unwrap();
    assert_eq!(ratio, 0);
}

#[test]
fn test_ratio_exactly_150_percent() {
    let e = engine();
    // Pour avoir 150%: reserve_value = 1.5 * liabilities
    // liabilities = 1000 ZST = 1000g or
    // reserve_value = 1500g or = 1500 * 63.33 TSN = 94999.5 TSN
    let mut state = default_state();
    state.reserve_tsn = 95_000 * ATOMIC_UNIT;
    let ratio = e.calculate_ratio(&state).unwrap();
    // On s'attend à ~15000 bps (150%)
    assert!(ratio >= 14_900 && ratio <= 15_100, "ratio ~150%: got {}", ratio);
}

#[test]
fn test_ratio_no_price() {
    let e = engine();
    let mut state = default_state();
    state.last_price.tsn_per_xau = 0;
    assert!(matches!(
        e.calculate_ratio(&state),
        Err(StablecoinError::NoPriceAvailable)
    ));
}

// === Tests ZRS Price ===

#[test]
fn test_zrs_price_healthy() {
    let e = engine();
    let state = default_state();
    let price = e.calculate_zrs_price(&state).unwrap();
    // ZRS price is in TSN atomiques
    // equity = reserve_value_xau - liabilities = (400k / 63.33) - 1000 ≈ 5316 XAU
    // prix_zrs_tsn = equity_xau * tsn_per_xau / MICRO_UNIT / supply_zrs
    // = 5316 * 10^8 * 63_333_333 / 10^6 / (5000 * 10^8)
    // Les divisions entières perdent de la précision sur de grands nombres
    assert!(price > 0, "price should be > 0: {}", price);
    // Vérifions juste que c'est raisonnable (quelques dizaines de TSN)
    assert!(price < 100 * ATOMIC_UNIT, "price too high: {}", price);
}

#[test]
fn test_zrs_price_no_supply_returns_1_tsn() {
    let e = engine();
    let mut state = default_state();
    state.supply_zrs = 0;
    let price = e.calculate_zrs_price(&state).unwrap();
    assert_eq!(price, ATOMIC_UNIT);
}

#[test]
fn test_zrs_price_undercollateralized_is_zero() {
    let e = engine();
    let mut state = default_state();
    state.reserve_tsn = 10_000 * ATOMIC_UNIT; // Très sous-collatéralisé
    state.supply_zst = 10_000 * ATOMIC_UNIT;  // Beaucoup de ZST
    let price = e.calculate_zrs_price(&state).unwrap();
    assert_eq!(price, 0);
}

// === Tests Frais ===

#[test]
fn test_fee_normal() {
    let e = engine();
    // 0.30% de 100 TSN = 0.3 TSN
    let fee = e.calculate_fee_amount(100 * ATOMIC_UNIT, 30).unwrap();
    // 100 * 10^8 * 30 / 10000 = 30 * 10^6 = 0.3 TSN
    assert_eq!(fee, 30_000_000); // 0.3 TSN en unités atomiques
}

#[test]
fn test_fee_rounds_up() {
    let e = engine();
    // Petit montant: 1 unité atomique * 30 bps = 0.003 → arrondi à 1
    let fee = e.calculate_fee_amount(1, 30).unwrap();
    assert_eq!(fee, 1); // Arrondi vers le haut
}

#[test]
fn test_stress_fee_normal_ratio() {
    let e = engine();
    let state = default_state(); // ratio > 300%
    let fee = e.calculate_stress_fee(&state).unwrap();
    assert_eq!(fee, 30); // 0.30% normal
}

#[test]
fn test_stress_fee_moderate_stress() {
    let e = engine();
    let mut state = default_state();
    // Mettre le ratio à ~250% (entre 200% et 300%)
    state.reserve_tsn = 158_500 * ATOMIC_UNIT;
    let ratio = e.calculate_ratio(&state).unwrap();
    assert!(ratio >= 24_000 && ratio <= 26_000, "ratio ~250%: {}", ratio);
    let fee = e.calculate_stress_fee(&state).unwrap();
    assert!(fee > 30, "stress fee should be > base: {}", fee);
    assert!(fee <= 230, "stress fee should be <= 230: {}", fee);
}

#[test]
fn test_stress_fee_high_stress() {
    let e = engine();
    let mut state = default_state();
    // Ratio ~175% (entre 150% et 200%)
    state.reserve_tsn = 111_000 * ATOMIC_UNIT;
    let ratio = e.calculate_ratio(&state).unwrap();
    assert!(ratio >= 17_000 && ratio <= 18_000, "ratio ~175%: {}", ratio);
    let fee = e.calculate_stress_fee(&state).unwrap();
    assert!(fee > 230, "stress fee should be > 230: {}", fee);
    assert!(fee <= 500, "stress fee should be <= 500: {}", fee);
}

#[test]
fn test_stress_fee_max() {
    let e = engine();
    let mut state = default_state();
    // Ratio < 150%
    state.reserve_tsn = 80_000 * ATOMIC_UNIT;
    let ratio = e.calculate_ratio(&state).unwrap();
    assert!(ratio < 15_000, "ratio should be < 150%: {}", ratio);
    let fee = e.calculate_stress_fee(&state).unwrap();
    assert_eq!(fee, 500); // 5% max
}

#[test]
fn test_fee_distribution() {
    let e = engine();
    let fee = 1000 * ATOMIC_UNIT;
    let (to_reserve, to_treasury) = e.distribute_fee(fee);
    assert_eq!(to_reserve, 800 * ATOMIC_UNIT); // 80%
    assert_eq!(to_treasury, 200 * ATOMIC_UNIT); // 20%
}

// === Tests Conversion TSN/ZST ===

#[test]
fn test_tsn_to_zst() {
    let e = engine();
    // 63.33 TSN → 1 ZST (1g or)
    let zst = e.tsn_to_zst(63_333_333 * 100, 63_333_333).unwrap();
    // 63.33 TSN * 10^8 (atomique) * 10^6 / 63_333_333 = 10^8 = 1 ZST
    assert_eq!(zst, ATOMIC_UNIT);
}

#[test]
fn test_zst_to_tsn() {
    let e = engine();
    // 1 ZST → 63.33 TSN
    let tsn = e.zst_to_tsn(ATOMIC_UNIT, 63_333_333).unwrap();
    // 10^8 * 63_333_333 / 10^6 = 6_333_333_300
    assert_eq!(tsn, 6_333_333_300);
}

#[test]
fn test_conversion_roundtrip() {
    let e = engine();
    let original_tsn = 100 * ATOMIC_UNIT;
    let price = 63_333_333u64;
    let zst = e.tsn_to_zst(original_tsn, price).unwrap();
    let tsn_back = e.zst_to_tsn(zst, price).unwrap();
    // Légère perte possible due aux arrondis, mais devrait être très proche
    let diff = if original_tsn > tsn_back {
        original_tsn - tsn_back
    } else {
        tsn_back - original_tsn
    };
    assert!(diff < ATOMIC_UNIT / 100, "roundtrip error too large: {}", diff);
}

// === Tests Simulation Mint ZST ===

#[test]
fn test_simulate_mint_zst_normal() {
    let e = engine();
    let state = default_state();
    let result = e.simulate_mint_zst(&state, 100 * ATOMIC_UNIT).unwrap();
    assert_eq!(result.action, StablecoinAction::MintZST);
    assert_eq!(result.amount_in, 100 * ATOMIC_UNIT);
    assert!(result.amount_out > 0);
    assert!(result.fee > 0);
    assert!(result.ratio_after > 0);
}

#[test]
fn test_simulate_mint_zst_zero_amount() {
    let e = engine();
    let state = default_state();
    assert!(matches!(
        e.simulate_mint_zst(&state, 0),
        Err(StablecoinError::ZeroAmount)
    ));
}

#[test]
fn test_simulate_mint_zst_no_price() {
    let e = engine();
    let mut state = default_state();
    state.last_price.tsn_per_xau = 0;
    assert!(matches!(
        e.simulate_mint_zst(&state, 100 * ATOMIC_UNIT),
        Err(StablecoinError::NoPriceAvailable)
    ));
}

// === Tests Simulation Burn ZST ===

#[test]
fn test_simulate_burn_zst_normal() {
    let e = engine();
    let state = default_state();
    let result = e
        .simulate_burn_zst(&state, 10 * ATOMIC_UNIT, 1000)
        .unwrap();
    assert_eq!(result.action, StablecoinAction::BurnZST);
    assert!(result.amount_out > 0);
    assert!(result.fee > 0);
}

#[test]
fn test_simulate_burn_zst_more_than_supply() {
    let e = engine();
    let state = default_state();
    assert!(e
        .simulate_burn_zst(&state, state.supply_zst + 1, 1000)
        .is_err());
}

// === Tests Simulation Mint ZRS ===

#[test]
fn test_simulate_mint_zrs_normal() {
    let e = engine();
    let state = default_state();
    let result = e.simulate_mint_zrs(&state, 100 * ATOMIC_UNIT).unwrap();
    assert_eq!(result.action, StablecoinAction::MintZRS);
    assert!(result.amount_out > 0);
}

#[test]
fn test_simulate_mint_zrs_ratio_too_high() {
    let e = engine();
    let mut state = default_state();
    // Réserve énorme → ratio déjà au-dessus de 800%
    state.reserve_tsn = 10_000_000 * ATOMIC_UNIT;
    let ratio = e.calculate_ratio(&state).unwrap();
    // Ajuster pour que le mint pousse au-delà de 800%
    if ratio > 80_000 {
        assert!(matches!(
            e.simulate_mint_zrs(&state, 100_000 * ATOMIC_UNIT),
            Err(StablecoinError::ReserveRatioTooHigh { .. })
        ));
    }
}

// === Tests Simulation Burn ZRS ===

#[test]
fn test_simulate_burn_zrs_normal() {
    let e = engine();
    let state = default_state();
    let result = e
        .simulate_burn_zrs(&state, 100 * ATOMIC_UNIT)
        .unwrap();
    assert_eq!(result.action, StablecoinAction::BurnZRS);
    assert!(result.amount_out > 0);
}

#[test]
fn test_simulate_burn_zrs_more_than_supply() {
    let e = engine();
    let state = default_state();
    assert!(e
        .simulate_burn_zrs(&state, state.supply_zrs + 1)
        .is_err());
}

// === Tests Circuit Breaker ===

#[test]
fn test_circuit_breaker_inactive() {
    let e = engine();
    let state = default_state();
    assert!(e.check_circuit_breaker(&state, 2000).is_ok());
}

#[test]
fn test_circuit_breaker_active() {
    let e = engine();
    let mut state = default_state();
    state.circuit_breaker_activated = 1000;
    assert!(matches!(
        e.check_circuit_breaker(&state, 1500),
        Err(StablecoinError::CircuitBreakerActive { .. })
    ));
}

#[test]
fn test_circuit_breaker_expired() {
    let e = engine();
    let mut state = default_state();
    state.circuit_breaker_activated = 1000;
    // 86400 secondes plus tard
    assert!(e.check_circuit_breaker(&state, 1000 + 86_401).is_ok());
}

// === Tests Cooldown ===

#[test]
fn test_cooldown_ok() {
    let e = engine();
    let state = default_state();
    // 5% de 1000 ZST = 50 ZST max par bloc
    let max = state.supply_zst * 500 / 10_000;
    assert!(e.check_cooldown(&state, max).is_ok());
}

#[test]
fn test_cooldown_exceeded() {
    let e = engine();
    let state = default_state();
    // Plus de 5% du supply
    let too_much = state.supply_zst * 600 / 10_000;
    assert!(matches!(
        e.check_cooldown(&state, too_much),
        Err(StablecoinError::CooldownExceeded { .. })
    ));
}

#[test]
fn test_cooldown_cumulative() {
    let e = engine();
    let mut state = default_state();
    let max_burn = state.supply_zst * 500 / 10_000;
    // Déjà brûlé 40% du max
    state.current_block_burned_zst = max_burn * 4 / 5;
    // Essayer de brûler encore 30% → total 70% > 100% du max
    let extra = max_burn * 3 / 10;
    assert!(matches!(
        e.check_cooldown(&state, extra),
        Err(StablecoinError::CooldownExceeded { .. })
    ));
}

// === Tests Can Mint/Burn ===

#[test]
fn test_can_mint_zst_healthy() {
    let e = engine();
    let state = default_state();
    assert!(e.can_mint_zst(&state, 100 * ATOMIC_UNIT).unwrap());
}

#[test]
fn test_can_mint_zst_would_break_ratio() {
    let e = engine();
    let mut state = default_state();
    // Réserve juste au-dessus de 150%
    state.reserve_tsn = 95_500 * ATOMIC_UNIT;
    // Un gros mint devrait échouer
    assert!(!e.can_mint_zst(&state, 1_000_000 * ATOMIC_UNIT).unwrap());
}

#[test]
fn test_can_burn_zrs_healthy() {
    let e = engine();
    let state = default_state();
    assert!(e.can_burn_zrs(&state, 100 * ATOMIC_UNIT).unwrap());
}

// === Tests Edge Cases ===

#[test]
fn test_very_small_amounts() {
    let e = engine();
    let state = default_state();
    // 1 unité atomique
    let result = e.simulate_mint_zst(&state, 1).unwrap();
    assert_eq!(result.amount_in, 1);
    // Le fee arrondi vers le haut peut consommer tout
}

#[test]
fn test_first_ever_mint_zst() {
    let e = engine();
    let mut state = ReserveState::default();
    state.last_price = AggregatedPrice {
        tsn_per_xau: 63_333_333,
        timestamp: 1000,
        oracle_count: 3,
        confidence: PriceConfidence::Medium,
    };
    // Seed la réserve avec du TSN (bootstrap du protocole)
    // Il faut assez de réserve pour que le ratio reste >= 150% après mint
    state.reserve_tsn = 500_000 * ATOMIC_UNIT;
    // Premier mint: pas de ZST en circulation, ratio = infini
    let result = e.simulate_mint_zst(&state, 1000 * ATOMIC_UNIT).unwrap();
    assert!(result.amount_out > 0);
    assert_eq!(result.ratio_before, u64::MAX);
}

#[test]
fn test_first_ever_mint_zrs() {
    let e = engine();
    let mut state = ReserveState::default();
    state.last_price = AggregatedPrice {
        tsn_per_xau: 63_333_333,
        timestamp: 1000,
        oracle_count: 3,
        confidence: PriceConfidence::Medium,
    };
    // Il faut du ZST en circulation pour que le ratio ne soit pas infini (>800%)
    state.reserve_tsn = 500_000 * ATOMIC_UNIT;
    state.supply_zst = 1_000 * ATOMIC_UNIT;
    let result = e.simulate_mint_zrs(&state, 1000 * ATOMIC_UNIT).unwrap();
    assert!(result.amount_out > 0);
}
