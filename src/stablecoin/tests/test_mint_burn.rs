use crate::stablecoin::config::StablecoinConfig;
use crate::stablecoin::errors::StablecoinError;
use crate::stablecoin::mint_burn::MintBurnManager;
use crate::stablecoin::types::*;

fn default_state() -> ReserveState {
    ReserveState {
        reserve_tsn: 400_000 * ATOMIC_UNIT,
        supply_zst: 1_000 * ATOMIC_UNIT,
        supply_zrs: 5_000 * ATOMIC_UNIT,
        last_price: AggregatedPrice {
            tsn_per_xau: 63_333_333,
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

fn manager() -> MintBurnManager {
    MintBurnManager::new(StablecoinConfig::default())
}

// === Tests Execute Mint ZST ===

#[test]
fn test_execute_mint_zst() {
    let mgr = manager();
    let mut state = default_state();
    let initial_reserve = state.reserve_tsn;
    let initial_supply = state.supply_zst;

    let req = MintBurnRequest {
        action: StablecoinAction::MintZST,
        amount_in: 100 * ATOMIC_UNIT,
        min_amount_out: 0,
        price_ref: 100,
    };

    let result = mgr.execute_mint_zst(&mut state, &req, 1000).unwrap();

    // Vérifier que l'état a changé
    assert!(state.reserve_tsn > initial_reserve);
    assert!(state.supply_zst > initial_supply);
    assert_eq!(state.supply_zst, initial_supply + result.amount_out);
    assert!(state.treasury_tsn > 0);
}

#[test]
fn test_execute_mint_zst_slippage_protection() {
    let mgr = manager();
    let mut state = default_state();

    let req = MintBurnRequest {
        action: StablecoinAction::MintZST,
        amount_in: 100 * ATOMIC_UNIT,
        min_amount_out: u128::MAX, // Impossible à atteindre
        price_ref: 100,
    };

    assert!(matches!(
        mgr.execute_mint_zst(&mut state, &req, 1000),
        Err(StablecoinError::SlippageExceeded { .. })
    ));
}

#[test]
fn test_execute_mint_zst_stale_price() {
    let mgr = manager();
    let mut state = default_state();
    state.last_price.confidence = PriceConfidence::Stale;

    let req = MintBurnRequest {
        action: StablecoinAction::MintZST,
        amount_in: 100 * ATOMIC_UNIT,
        min_amount_out: 0,
        price_ref: 100,
    };

    assert!(matches!(
        mgr.execute_mint_zst(&mut state, &req, 1000),
        Err(StablecoinError::OracleUnavailable)
    ));
}

// === Tests Execute Burn ZST ===

#[test]
fn test_execute_burn_zst() {
    let mgr = manager();
    let mut state = default_state();
    let initial_reserve = state.reserve_tsn;
    let initial_supply = state.supply_zst;

    let req = MintBurnRequest {
        action: StablecoinAction::BurnZST,
        amount_in: 10 * ATOMIC_UNIT,
        min_amount_out: 0,
        price_ref: 100,
    };

    let result = mgr.execute_burn_zst(&mut state, &req, 1000).unwrap();

    assert!(state.reserve_tsn < initial_reserve);
    assert_eq!(state.supply_zst, initial_supply - 10 * ATOMIC_UNIT);
    assert!(result.amount_out > 0);
}

#[test]
fn test_execute_burn_zst_tracks_cooldown() {
    let mgr = manager();
    let mut state = default_state();

    let req = MintBurnRequest {
        action: StablecoinAction::BurnZST,
        amount_in: 10 * ATOMIC_UNIT,
        min_amount_out: 0,
        price_ref: 100,
    };

    mgr.execute_burn_zst(&mut state, &req, 1000).unwrap();
    assert_eq!(state.current_block_burned_zst, 10 * ATOMIC_UNIT);

    // Deuxième burn dans le même bloc
    mgr.execute_burn_zst(&mut state, &req, 1000).unwrap();
    assert_eq!(state.current_block_burned_zst, 20 * ATOMIC_UNIT);
}

#[test]
fn test_execute_burn_zst_cooldown_exceeded() {
    let mgr = manager();
    let mut state = default_state();

    // Essayer de brûler plus de 5% du supply en un coup
    let too_much = state.supply_zst * 600 / 10_000; // 6%
    let req = MintBurnRequest {
        action: StablecoinAction::BurnZST,
        amount_in: too_much,
        min_amount_out: 0,
        price_ref: 100,
    };

    assert!(matches!(
        mgr.execute_burn_zst(&mut state, &req, 1000),
        Err(StablecoinError::CooldownExceeded { .. })
    ));
}

// === Tests Execute Mint ZRS ===

#[test]
fn test_execute_mint_zrs() {
    let mgr = manager();
    let mut state = default_state();
    let initial_zrs = state.supply_zrs;

    let req = MintBurnRequest {
        action: StablecoinAction::MintZRS,
        amount_in: 100 * ATOMIC_UNIT,
        min_amount_out: 0,
        price_ref: 100,
    };

    let result = mgr.execute_mint_zrs(&mut state, &req, 1000).unwrap();
    assert!(state.supply_zrs > initial_zrs);
    assert!(result.amount_out > 0);
}

#[test]
fn test_execute_mint_zrs_circuit_breaker() {
    let mgr = manager();
    let mut state = default_state();
    state.circuit_breaker_activated = 900; // Activé à t=900

    let req = MintBurnRequest {
        action: StablecoinAction::MintZRS,
        amount_in: 100 * ATOMIC_UNIT,
        min_amount_out: 0,
        price_ref: 100,
    };

    assert!(matches!(
        mgr.execute_mint_zrs(&mut state, &req, 1000),
        Err(StablecoinError::CircuitBreakerActive { .. })
    ));
}

// === Tests Execute Burn ZRS ===

#[test]
fn test_execute_burn_zrs() {
    let mgr = manager();
    let mut state = default_state();
    let initial_zrs = state.supply_zrs;

    let req = MintBurnRequest {
        action: StablecoinAction::BurnZRS,
        amount_in: 100 * ATOMIC_UNIT,
        min_amount_out: 0,
        price_ref: 100,
    };

    let result = mgr.execute_burn_zrs(&mut state, &req, 1000).unwrap();
    assert_eq!(state.supply_zrs, initial_zrs - 100 * ATOMIC_UNIT);
    assert!(result.amount_out > 0);
}

#[test]
fn test_execute_burn_zrs_circuit_breaker() {
    let mgr = manager();
    let mut state = default_state();
    state.circuit_breaker_activated = 900;

    let req = MintBurnRequest {
        action: StablecoinAction::BurnZRS,
        amount_in: 100 * ATOMIC_UNIT,
        min_amount_out: 0,
        price_ref: 100,
    };

    assert!(matches!(
        mgr.execute_burn_zrs(&mut state, &req, 1000),
        Err(StablecoinError::CircuitBreakerActive { .. })
    ));
}

// === Tests Dispatch ===

#[test]
fn test_execute_dispatch() {
    let mgr = manager();
    let mut state = default_state();

    for action in [
        StablecoinAction::MintZST,
        StablecoinAction::BurnZST,
        StablecoinAction::MintZRS,
        StablecoinAction::BurnZRS,
    ] {
        let mut s = state.clone();
        let amount = match action {
            StablecoinAction::BurnZST => 10 * ATOMIC_UNIT,
            StablecoinAction::BurnZRS => 100 * ATOMIC_UNIT,
            _ => 100 * ATOMIC_UNIT,
        };
        let req = MintBurnRequest {
            action,
            amount_in: amount,
            min_amount_out: 0,
            price_ref: 100,
        };
        let result = mgr.execute(&mut s, &req, 1000).unwrap();
        assert_eq!(result.action, action);
    }
}

// === Tests New Block ===

#[test]
fn test_new_block_resets_cooldown() {
    let mgr = manager();
    let mut state = default_state();
    state.current_block_burned_zst = 50 * ATOMIC_UNIT;
    state.current_block_height = 100;

    mgr.new_block(&mut state, 101);
    assert_eq!(state.current_block_burned_zst, 0);
    assert_eq!(state.current_block_height, 101);
}

// === Tests Circuit Breaker Expiry ===

#[test]
fn test_circuit_breaker_expiry() {
    let mgr = manager();
    let mut state = default_state();
    state.circuit_breaker_activated = 1000;

    // Pas encore expiré
    mgr.check_circuit_breaker_expiry(&mut state, 50_000);
    assert_eq!(state.circuit_breaker_activated, 1000);

    // Expiré
    mgr.check_circuit_breaker_expiry(&mut state, 1000 + 86_401);
    assert_eq!(state.circuit_breaker_activated, 0);
}

// === Tests Scénarios Complexes ===

#[test]
fn test_scenario_mint_then_burn_zst() {
    let mgr = manager();
    let mut state = default_state();

    // Mint 100 TSN → ZST
    let mint_req = MintBurnRequest {
        action: StablecoinAction::MintZST,
        amount_in: 100 * ATOMIC_UNIT,
        min_amount_out: 0,
        price_ref: 100,
    };
    let mint_result = mgr.execute_mint_zst(&mut state, &mint_req, 1000).unwrap();

    // Burn la moitié des ZST reçus
    let burn_amount = mint_result.amount_out / 2;
    let burn_req = MintBurnRequest {
        action: StablecoinAction::BurnZST,
        amount_in: burn_amount,
        min_amount_out: 0,
        price_ref: 100,
    };
    let burn_result = mgr.execute_burn_zst(&mut state, &burn_req, 1000).unwrap();

    // Le TSN récupéré devrait être environ la moitié du TSN déposé (moins les frais)
    assert!(burn_result.amount_out < 50 * ATOMIC_UNIT);
    assert!(burn_result.amount_out > 40 * ATOMIC_UNIT);
}

#[test]
fn test_scenario_bank_run_protection() {
    let mgr = manager();
    let mut state = default_state();

    // Essayer de brûler tout le supply en un bloc → cooldown
    let req = MintBurnRequest {
        action: StablecoinAction::BurnZST,
        amount_in: state.supply_zst,
        min_amount_out: 0,
        price_ref: 100,
    };

    assert!(matches!(
        mgr.execute_burn_zst(&mut state, &req, 1000),
        Err(StablecoinError::CooldownExceeded { .. })
    ));
}

#[test]
fn test_scenario_circuit_breaker_activation() {
    let mgr = manager();
    let mut state = default_state();
    // Ratio très bas pour déclencher le circuit breaker
    state.reserve_tsn = 70_000 * ATOMIC_UNIT; // ratio < 120%

    let req = MintBurnRequest {
        action: StablecoinAction::BurnZST,
        amount_in: 5 * ATOMIC_UNIT, // Petit burn
        min_amount_out: 0,
        price_ref: 100,
    };

    let _ = mgr.execute_burn_zst(&mut state, &req, 2000);
    // Le circuit breaker devrait s'activer si le ratio descend sous 120%
    let ratio = mgr.engine().calculate_ratio(&state).unwrap();
    if ratio < 12_000 {
        assert!(state.circuit_breaker_activated > 0);
    }
}
