// ZST — Logique d'exécution Mint/Burn
// Applique les opérations sur l'état de la réserve

use crate::stablecoin::config::StablecoinConfig;
use crate::stablecoin::errors::StablecoinError;
use crate::stablecoin::reserve::ReserveEngine;
use crate::stablecoin::types::*;

/// Gestionnaire des opérations mint/burn
pub struct MintBurnManager {
    engine: ReserveEngine,
}

impl MintBurnManager {
    pub fn new(config: StablecoinConfig) -> Self {
        Self {
            engine: ReserveEngine::new(config),
        }
    }

    pub fn engine(&self) -> &ReserveEngine {
        &self.engine
    }

    /// Exécute un mint ZST: dépose TSN, reçoit ZST
    pub fn execute_mint_zst(
        &self,
        state: &mut ReserveState,
        request: &MintBurnRequest,
        current_timestamp: u64,
    ) -> Result<MintBurnResult, StablecoinError> {
        self.validate_common(state, current_timestamp)?;

        let result = self.engine.simulate_mint_zst(state, request.amount_in)?;

        // Vérifier slippage
        if result.amount_out < request.min_amount_out {
            return Err(StablecoinError::SlippageExceeded {
                actual: result.amount_out,
                expected: request.min_amount_out,
            });
        }

        // Appliquer sur l'état
        state.reserve_tsn += result.amount_in - result.fee + result.fee_reserve;
        state.treasury_tsn += result.fee_treasury;
        state.supply_zst += result.amount_out;

        Ok(result)
    }

    /// Exécute un burn ZST: brûle ZST, récupère TSN
    pub fn execute_burn_zst(
        &self,
        state: &mut ReserveState,
        request: &MintBurnRequest,
        current_timestamp: u64,
    ) -> Result<MintBurnResult, StablecoinError> {
        self.validate_common(state, current_timestamp)?;

        // Vérifier circuit breaker (sauf en mode survie où burn ZST reste OK)
        let is_survival = self.is_circuit_breaker_active(state, current_timestamp);
        if is_survival {
            // En mode survie, seul le burn ZST est autorisé, mais avec frais max
        }

        let result =
            self.engine
                .simulate_burn_zst(state, request.amount_in, current_timestamp)?;

        if result.amount_out < request.min_amount_out {
            return Err(StablecoinError::SlippageExceeded {
                actual: result.amount_out,
                expected: request.min_amount_out,
            });
        }

        // Appliquer sur l'état
        let tsn_gross = self
            .engine
            .zst_to_tsn(request.amount_in, state.last_price.tsn_per_xau)?;
        state.reserve_tsn = state.reserve_tsn.saturating_sub(tsn_gross);
        state.reserve_tsn += result.fee_reserve;
        state.treasury_tsn += result.fee_treasury;
        state.supply_zst -= request.amount_in;
        state.current_block_burned_zst += request.amount_in;

        // Vérifier si on doit activer le circuit breaker
        let ratio = self.engine.calculate_ratio(state)?;
        if ratio < self.engine.config.circuit_breaker_ratio
            && state.circuit_breaker_activated == 0
        {
            state.circuit_breaker_activated = current_timestamp;
        }

        Ok(result)
    }

    /// Exécute un mint ZRS: dépose TSN, reçoit ZRS
    pub fn execute_mint_zrs(
        &self,
        state: &mut ReserveState,
        request: &MintBurnRequest,
        current_timestamp: u64,
    ) -> Result<MintBurnResult, StablecoinError> {
        self.validate_common(state, current_timestamp)?;
        self.engine
            .check_circuit_breaker(state, current_timestamp)?;

        let result = self.engine.simulate_mint_zrs(state, request.amount_in)?;

        if result.amount_out < request.min_amount_out {
            return Err(StablecoinError::SlippageExceeded {
                actual: result.amount_out,
                expected: request.min_amount_out,
            });
        }

        // Appliquer
        state.reserve_tsn += result.amount_in - result.fee + result.fee_reserve;
        state.treasury_tsn += result.fee_treasury;
        state.supply_zrs += result.amount_out;

        Ok(result)
    }

    /// Exécute un burn ZRS: brûle ZRS, récupère TSN
    pub fn execute_burn_zrs(
        &self,
        state: &mut ReserveState,
        request: &MintBurnRequest,
        current_timestamp: u64,
    ) -> Result<MintBurnResult, StablecoinError> {
        self.validate_common(state, current_timestamp)?;
        self.engine
            .check_circuit_breaker(state, current_timestamp)?;

        let result = self.engine.simulate_burn_zrs(state, request.amount_in)?;

        if result.amount_out < request.min_amount_out {
            return Err(StablecoinError::SlippageExceeded {
                actual: result.amount_out,
                expected: request.min_amount_out,
            });
        }

        // Appliquer
        let zrs_price = self.engine.calculate_zrs_price(state)?;
        let tsn_gross = request
            .amount_in
            .checked_mul(zrs_price)
            .ok_or(StablecoinError::ArithmeticOverflow)?
            / ATOMIC_UNIT;
        state.reserve_tsn = state.reserve_tsn.saturating_sub(tsn_gross);
        state.reserve_tsn += result.fee_reserve;
        state.treasury_tsn += result.fee_treasury;
        state.supply_zrs -= request.amount_in;

        Ok(result)
    }

    /// Dispatch une requête vers la bonne méthode
    pub fn execute(
        &self,
        state: &mut ReserveState,
        request: &MintBurnRequest,
        current_timestamp: u64,
    ) -> Result<MintBurnResult, StablecoinError> {
        match request.action {
            StablecoinAction::MintZST => self.execute_mint_zst(state, request, current_timestamp),
            StablecoinAction::BurnZST => self.execute_burn_zst(state, request, current_timestamp),
            StablecoinAction::MintZRS => self.execute_mint_zrs(state, request, current_timestamp),
            StablecoinAction::BurnZRS => self.execute_burn_zrs(state, request, current_timestamp),
        }
    }

    /// Réinitialise le tracking cooldown pour un nouveau bloc
    pub fn new_block(&self, state: &mut ReserveState, block_height: u64) {
        state.current_block_burned_zst = 0;
        state.current_block_height = block_height;
    }

    /// Désactive le circuit breaker si expiré
    pub fn check_circuit_breaker_expiry(&self, state: &mut ReserveState, current_timestamp: u64) {
        if state.circuit_breaker_activated > 0 {
            let expiry =
                state.circuit_breaker_activated + self.engine.config.circuit_breaker_duration;
            if current_timestamp >= expiry {
                state.circuit_breaker_activated = 0;
            }
        }
    }

    // --- Helpers privés ---

    fn validate_common(
        &self,
        state: &ReserveState,
        _current_timestamp: u64,
    ) -> Result<(), StablecoinError> {
        if state.last_price.tsn_per_xau == 0 {
            return Err(StablecoinError::NoPriceAvailable);
        }
        if state.last_price.confidence == PriceConfidence::Stale {
            return Err(StablecoinError::OracleUnavailable);
        }
        Ok(())
    }

    fn is_circuit_breaker_active(&self, state: &ReserveState, current_timestamp: u64) -> bool {
        if state.circuit_breaker_activated == 0 {
            return false;
        }
        let expiry = state.circuit_breaker_activated + self.engine.config.circuit_breaker_duration;
        current_timestamp < expiry
    }
}
