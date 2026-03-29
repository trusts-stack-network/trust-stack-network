// ZST — Moteur de réserve
// Calculs du reserve ratio, prix ZRS, frais dynamiques, simulations

use crate::stablecoin::config::StablecoinConfig;
use crate::stablecoin::errors::StablecoinError;
use crate::stablecoin::types::*;

/// Moteur de calcul de la réserve ZST
pub struct ReserveEngine {
    pub config: StablecoinConfig,
}

impl ReserveEngine {
    pub fn new(config: StablecoinConfig) -> Self {
        Self { config }
    }

    /// Calcule la valeur de la réserve en micro-XAU
    /// reserve_value = reserve_tsn * price_tsn / price_xau
    /// Ici on travaille en TSN atomiques, et tsn_per_xau est en micro-TSN par XAU
    /// Retourne la valeur en unités atomiques ZST (= grammes d'or * 10^8)
    pub fn reserve_value_in_xau(&self, state: &ReserveState) -> Result<u128, StablecoinError> {
        if state.last_price.tsn_per_xau == 0 {
            return Err(StablecoinError::NoPriceAvailable);
        }
        // reserve_tsn est en unités atomiques (10^8)
        // tsn_per_xau est le nombre de micro-TSN pour 1g d'or (10^6)
        // On veut: reserve_value_xau = reserve_tsn / tsn_per_xau (ajusté pour les décimales)
        //
        // reserve_tsn (atomique) / (tsn_per_xau * ATOMIC_UNIT / MICRO_UNIT)
        // = reserve_tsn * MICRO_UNIT / (tsn_per_xau * ATOMIC_UNIT)
        //
        // Simplifié: reserve_tsn * 10^6 / (tsn_per_xau * 10^8)
        //          = reserve_tsn / (tsn_per_xau * 100)
        //
        // En unités atomiques ZST (10^8 par gramme):
        // reserve_value_zst_atomic = reserve_tsn * ATOMIC_UNIT / (tsn_per_xau * 100)
        //
        // Plus simple: reserve_tsn / tsn_per_xau * MICRO_UNIT
        // Mais attention aux overflows et à la précision.
        //
        // Approche: (reserve_tsn * MICRO_UNIT) / tsn_per_xau
        // Cela donne des unités atomiques ZST (10^8 par gramme d'or)
        let numerator = state
            .reserve_tsn
            .checked_mul(MICRO_UNIT as u128)
            .ok_or(StablecoinError::ArithmeticOverflow)?;
        let value = numerator / (state.last_price.tsn_per_xau as u128);
        Ok(value)
    }

    /// Calcule les liabilities (dettes) en unités atomiques ZST
    /// liabilities = supply_zst (car 1 ZST = 1g XAU, et supply_zst est en unités atomiques)
    pub fn liabilities(&self, state: &ReserveState) -> u128 {
        state.supply_zst
    }

    /// Calcule le reserve ratio en bps (10000 = 100%)
    /// ratio = reserve_value / liabilities * 10000
    pub fn calculate_ratio(&self, state: &ReserveState) -> Result<u64, StablecoinError> {
        if state.supply_zst == 0 {
            // Pas de ZST en circulation = ratio infini (max)
            return Ok(u64::MAX);
        }
        let reserve_value = self.reserve_value_in_xau(state)?;
        let liabilities = self.liabilities(state);

        // ratio_bps = reserve_value * BPS_SCALE / liabilities
        let ratio = reserve_value
            .checked_mul(BPS_SCALE as u128)
            .ok_or(StablecoinError::ArithmeticOverflow)?
            / liabilities;

        Ok(ratio.min(u64::MAX as u128) as u64)
    }

    /// Calcule le prix d'un ZRS en unités atomiques TSN
    /// prix_zrs = max(reserve_value - liabilities, 0) / supply_zrs
    /// Converti en TSN atomiques via le prix oracle
    pub fn calculate_zrs_price(&self, state: &ReserveState) -> Result<u128, StablecoinError> {
        if state.supply_zrs == 0 {
            // Pas de ZRS en circulation — prix initial = 1 TSN par ZRS
            return Ok(ATOMIC_UNIT);
        }
        if state.last_price.tsn_per_xau == 0 {
            return Err(StablecoinError::NoPriceAvailable);
        }

        let reserve_value = self.reserve_value_in_xau(state)?;
        let liabilities = self.liabilities(state);

        if reserve_value <= liabilities {
            // Réserve sous-collatéralisée, ZRS vaut 0
            return Ok(0);
        }

        // equity_xau = reserve_value - liabilities (en unités atomiques XAU)
        let equity_xau = reserve_value - liabilities;

        // prix_zrs_xau = equity_xau / supply_zrs (en unités atomiques XAU par ZRS)
        // Convertir en TSN: prix_zrs_tsn = prix_zrs_xau * tsn_per_xau / MICRO_UNIT
        let price_tsn = equity_xau
            .checked_mul(state.last_price.tsn_per_xau as u128)
            .ok_or(StablecoinError::ArithmeticOverflow)?
            / (MICRO_UNIT as u128)
            / state.supply_zrs;

        Ok(price_tsn)
    }

    /// Vérifie si le mint ZST est autorisé (ratio >= min après mint)
    pub fn can_mint_zst(
        &self,
        state: &ReserveState,
        tsn_amount: u128,
    ) -> Result<bool, StablecoinError> {
        let mut simulated = state.clone();
        let fee = self.calculate_mint_fee(state, StablecoinAction::MintZST, tsn_amount)?;
        let tsn_after_fee = tsn_amount.checked_sub(fee).ok_or(StablecoinError::ArithmeticOverflow)?;

        // TSN déposé va dans la réserve
        simulated.reserve_tsn = simulated
            .reserve_tsn
            .checked_add(tsn_after_fee)
            .ok_or(StablecoinError::ArithmeticOverflow)?;

        // ZST créé = tsn_after_fee converti au prix oracle
        let zst_out = self.tsn_to_zst(tsn_after_fee, state.last_price.tsn_per_xau)?;
        simulated.supply_zst = simulated
            .supply_zst
            .checked_add(zst_out)
            .ok_or(StablecoinError::ArithmeticOverflow)?;

        let ratio_after = self.calculate_ratio(&simulated)?;
        Ok(ratio_after >= self.config.min_reserve_ratio)
    }

    /// Vérifie si le burn ZST est autorisé (toujours, sauf circuit breaker/cooldown)
    pub fn can_burn_zst(
        &self,
        state: &ReserveState,
        zst_amount: u128,
        current_timestamp: u64,
    ) -> Result<bool, StablecoinError> {
        // Vérifier circuit breaker
        self.check_circuit_breaker(state, current_timestamp)?;
        // Vérifier cooldown
        self.check_cooldown(state, zst_amount)?;
        Ok(true)
    }

    /// Vérifie si le mint ZRS est autorisé (ratio < max après mint)
    pub fn can_mint_zrs(
        &self,
        state: &ReserveState,
        tsn_amount: u128,
    ) -> Result<bool, StablecoinError> {
        let mut simulated = state.clone();
        let fee = self.calculate_mint_fee(state, StablecoinAction::MintZRS, tsn_amount)?;
        let tsn_after_fee = tsn_amount.checked_sub(fee).ok_or(StablecoinError::ArithmeticOverflow)?;

        simulated.reserve_tsn = simulated
            .reserve_tsn
            .checked_add(tsn_after_fee)
            .ok_or(StablecoinError::ArithmeticOverflow)?;

        let zrs_price = self.calculate_zrs_price(state)?;
        if zrs_price > 0 {
            let zrs_out = tsn_after_fee
                .checked_mul(ATOMIC_UNIT)
                .ok_or(StablecoinError::ArithmeticOverflow)?
                / zrs_price;
            simulated.supply_zrs = simulated
                .supply_zrs
                .checked_add(zrs_out)
                .ok_or(StablecoinError::ArithmeticOverflow)?;
        }

        let ratio_after = self.calculate_ratio(&simulated)?;
        Ok(ratio_after <= self.config.max_reserve_ratio_mint_zrs)
    }

    /// Vérifie si le burn ZRS est autorisé (ratio > min_burn_zrs après burn)
    pub fn can_burn_zrs(
        &self,
        state: &ReserveState,
        zrs_amount: u128,
    ) -> Result<bool, StablecoinError> {
        let mut simulated = state.clone();
        let zrs_price = self.calculate_zrs_price(state)?;

        // TSN à rendre = zrs_amount * zrs_price / ATOMIC_UNIT
        let tsn_out_gross = zrs_amount
            .checked_mul(zrs_price)
            .ok_or(StablecoinError::ArithmeticOverflow)?
            / ATOMIC_UNIT;
        let fee = self.calculate_fee_amount(tsn_out_gross, self.config.fee_burn_zrs_bps)?;
        let tsn_out = tsn_out_gross.checked_sub(fee).ok_or(StablecoinError::ArithmeticOverflow)?;

        simulated.reserve_tsn = simulated.reserve_tsn.saturating_sub(tsn_out);
        simulated.supply_zrs = simulated.supply_zrs.saturating_sub(zrs_amount);

        // Si supply_zst = 0, pas de ratio à vérifier
        if simulated.supply_zst == 0 {
            return Ok(true);
        }

        let ratio_after = self.calculate_ratio(&simulated)?;
        Ok(ratio_after >= self.config.min_reserve_ratio_burn_zrs)
    }

    /// Calcule les frais dynamiques (stress fee) pour le burn ZST
    /// ratio >= 300%: 0.30% (normal)
    /// 200% <= ratio < 300%: 0.30% + (300% - ratio) / 100% * 2% → max 2.30%
    /// 150% <= ratio < 200%: 2.30% + (200% - ratio) / 50% * 2.70% → max 5.00%
    /// ratio < 150%: 5.00%
    pub fn calculate_stress_fee(&self, state: &ReserveState) -> Result<u64, StablecoinError> {
        let ratio = self.calculate_ratio(state)?;
        let base_fee = self.config.fee_burn_zst_bps;

        if ratio >= 30_000 {
            // >= 300% — frais normal
            Ok(base_fee)
        } else if ratio >= 20_000 {
            // 200% <= ratio < 300%
            // Interpolation linéaire: base + (30000 - ratio) / 10000 * 200
            let extra = ((30_000 - ratio) as u128 * 200) / 10_000;
            Ok(base_fee + extra as u64)
        } else if ratio >= 15_000 {
            // 150% <= ratio < 200%
            // fee = 230 + (20000 - ratio) / 5000 * 270
            let extra = ((20_000 - ratio) as u128 * 270) / 5_000;
            Ok(230 + extra as u64)
        } else {
            // < 150% — frais maximum
            Ok(self.config.fee_stress_max_bps)
        }
    }

    /// Calcule les frais pour une opération mint
    pub fn calculate_mint_fee(
        &self,
        state: &ReserveState,
        action: StablecoinAction,
        tsn_amount: u128,
    ) -> Result<u128, StablecoinError> {
        let fee_bps = match action {
            StablecoinAction::MintZST => self.config.fee_mint_zst_bps,
            StablecoinAction::MintZRS => self.config.fee_mint_zrs_bps,
            _ => return Err(StablecoinError::ZeroAmount), // Pas un mint
        };
        self.calculate_fee_amount(tsn_amount, fee_bps)
    }

    /// Calcule les frais pour une opération burn
    pub fn calculate_burn_fee(
        &self,
        state: &ReserveState,
        action: StablecoinAction,
        tsn_amount: u128,
    ) -> Result<u128, StablecoinError> {
        let fee_bps = match action {
            StablecoinAction::BurnZST => self.calculate_stress_fee(state)?,
            StablecoinAction::BurnZRS => self.config.fee_burn_zrs_bps,
            _ => return Err(StablecoinError::ZeroAmount),
        };
        self.calculate_fee_amount(tsn_amount, fee_bps)
    }

    /// Calcule un montant de frais: amount * fee_bps / BPS_SCALE
    /// Arrondi toujours en faveur du protocole (vers le haut)
    pub fn calculate_fee_amount(&self, amount: u128, fee_bps: u64) -> Result<u128, StablecoinError> {
        let numerator = amount
            .checked_mul(fee_bps as u128)
            .ok_or(StablecoinError::ArithmeticOverflow)?;
        // Arrondi vers le haut: (a + b - 1) / b
        let fee = (numerator + BPS_SCALE as u128 - 1) / BPS_SCALE as u128;
        Ok(fee)
    }

    /// Distribue les frais: 80% réserve, 20% trésorerie
    pub fn distribute_fee(&self, fee: u128) -> (u128, u128) {
        let to_reserve = fee * self.config.fee_to_reserve_bps as u128 / BPS_SCALE as u128;
        let to_treasury = fee - to_reserve;
        (to_reserve, to_treasury)
    }

    /// Convertit TSN (atomique) en ZST (atomique) au prix oracle
    /// zst = tsn * MICRO_UNIT / tsn_per_xau
    pub fn tsn_to_zst(&self, tsn_amount: u128, tsn_per_xau: u64) -> Result<u128, StablecoinError> {
        if tsn_per_xau == 0 {
            return Err(StablecoinError::NoPriceAvailable);
        }
        let zst = tsn_amount
            .checked_mul(MICRO_UNIT as u128)
            .ok_or(StablecoinError::ArithmeticOverflow)?
            / (tsn_per_xau as u128);
        Ok(zst)
    }

    /// Convertit ZST (atomique) en TSN (atomique) au prix oracle
    /// tsn = zst * tsn_per_xau / MICRO_UNIT
    pub fn zst_to_tsn(&self, zst_amount: u128, tsn_per_xau: u64) -> Result<u128, StablecoinError> {
        let tsn = zst_amount
            .checked_mul(tsn_per_xau as u128)
            .ok_or(StablecoinError::ArithmeticOverflow)?
            / (MICRO_UNIT as u128);
        Ok(tsn)
    }

    /// Vérifie le circuit breaker
    pub fn check_circuit_breaker(
        &self,
        state: &ReserveState,
        current_timestamp: u64,
    ) -> Result<(), StablecoinError> {
        if state.circuit_breaker_activated > 0 {
            let expiry = state.circuit_breaker_activated + self.config.circuit_breaker_duration;
            if current_timestamp < expiry {
                return Err(StablecoinError::CircuitBreakerActive {
                    until_timestamp: expiry,
                });
            }
        }
        Ok(())
    }

    /// Vérifie le cooldown de burn ZST par bloc
    pub fn check_cooldown(
        &self,
        state: &ReserveState,
        zst_amount: u128,
    ) -> Result<(), StablecoinError> {
        if state.supply_zst == 0 {
            return Ok(());
        }
        let max_burn = state.supply_zst * self.config.cooldown_max_burn_pct as u128
            / BPS_SCALE as u128;
        let total_burned = state.current_block_burned_zst + zst_amount;
        if total_burned > max_burn {
            return Err(StablecoinError::CooldownExceeded {
                requested: total_burned,
                max_allowed: max_burn,
            });
        }
        Ok(())
    }

    /// Simule un mint ZST et retourne le résultat prévu
    pub fn simulate_mint_zst(
        &self,
        state: &ReserveState,
        tsn_amount: u128,
    ) -> Result<MintBurnResult, StablecoinError> {
        if tsn_amount == 0 {
            return Err(StablecoinError::ZeroAmount);
        }
        if state.last_price.tsn_per_xau == 0 {
            return Err(StablecoinError::NoPriceAvailable);
        }

        let ratio_before = self.calculate_ratio(state)?;
        let fee = self.calculate_mint_fee(state, StablecoinAction::MintZST, tsn_amount)?;
        let (fee_reserve, fee_treasury) = self.distribute_fee(fee);
        let tsn_after_fee = tsn_amount.checked_sub(fee).ok_or(StablecoinError::ArithmeticOverflow)?;
        let zst_out = self.tsn_to_zst(tsn_after_fee, state.last_price.tsn_per_xau)?;

        // Simuler l'état après
        let mut after = state.clone();
        after.reserve_tsn += tsn_after_fee + fee_reserve;
        after.treasury_tsn += fee_treasury;
        after.supply_zst += zst_out;
        let ratio_after = self.calculate_ratio(&after)?;

        if ratio_after < self.config.min_reserve_ratio {
            return Err(StablecoinError::ReserveRatioTooLow {
                current: ratio_after,
                minimum: self.config.min_reserve_ratio,
            });
        }

        Ok(MintBurnResult {
            action: StablecoinAction::MintZST,
            amount_in: tsn_amount,
            amount_out: zst_out,
            fee,
            fee_treasury,
            fee_reserve,
            ratio_before,
            ratio_after,
            price_used: state.last_price.tsn_per_xau,
        })
    }

    /// Simule un burn ZST et retourne le résultat prévu
    pub fn simulate_burn_zst(
        &self,
        state: &ReserveState,
        zst_amount: u128,
        current_timestamp: u64,
    ) -> Result<MintBurnResult, StablecoinError> {
        if zst_amount == 0 {
            return Err(StablecoinError::ZeroAmount);
        }
        if state.last_price.tsn_per_xau == 0 {
            return Err(StablecoinError::NoPriceAvailable);
        }
        if zst_amount > state.supply_zst {
            return Err(StablecoinError::ZeroAmount);
        }

        self.check_circuit_breaker(state, current_timestamp)?;
        self.check_cooldown(state, zst_amount)?;

        let ratio_before = self.calculate_ratio(state)?;
        let tsn_gross = self.zst_to_tsn(zst_amount, state.last_price.tsn_per_xau)?;
        let stress_fee_bps = self.calculate_stress_fee(state)?;
        let fee = self.calculate_fee_amount(tsn_gross, stress_fee_bps)?;
        let (fee_reserve, fee_treasury) = self.distribute_fee(fee);
        let tsn_out = tsn_gross.checked_sub(fee).ok_or(StablecoinError::ArithmeticOverflow)?;

        let mut after = state.clone();
        // La réserve perd le TSN gross rendu, mais récupère la part des frais
        after.reserve_tsn = after.reserve_tsn.saturating_sub(tsn_gross);
        after.reserve_tsn += fee_reserve;
        after.treasury_tsn += fee_treasury;
        after.supply_zst -= zst_amount;
        let ratio_after = self.calculate_ratio(&after)?;

        Ok(MintBurnResult {
            action: StablecoinAction::BurnZST,
            amount_in: zst_amount,
            amount_out: tsn_out,
            fee,
            fee_treasury,
            fee_reserve,
            ratio_before,
            ratio_after,
            price_used: state.last_price.tsn_per_xau,
        })
    }

    /// Simule un mint ZRS
    pub fn simulate_mint_zrs(
        &self,
        state: &ReserveState,
        tsn_amount: u128,
    ) -> Result<MintBurnResult, StablecoinError> {
        if tsn_amount == 0 {
            return Err(StablecoinError::ZeroAmount);
        }
        if state.last_price.tsn_per_xau == 0 {
            return Err(StablecoinError::NoPriceAvailable);
        }

        let ratio_before = self.calculate_ratio(state)?;
        let fee = self.calculate_mint_fee(state, StablecoinAction::MintZRS, tsn_amount)?;
        let (fee_reserve, fee_treasury) = self.distribute_fee(fee);
        let tsn_after_fee = tsn_amount.checked_sub(fee).ok_or(StablecoinError::ArithmeticOverflow)?;

        let zrs_price = self.calculate_zrs_price(state)?;
        let zrs_out = if zrs_price > 0 {
            tsn_after_fee
                .checked_mul(ATOMIC_UNIT)
                .ok_or(StablecoinError::ArithmeticOverflow)?
                / zrs_price
        } else {
            // Prix initial: 1 ZRS = 1 TSN
            tsn_after_fee
        };

        let mut after = state.clone();
        after.reserve_tsn += tsn_after_fee + fee_reserve;
        after.treasury_tsn += fee_treasury;
        after.supply_zrs += zrs_out;
        let ratio_after = self.calculate_ratio(&after)?;

        if ratio_after > self.config.max_reserve_ratio_mint_zrs {
            return Err(StablecoinError::ReserveRatioTooHigh {
                current: ratio_after,
                maximum: self.config.max_reserve_ratio_mint_zrs,
            });
        }

        Ok(MintBurnResult {
            action: StablecoinAction::MintZRS,
            amount_in: tsn_amount,
            amount_out: zrs_out,
            fee,
            fee_treasury,
            fee_reserve,
            ratio_before,
            ratio_after,
            price_used: state.last_price.tsn_per_xau,
        })
    }

    /// Simule un burn ZRS
    pub fn simulate_burn_zrs(
        &self,
        state: &ReserveState,
        zrs_amount: u128,
    ) -> Result<MintBurnResult, StablecoinError> {
        if zrs_amount == 0 {
            return Err(StablecoinError::ZeroAmount);
        }
        if state.last_price.tsn_per_xau == 0 {
            return Err(StablecoinError::NoPriceAvailable);
        }
        if zrs_amount > state.supply_zrs {
            return Err(StablecoinError::ZeroAmount);
        }

        let ratio_before = self.calculate_ratio(state)?;
        let zrs_price = self.calculate_zrs_price(state)?;

        let tsn_gross = zrs_amount
            .checked_mul(zrs_price)
            .ok_or(StablecoinError::ArithmeticOverflow)?
            / ATOMIC_UNIT;

        let fee = self.calculate_fee_amount(tsn_gross, self.config.fee_burn_zrs_bps)?;
        let (fee_reserve, fee_treasury) = self.distribute_fee(fee);
        let tsn_out = tsn_gross.checked_sub(fee).ok_or(StablecoinError::ArithmeticOverflow)?;

        let mut after = state.clone();
        after.reserve_tsn = after.reserve_tsn.saturating_sub(tsn_gross);
        after.reserve_tsn += fee_reserve;
        after.treasury_tsn += fee_treasury;
        after.supply_zrs -= zrs_amount;
        let ratio_after = self.calculate_ratio(&after)?;

        if ratio_after < self.config.min_reserve_ratio_burn_zrs && state.supply_zst > 0 {
            return Err(StablecoinError::ReserveRatioTooLowForBurnZrs {
                current: ratio_after,
                minimum: self.config.min_reserve_ratio_burn_zrs,
            });
        }

        Ok(MintBurnResult {
            action: StablecoinAction::BurnZRS,
            amount_in: zrs_amount,
            amount_out: tsn_out,
            fee,
            fee_treasury,
            fee_reserve,
            ratio_before,
            ratio_after,
            price_used: state.last_price.tsn_per_xau,
        })
    }
}
