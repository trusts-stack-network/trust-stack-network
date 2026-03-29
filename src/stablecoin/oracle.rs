// ZST — Oracle Manager
// Agrégation des prix, validation quorum, TWAP, circuit breaker oracle

use crate::stablecoin::config::StablecoinConfig;
use crate::stablecoin::errors::StablecoinError;
use crate::stablecoin::types::*;
use std::collections::VecDeque;

/// Gestionnaire des prix oracle
pub struct OracleManager {
    config: StablecoinConfig,
    /// Prix soumis par les oracles (fenêtre glissante)
    pending_prices: Vec<OraclePrice>,
    /// Historique des prix agrégés pour le TWAP
    price_history: VecDeque<AggregatedPrice>,
    /// Oracles autorisés (clés publiques)
    authorized_oracles: Vec<[u8; 32]>,
    /// Dernier prix agrégé
    current_price: AggregatedPrice,
}

impl OracleManager {
    pub fn new(config: StablecoinConfig) -> Self {
        Self {
            config,
            pending_prices: Vec::new(),
            price_history: VecDeque::with_capacity(64),
            authorized_oracles: Vec::new(),
            current_price: AggregatedPrice::default(),
        }
    }

    /// Enregistre un oracle autorisé
    pub fn register_oracle(&mut self, oracle_id: [u8; 32]) {
        if !self.authorized_oracles.contains(&oracle_id) {
            self.authorized_oracles.push(oracle_id);
        }
    }

    /// Supprime un oracle
    pub fn unregister_oracle(&mut self, oracle_id: &[u8; 32]) {
        self.authorized_oracles.retain(|id| id != oracle_id);
    }

    /// Soumet un prix oracle
    pub fn submit_price(
        &mut self,
        price: OraclePrice,
        current_timestamp: u64,
    ) -> Result<(), StablecoinError> {
        // Vérifier que l'oracle est autorisé
        if !self.authorized_oracles.contains(&price.oracle_id)
            && !self.authorized_oracles.is_empty()
        {
            return Err(StablecoinError::InvalidOracleSignature);
        }

        // Vérifier l'âge du prix
        if current_timestamp > price.timestamp
            && current_timestamp - price.timestamp > self.config.oracle_max_age_secs
        {
            return Err(StablecoinError::OraclePriceStale {
                age_secs: current_timestamp - price.timestamp,
                max_secs: self.config.oracle_max_age_secs,
            });
        }

        // Vérifier les valeurs
        if price.xau_usd == 0 || price.tsn_usd == 0 {
            return Err(StablecoinError::NoPriceAvailable);
        }

        // TODO: Vérifier la signature ML-DSA-65 en production
        // Pour le testnet, on skip la vérification de signature

        // Supprimer les anciens prix du même oracle
        self.pending_prices
            .retain(|p| p.oracle_id != price.oracle_id);

        // Supprimer les prix trop vieux
        self.pending_prices.retain(|p| {
            current_timestamp <= p.timestamp
                || current_timestamp - p.timestamp <= self.config.oracle_max_age_secs
        });

        self.pending_prices.push(price);
        Ok(())
    }

    /// Agrège les prix soumis et produit un prix unique
    pub fn aggregate_prices(
        &mut self,
        current_timestamp: u64,
    ) -> Result<AggregatedPrice, StablecoinError> {
        // Filtrer les prix valides (pas trop vieux)
        let valid_prices: Vec<&OraclePrice> = self
            .pending_prices
            .iter()
            .filter(|p| {
                current_timestamp <= p.timestamp
                    || current_timestamp - p.timestamp <= self.config.oracle_max_age_secs
            })
            .collect();

        let count = valid_prices.len() as u8;
        if count < self.config.oracle_quorum {
            return Err(StablecoinError::OracleQuorumNotMet {
                count,
                required: self.config.oracle_quorum,
            });
        }

        // Calculer TSN/XAU pour chaque oracle
        // tsn_per_xau = xau_usd * MICRO_UNIT / tsn_usd
        let mut tsn_per_xau_values: Vec<u64> = valid_prices
            .iter()
            .filter_map(|p| {
                if p.tsn_usd == 0 {
                    return None;
                }
                let value = (p.xau_usd as u128 * MICRO_UNIT as u128) / p.tsn_usd as u128;
                Some(value.min(u64::MAX as u128) as u64)
            })
            .collect();

        if tsn_per_xau_values.is_empty() {
            return Err(StablecoinError::NoPriceAvailable);
        }

        // Médiane
        tsn_per_xau_values.sort();
        let median = if tsn_per_xau_values.len() % 2 == 0 {
            let mid = tsn_per_xau_values.len() / 2;
            (tsn_per_xau_values[mid - 1] + tsn_per_xau_values[mid]) / 2
        } else {
            tsn_per_xau_values[tsn_per_xau_values.len() / 2]
        };

        // Vérifier la déviation de chaque prix par rapport à la médiane
        if median > 0 {
            for &val in &tsn_per_xau_values {
                let deviation = if val > median {
                    ((val - median) as u128 * BPS_SCALE as u128) / median as u128
                } else {
                    ((median - val) as u128 * BPS_SCALE as u128) / median as u128
                };
                if deviation > self.config.oracle_max_deviation_bps as u128 {
                    return Err(StablecoinError::OracleDeviationTooHigh {
                        deviation_bps: deviation as u64,
                    });
                }
            }
        }

        // Vérifier le circuit breaker oracle (variation vs TWAP)
        if let Some(last) = self.price_history.back() {
            if last.tsn_per_xau > 0 {
                let change = if median > last.tsn_per_xau {
                    ((median - last.tsn_per_xau) as u128 * BPS_SCALE as u128)
                        / last.tsn_per_xau as u128
                } else {
                    ((last.tsn_per_xau - median) as u128 * BPS_SCALE as u128)
                        / last.tsn_per_xau as u128
                };
                if change > self.config.oracle_circuit_breaker_bps as u128 {
                    return Err(StablecoinError::OracleCircuitBreaker {
                        change_bps: change as u64,
                        max_bps: self.config.oracle_circuit_breaker_bps,
                    });
                }
            }
        }

        // Déterminer la confiance
        let confidence = if count >= 4 {
            PriceConfidence::High
        } else if count >= 3 {
            PriceConfidence::Medium
        } else {
            PriceConfidence::Low
        };

        let aggregated = AggregatedPrice {
            tsn_per_xau: median,
            timestamp: current_timestamp,
            oracle_count: count,
            confidence,
        };

        // Ajouter à l'historique pour le TWAP
        self.price_history.push_back(aggregated.clone());
        if self.price_history.len() > self.config.twap_blocks as usize * 2 {
            self.price_history.pop_front();
        }

        self.current_price = aggregated.clone();
        Ok(aggregated)
    }

    /// Calcule le TWAP sur les N derniers blocs
    pub fn calculate_twap(&self) -> Option<u64> {
        let n = self.config.twap_blocks as usize;
        if self.price_history.is_empty() {
            return None;
        }

        let prices: Vec<u64> = self
            .price_history
            .iter()
            .rev()
            .take(n)
            .map(|p| p.tsn_per_xau)
            .collect();

        if prices.is_empty() {
            return None;
        }

        let sum: u128 = prices.iter().map(|&p| p as u128).sum();
        Some((sum / prices.len() as u128) as u64)
    }

    /// Retourne le prix courant (TWAP si disponible, sinon dernier agrégé)
    pub fn get_current_price(&self) -> Result<AggregatedPrice, StablecoinError> {
        if self.current_price.tsn_per_xau == 0 {
            return Err(StablecoinError::NoPriceAvailable);
        }

        // Utiliser le TWAP si on a assez d'historique
        if let Some(twap) = self.calculate_twap() {
            let mut price = self.current_price.clone();
            price.tsn_per_xau = twap;
            Ok(price)
        } else {
            Ok(self.current_price.clone())
        }
    }

    /// Vérifie si le prix est stale
    pub fn is_price_stale(&self, current_timestamp: u64) -> bool {
        if self.current_price.tsn_per_xau == 0 {
            return true;
        }
        if current_timestamp > self.current_price.timestamp {
            return current_timestamp - self.current_price.timestamp
                > self.config.oracle_max_age_secs;
        }
        false
    }

    /// Retourne le nombre d'oracles actifs
    pub fn active_oracle_count(&self) -> usize {
        self.pending_prices.len()
    }

    /// Retourne les oracles enregistrés
    pub fn registered_oracles(&self) -> &[[u8; 32]] {
        &self.authorized_oracles
    }

    /// Retourne l'historique des prix
    pub fn price_history(&self) -> &VecDeque<AggregatedPrice> {
        &self.price_history
    }

    /// Force un prix (pour le testnet / tests)
    pub fn force_price(&mut self, tsn_per_xau: u64, timestamp: u64) {
        let price = AggregatedPrice {
            tsn_per_xau,
            timestamp,
            oracle_count: 1,
            confidence: PriceConfidence::Medium,
        };
        self.price_history.push_back(price.clone());
        self.current_price = price;
    }
}
