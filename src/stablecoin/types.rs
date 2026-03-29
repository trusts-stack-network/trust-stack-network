// ZST — TSN Gold Stable Protocol
// Types de données principaux

use serde::{Deserialize, Serialize};

/// Type d'actif dans le protocole ZST
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssetType {
    /// Token natif TSN (collatéral)
    TSN = 0,
    /// ZST Gold Stable (1 ZST = 1g XAU)
    ZST = 1,
    /// ZRS Reserve Share (absorbe la volatilité)
    ZRS = 2,
}

impl std::fmt::Display for AssetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetType::TSN => write!(f, "TSN"),
            AssetType::ZST => write!(f, "ZST"),
            AssetType::ZRS => write!(f, "ZRS"),
        }
    }
}

/// Prix soumis par un opérateur d'oracle
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OraclePrice {
    /// Prix de l'or en microdollars (ex: 2_300_000_000 = $2300.00)
    pub xau_usd: u64,
    /// Prix du TSN en microdollars (ex: 1_500_000 = $1.50)
    pub tsn_usd: u64,
    /// Unix timestamp de la soumission
    pub timestamp: u64,
    /// Hauteur du bloc de soumission
    pub block_height: u64,
    /// Clé publique de l'opérateur d'oracle
    pub oracle_id: [u8; 32],
    /// Signature ML-DSA-65
    pub signature: Vec<u8>,
}

/// Niveau de confiance du prix agrégé
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PriceConfidence {
    /// >= 4 oracles, faible déviation
    High,
    /// 3 oracles ou déviation modérée
    Medium,
    /// Quorum minimum, déviation élevée
    Low,
    /// Prix expiré
    Stale,
}

/// Prix agrégé après médiane + TWAP
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedPrice {
    /// Combien de micro-TSN pour 1g d'or
    /// Ex: si 1 TSN = $1.50 et 1g or = $95, alors tsn_per_xau = 63_333_333 (~63.33 TSN)
    /// Stocké avec 6 décimales de précision (micro-unités)
    pub tsn_per_xau: u64,
    /// Timestamp du prix
    pub timestamp: u64,
    /// Nombre d'oracles ayant contribué
    pub oracle_count: u8,
    /// Niveau de confiance
    pub confidence: PriceConfidence,
}

impl Default for AggregatedPrice {
    fn default() -> Self {
        Self {
            tsn_per_xau: 0,
            timestamp: 0,
            oracle_count: 0,
            confidence: PriceConfidence::Stale,
        }
    }
}

/// État global de la réserve du protocole ZST
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReserveState {
    /// Total TSN dans la réserve (en unités atomiques, 8 décimales)
    pub reserve_tsn: u128,
    /// Total ZST en circulation
    pub supply_zst: u128,
    /// Total ZRS en circulation
    pub supply_zrs: u128,
    /// Dernier prix agrégé
    pub last_price: AggregatedPrice,
    /// Frais accumulés pour la trésorerie
    pub treasury_tsn: u128,
    /// Hauteur du dernier bloc traité
    pub last_block_height: u64,
    /// Timestamp d'activation du circuit breaker (0 = inactif)
    pub circuit_breaker_activated: u64,
    /// Montant ZST brûlé dans le bloc courant (pour cooldown)
    pub current_block_burned_zst: u128,
    /// Hauteur du bloc courant pour le tracking cooldown
    pub current_block_height: u64,
}

impl Default for ReserveState {
    fn default() -> Self {
        Self {
            reserve_tsn: 0,
            supply_zst: 0,
            supply_zrs: 0,
            last_price: AggregatedPrice::default(),
            treasury_tsn: 0,
            last_block_height: 0,
            circuit_breaker_activated: 0,
            current_block_burned_zst: 0,
            current_block_height: 0,
        }
    }
}

/// Action stablecoin possible
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StablecoinAction {
    /// Déposer TSN → recevoir ZST
    MintZST,
    /// Brûler ZST → récupérer TSN
    BurnZST,
    /// Déposer TSN → recevoir ZRS
    MintZRS,
    /// Brûler ZRS → récupérer TSN
    BurnZRS,
}

impl std::fmt::Display for StablecoinAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StablecoinAction::MintZST => write!(f, "MintZST"),
            StablecoinAction::BurnZST => write!(f, "BurnZST"),
            StablecoinAction::MintZRS => write!(f, "MintZRS"),
            StablecoinAction::BurnZRS => write!(f, "BurnZRS"),
        }
    }
}

/// Requête de mint/burn
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintBurnRequest {
    /// Action demandée
    pub action: StablecoinAction,
    /// Montant d'entrée (en unités atomiques)
    pub amount_in: u128,
    /// Montant minimum de sortie (slippage protection)
    pub min_amount_out: u128,
    /// Hauteur du bloc du prix oracle utilisé
    pub price_ref: u64,
}

/// Résultat d'une opération mint/burn
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintBurnResult {
    /// Action effectuée
    pub action: StablecoinAction,
    /// Montant d'entrée consommé
    pub amount_in: u128,
    /// Montant de sortie produit
    pub amount_out: u128,
    /// Frais prélevés (en TSN)
    pub fee: u128,
    /// Frais vers la trésorerie (20%)
    pub fee_treasury: u128,
    /// Frais vers la réserve (80%)
    pub fee_reserve: u128,
    /// Reserve ratio avant l'opération (en bps, ex: 40000 = 400%)
    pub ratio_before: u64,
    /// Reserve ratio après l'opération
    pub ratio_after: u64,
    /// Prix oracle utilisé (TSN par XAU)
    pub price_used: u64,
}

/// Transaction stablecoin shielded (pour l'intégration future)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedMintBurn {
    /// Action
    pub action: StablecoinAction,
    /// Nullifiers des notes détruites
    pub nullifiers_in: Vec<[u8; 32]>,
    /// Commitments des notes créées
    pub commitments_out: Vec<[u8; 32]>,
    /// Hauteur du bloc du prix oracle utilisé
    pub price_ref_height: u64,
    /// Preuve Plonky3
    pub proof: Vec<u8>,
    /// Commitment des frais
    pub fee_commitment: [u8; 32],
}

/// Transaction stablecoin (extension du Transaction existant)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StablecoinTx {
    /// Soumission de prix oracle
    OracleSubmit(OraclePrice),
    /// Mint transparent (phase 1-2)
    MintTransparent(MintBurnRequest),
    /// Burn transparent (phase 1-2)
    BurnTransparent(MintBurnRequest),
    /// Mint shielded (phase 3+)
    MintShielded(ShieldedMintBurn),
    /// Burn shielded (phase 3+)
    BurnShielded(ShieldedMintBurn),
}

/// Constantes de précision
pub const DECIMALS: u32 = 8;
pub const ATOMIC_UNIT: u128 = 100_000_000; // 10^8
pub const BPS_SCALE: u64 = 10_000; // 100% = 10000 bps
pub const MICRO_UNIT: u64 = 1_000_000; // Pour les prix en micro-unités
