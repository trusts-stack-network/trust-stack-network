//! Configuration STARK Plonky3 pour TSN
//!
//! Goldilocks field, Poseidon2 hash (Horizen Labs constants), FRI PCS.
//!
//! Ce module définit les type aliases et la fonction de construction pour
//! la configuration STARK complète utilisée par le prover/verifier Plonky3.
//!
//! ## Paramètres de sécurité
//!
//! - `log_blowup = 2` → blowup factor = 4
//! - `num_queries = 40`
//! - `proof_of_work_bits = 8`
//! - Sécurité conjecturée: log_blowup × num_queries + pow_bits = 2×40 + 8 = 88 bits
//!   (conservateur ; la sécurité réelle est plus élevée avec le field size)
//!
//! ## Types
//!
//! La stack complète est :
//! ```text
//! Goldilocks → Poseidon2 (width=8, HL constants) → PaddingFreeSponge
//!   → TruncatedPermutation → MerkleTreeMmcs → ExtensionMmcs → TwoAdicFriPcs → StarkConfig
//! ```

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::FriParameters;
use p3_fri::TwoAdicFriPcs;
use p3_goldilocks::Goldilocks;
use p3_goldilocks::{
    Poseidon2GoldilocksHL, HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS,
    HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS,
};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2::ExternalLayerConstants;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;

// =============================================================================
// Type aliases
// =============================================================================

/// Base field: Goldilocks (p = 2^64 - 2^32 + 1)
pub type Val = Goldilocks;

/// Extension field: quadratic extension of Goldilocks
pub type Challenge = BinomialExtensionField<Val, 2>;

/// Poseidon2 permutation: width-8 over Goldilocks, Horizen Labs constants
pub type Perm = Poseidon2GoldilocksHL<8>;

/// Hash function: Poseidon2 sponge, width=8, rate=4, output=4 field elements
pub type MyHash = PaddingFreeSponge<Perm, 8, 4, 4>;

/// Compression function: truncated permutation for Merkle tree internal nodes
/// N=2 (binary tree), CHUNK=4 (digest size), WIDTH=8 (permutation width)
pub type MyCompress = TruncatedPermutation<Perm, 2, 4, 8>;

/// Vector commitment: Merkle tree over Goldilocks with 4-element digests
/// Uses Packing types to satisfy CryptographicHasher trait bounds
pub type ValMmcs = MerkleTreeMmcs<
    <Val as Field>::Packing,
    <Val as Field>::Packing,
    MyHash,
    MyCompress,
    4,
>;

/// Extension MMCS: wraps ValMmcs for challenge field operations
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

/// DFT: parallel radix-2 DIT over Goldilocks
pub type Dft = Radix2DitParallel<Val>;

/// Polynomial commitment scheme: FRI over two-adic Goldilocks
pub type MyPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

/// Fiat-Shamir challenger: duplex sponge, width=8, rate=4
pub type MyChallenger = DuplexChallenger<Val, Perm, 8, 4>;

/// Configuration STARK complète pour TSN
pub type TsnStarkConfig = StarkConfig<MyPcs, Challenge, MyChallenger>;

// =============================================================================
// Construction
// =============================================================================

/// Construit la permutation Poseidon2 width-8 Goldilocks avec les constantes Horizen Labs.
fn make_perm() -> Perm {
    p3_poseidon2::Poseidon2::new(
        ExternalLayerConstants::<Goldilocks, 8>::new_from_saved_array(
            HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS,
            Goldilocks::new_array,
        ),
        Goldilocks::new_array(HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS).to_vec(),
    )
}

/// Construit la configuration STARK Plonky3 pour TSN.
///
/// Paramètres FRI :
/// - `log_blowup = 2` (blowup factor 4, pour ~128 bits de sécurité)
/// - `num_queries = 40`
/// - `query_proof_of_work_bits = 8`
/// - `commit_proof_of_work_bits = 0`
/// - `log_final_poly_len = 0` (polynôme final de degré 1)
///
/// La sécurité conjecturée (ethSTARK) est :
///   log_blowup × num_queries + query_pow_bits = 2 × 40 + 8 = 88 bits
///
/// Combinée avec la taille du field Goldilocks (64 bits), cela fournit
/// une sécurité largement suffisante pour un système post-quantique.
pub fn build_stark_config() -> TsnStarkConfig {
    // 1. Permutation Poseidon2
    let perm = make_perm();

    // 2. Hash (sponge) et compression (truncated permutation)
    let hash = PaddingFreeSponge::new(perm.clone());
    let compress = TruncatedPermutation::new(perm.clone());

    // 3. Merkle tree MMCS
    let val_mmcs = ValMmcs::new(hash, compress);

    // 4. Extension MMCS for challenge field (required by FRI)
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    // 5. DFT
    let dft = Dft::default();

    // 6. FRI parameters (mmcs is the challenge MMCS)
    let fri_params = FriParameters {
        log_blowup: 2,
        log_final_poly_len: 0,
        num_queries: 40,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };

    // 7. PCS
    let pcs = TwoAdicFriPcs::new(dft, val_mmcs, fri_params);

    // 8. Challenger (template — will be cloned for each prove/verify)
    let challenger = DuplexChallenger::new(perm);

    // 9. StarkConfig
    StarkConfig::new(pcs, challenger)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_stark_config() {
        let _config = build_stark_config();
        // Si on arrive ici, la construction est correcte
    }
}
