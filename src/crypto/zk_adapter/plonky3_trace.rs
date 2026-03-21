//! Génération de la trace d'exécution pour l'AIR Plonky3.
//!
//! Ce module prend un `ZkTransactionWitness` (spends, outputs, fee)
//! et génère une matrice de trace (`RowMajorMatrix<Goldilocks>`) compatible
//! avec le système de preuve AIR de Plonky3.
//!
//! ## Trace Layout
//!
//! La trace est organisée en sections par opération :
//!
//! Pour chaque spend :
//! - Calcul du note commitment via Poseidon2 (value, pk_hash, randomness)
//! - Vérification du chemin Merkle (32 niveaux de hash Poseidon2)
//! - Calcul du nullifier (nullifier_key, commitment, position)
//!
//! Pour chaque output :
//! - Calcul du note commitment via Poseidon2 (value, pk_hash, randomness)
//!
//! La dernière ligne encode la contrainte de balance : sum(inputs) = sum(outputs) + fee.
//!
//! ## Trace Width
//!
//! Chaque ligne contient `TRACE_WIDTH` = 16 colonnes de Goldilocks :
//! - Col 0     : type de ligne (0=padding, 1=commitment_hash, 2=merkle_level, 3=nullifier, 4=balance)
//! - Col 1     : index (spend/output index, ou merkle level)
//! - Col 2..9  : état Poseidon2 avant permutation (8 éléments)
//! - Col 10..13: résultat du hash (4 éléments, capacité du sponge)
//! - Col 14    : valeur auxiliaire (bit de chemin Merkle, valeur de note, etc.)
//! - Col 15    : accumulateur de balance
//!
//! La hauteur de la trace est arrondie à la puissance de 2 supérieure.

use p3_field::PrimeCharacteristicRing;
use p3_field::PrimeField64 as P3PrimeField64;
use p3_field::integers::QuotientMap;
use p3_goldilocks::Goldilocks;
use p3_goldilocks::{
    Poseidon2GoldilocksHL, HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS,
    HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::ExternalLayerConstants;
use p3_symmetric::Permutation;

use super::{OutputWitness, SpendWitness};

/// Largeur de la trace (nombre de colonnes).
pub const TRACE_WIDTH: usize = 16;

/// Profondeur de l'arbre Merkle.
const MERKLE_DEPTH: usize = 32;

/// Colonnes de type de ligne.
const COL_ROW_TYPE: usize = 0;
const COL_INDEX: usize = 1;
const COL_STATE_START: usize = 2;
const COL_RESULT_START: usize = 10;
const COL_AUX: usize = 14;
const COL_BALANCE_ACC: usize = 15;

/// Types de lignes dans la trace.
const ROW_TYPE_PADDING: u64 = 0;
const ROW_TYPE_COMMITMENT: u64 = 1;
const ROW_TYPE_MERKLE: u64 = 2;
const ROW_TYPE_NULLIFIER: u64 = 3;
const ROW_TYPE_BALANCE: u64 = 4;
const ROW_TYPE_OUTPUT_COMMITMENT: u64 = 5;

/// Témoin complet pour une transaction ZK.
pub struct ZkTransactionWitness {
    /// Témoins pour les notes dépensées
    pub spends: Vec<SpendWitness>,
    /// Témoins pour les notes créées
    pub outputs: Vec<OutputWitness>,
    /// Frais de transaction
    pub fee: u64,
}

/// Construit la permutation Poseidon2 Goldilocks width-8 avec les constantes Horizen Labs.
fn make_poseidon2_perm() -> Poseidon2GoldilocksHL<8> {
    p3_poseidon2::Poseidon2::new(
        ExternalLayerConstants::<Goldilocks, 8>::new_from_saved_array(
            HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS,
            Goldilocks::new_array,
        ),
        Goldilocks::new_array(HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS).to_vec(),
    )
}

/// Convertit 32 bytes en 4 éléments Goldilocks (8 bytes par élément, little-endian).
fn bytes32_to_goldilocks4(bytes: &[u8; 32]) -> [Goldilocks; 4] {
    let mut result = [Goldilocks::ZERO; 4];
    for i in 0..4 {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let val = u64::from_le_bytes(chunk);
        // Réduction modulo le premier de Goldilocks pour rester dans le champ
        result[i] = <Goldilocks as QuotientMap<u64>>::from_int(val);
    }
    result
}

/// Convertit 4 éléments Goldilocks en 32 bytes (little-endian).
fn goldilocks4_to_bytes32(elems: &[Goldilocks; 4]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..4 {
        let bytes = elems[i].as_canonical_u64().to_le_bytes();
        result[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }
    result
}

/// Hash Poseidon2 de 2 entrées (4 éléments chacune) → 4 éléments de sortie.
///
/// Utilise un sponge width-8 : [input_left(4), input_right(4)] → permute → [output(4), _].
fn poseidon2_hash_pair(
    perm: &Poseidon2GoldilocksHL<8>,
    left: &[Goldilocks; 4],
    right: &[Goldilocks; 4],
) -> ([Goldilocks; 8], [Goldilocks; 4]) {
    let mut state = [Goldilocks::ZERO; 8];
    state[0] = left[0];
    state[1] = left[1];
    state[2] = left[2];
    state[3] = left[3];
    state[4] = right[0];
    state[5] = right[1];
    state[6] = right[2];
    state[7] = right[3];

    let state_before = state;
    perm.permute_mut(&mut state);

    let result = [state[0], state[1], state[2], state[3]];
    (state_before, result)
}

/// Hash Poseidon2 pour un note commitment : H(value, pk_hash[4], randomness[4]).
///
/// Packing : state = [value, pk_hash[0..3], randomness[0..3]] puis permute.
fn poseidon2_hash_commitment(
    perm: &Poseidon2GoldilocksHL<8>,
    value: Goldilocks,
    pk_hash: &[Goldilocks; 4],
    randomness: &[Goldilocks; 4],
) -> ([Goldilocks; 8], [Goldilocks; 4]) {
    let mut state = [Goldilocks::ZERO; 8];
    // Pack: value dans state[0], pk_hash dans state[1..4], randomness dans state[4..7]
    // state[7] reste zéro (padding du sponge, capacité)
    state[0] = value;
    state[1] = pk_hash[0];
    state[2] = pk_hash[1];
    state[3] = pk_hash[2];
    state[4] = randomness[0];
    state[5] = randomness[1];
    state[6] = randomness[2];
    state[7] = randomness[3];

    let state_before = state;
    perm.permute_mut(&mut state);

    let result = [state[0], state[1], state[2], state[3]];
    (state_before, result)
}

/// Hash Poseidon2 pour un nullifier : H(nullifier_key[4], commitment[4]) suivi de
/// H(result[4], position, 0, 0, 0).
fn poseidon2_hash_nullifier(
    perm: &Poseidon2GoldilocksHL<8>,
    nk: &[Goldilocks; 4],
    commitment: &[Goldilocks; 4],
    position: Goldilocks,
) -> ([Goldilocks; 8], [Goldilocks; 8], [Goldilocks; 4]) {
    // Étape 1 : H(nk, commitment)
    let (state1_before, intermediate) = poseidon2_hash_pair(perm, nk, commitment);

    // Étape 2 : H(intermediate, [position, 0, 0, 0])
    let position_block = [position, Goldilocks::ZERO, Goldilocks::ZERO, Goldilocks::ZERO];
    let (state2_before, nullifier) = poseidon2_hash_pair(perm, &intermediate, &position_block);

    (state1_before, state2_before, nullifier)
}

/// Arrondit à la puissance de 2 supérieure ou égale.
fn next_power_of_two(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    n.next_power_of_two()
}

/// Génère la trace d'exécution pour une transaction complète.
///
/// # Arguments
/// * `witness` - Le témoin de la transaction (spends, outputs, fee)
///
/// # Returns
/// * `(trace_matrix, public_values)` où :
///   - `trace_matrix` est une `RowMajorMatrix<Goldilocks>` de largeur `TRACE_WIDTH`
///   - `public_values` contient : [merkle_roots..., nullifiers..., output_commitments..., fee]
///
/// # Trace Structure
///
/// Pour chaque spend (index `i`) :
///   1. 1 ligne `ROW_TYPE_COMMITMENT` : hash du note commitment
///   2. 32 lignes `ROW_TYPE_MERKLE` : vérification du chemin Merkle (un niveau par ligne)
///   3. 2 lignes `ROW_TYPE_NULLIFIER` : hash du nullifier (2 étapes Poseidon2)
///
/// Pour chaque output (index `j`) :
///   1. 1 ligne `ROW_TYPE_OUTPUT_COMMITMENT` : hash du note commitment
///
/// 1 ligne finale `ROW_TYPE_BALANCE` : contrainte sum(inputs) == sum(outputs) + fee
///
/// Le reste est rempli de lignes `ROW_TYPE_PADDING` (tous zéros).
pub fn generate_transaction_trace(
    witness: &ZkTransactionWitness,
) -> (RowMajorMatrix<Goldilocks>, Vec<Goldilocks>) {
    let perm = make_poseidon2_perm();

    // Nombre de lignes utiles :
    // - Par spend : 1 (commitment) + MERKLE_DEPTH (merkle) + 2 (nullifier) = 35
    // - Par output : 1 (commitment)
    // - 1 ligne de balance
    let rows_per_spend: usize = 1 + MERKLE_DEPTH + 2;
    let useful_rows = witness.spends.len() * rows_per_spend + witness.outputs.len() + 1;
    let total_rows = next_power_of_two(useful_rows);

    let mut values = vec![Goldilocks::ZERO; total_rows * TRACE_WIDTH];
    let mut public_values: Vec<Goldilocks> = Vec::new();
    let mut row_idx: usize = 0;

    // Accumulateur de balance : somme des valeurs d'input
    let mut balance_acc = Goldilocks::ZERO;

    // --- Traitement des spends ---
    for (spend_idx, spend) in witness.spends.iter().enumerate() {
        let value_gl = <Goldilocks as QuotientMap<u64>>::from_int(spend.value);
        let pk_hash_gl = bytes32_to_goldilocks4(&spend.recipient_pk_hash);
        let randomness_gl = bytes32_to_goldilocks4(&spend.randomness);
        let nk_gl = bytes32_to_goldilocks4(&spend.nullifier_key);
        let position_gl = <Goldilocks as QuotientMap<u64>>::from_int(spend.position);

        balance_acc = balance_acc + value_gl;

        // 1. Note commitment
        let (state_before, commitment) =
            poseidon2_hash_commitment(&perm, value_gl, &pk_hash_gl, &randomness_gl);

        write_row(
            &mut values,
            row_idx,
            ROW_TYPE_COMMITMENT,
            spend_idx as u64,
            &state_before,
            &commitment,
            value_gl,
            balance_acc,
        );
        row_idx += 1;

        // 2. Vérification Merkle (32 niveaux)
        let mut current_hash = commitment;
        let merkle_path_len = spend.merkle_path.len().min(MERKLE_DEPTH);

        for level in 0..MERKLE_DEPTH {
            let sibling = if level < merkle_path_len {
                bytes32_to_goldilocks4(&spend.merkle_path[level])
            } else {
                // Si le chemin est plus court, utiliser des zéros (empty subtree)
                [Goldilocks::ZERO; 4]
            };

            // Bit de chemin : détermine si current est à gauche ou à droite
            let path_bit = if (spend.leaf_index >> level) & 1 == 0 {
                Goldilocks::ZERO // current est à gauche
            } else {
                Goldilocks::ONE // current est à droite
            };

            let (left, right) = if path_bit == Goldilocks::ZERO {
                (current_hash, sibling)
            } else {
                (sibling, current_hash)
            };

            let (state_before_merkle, parent_hash) = poseidon2_hash_pair(&perm, &left, &right);

            write_row(
                &mut values,
                row_idx,
                ROW_TYPE_MERKLE,
                level as u64,
                &state_before_merkle,
                &parent_hash,
                path_bit,
                balance_acc,
            );
            row_idx += 1;

            current_hash = parent_hash;
        }

        // La racine Merkle calculée est dans current_hash
        let merkle_root_bytes = goldilocks4_to_bytes32(&current_hash);
        // Ajouter la racine Merkle aux valeurs publiques
        for elem in &current_hash {
            public_values.push(*elem);
        }

        // 3. Nullifier (2 étapes de hash)
        let (nf_state1, nf_state2, nullifier) =
            poseidon2_hash_nullifier(&perm, &nk_gl, &commitment, position_gl);

        // Étape 1 du nullifier : H(nk, commitment)
        let nf_intermediate = {
            let mut st = [Goldilocks::ZERO; 8];
            st[..4].copy_from_slice(&nk_gl);
            st[4..8].copy_from_slice(&commitment);
            let mut st2 = st;
            perm.permute_mut(&mut st2);
            [st2[0], st2[1], st2[2], st2[3]]
        };

        write_row(
            &mut values,
            row_idx,
            ROW_TYPE_NULLIFIER,
            spend_idx as u64,
            &nf_state1,
            &nf_intermediate,
            position_gl,
            balance_acc,
        );
        row_idx += 1;

        // Étape 2 du nullifier : H(intermediate, position_block)
        write_row(
            &mut values,
            row_idx,
            ROW_TYPE_NULLIFIER,
            spend_idx as u64,
            &nf_state2,
            &nullifier,
            position_gl,
            balance_acc,
        );
        row_idx += 1;

        // Ajouter le nullifier aux valeurs publiques
        for elem in &nullifier {
            public_values.push(*elem);
        }

        // Ignorer merkle_root_bytes (utilisé implicitement via public_values)
        let _ = merkle_root_bytes;
    }

    // --- Traitement des outputs ---
    for (output_idx, output) in witness.outputs.iter().enumerate() {
        let value_gl = <Goldilocks as QuotientMap<u64>>::from_int(output.value);
        let pk_hash_gl = bytes32_to_goldilocks4(&output.recipient_pk_hash);
        let randomness_gl = bytes32_to_goldilocks4(&output.randomness);

        // Soustraire la valeur de l'output de l'accumulateur
        // (pour la balance finale : acc - sum(outputs) - fee == 0)
        let (state_before, commitment) =
            poseidon2_hash_commitment(&perm, value_gl, &pk_hash_gl, &randomness_gl);

        write_row(
            &mut values,
            row_idx,
            ROW_TYPE_OUTPUT_COMMITMENT,
            output_idx as u64,
            &state_before,
            &commitment,
            value_gl,
            balance_acc,
        );
        row_idx += 1;

        // Ajouter le commitment de l'output aux valeurs publiques
        for elem in &commitment {
            public_values.push(*elem);
        }
    }

    // --- Ligne de balance ---
    // Contrainte : sum(inputs) == sum(outputs) + fee
    // balance_acc contient sum(inputs)
    let fee_gl = <Goldilocks as QuotientMap<u64>>::from_int(witness.fee);
    let total_outputs: u64 = witness.outputs.iter().map(|o| o.value).sum();
    let total_outputs_gl = <Goldilocks as QuotientMap<u64>>::from_int(total_outputs);
    // expected = total_outputs + fee
    let expected = total_outputs_gl + fee_gl;

    {
        let offset = row_idx * TRACE_WIDTH;
        values[offset + COL_ROW_TYPE] = <Goldilocks as QuotientMap<u64>>::from_int(ROW_TYPE_BALANCE);
        values[offset + COL_INDEX] = Goldilocks::ZERO;
        // State : [sum_inputs, sum_outputs, fee, expected, 0, 0, 0, 0]
        values[offset + COL_STATE_START] = balance_acc;
        values[offset + COL_STATE_START + 1] = total_outputs_gl;
        values[offset + COL_STATE_START + 2] = fee_gl;
        values[offset + COL_STATE_START + 3] = expected;
        // Result : la différence (devrait être zéro si balance correcte)
        let diff = balance_acc - expected;
        values[offset + COL_RESULT_START] = diff;
        values[offset + COL_AUX] = fee_gl;
        values[offset + COL_BALANCE_ACC] = balance_acc;
    }
    row_idx += 1;

    // Ajouter le fee aux valeurs publiques
    public_values.push(fee_gl);

    // Les lignes restantes sont déjà à zéro (padding)
    let _ = row_idx;

    let trace = RowMajorMatrix::new(values, TRACE_WIDTH);
    (trace, public_values)
}

/// Écrit une ligne dans le buffer de la trace.
#[inline]
fn write_row(
    values: &mut [Goldilocks],
    row: usize,
    row_type: u64,
    index: u64,
    state: &[Goldilocks; 8],
    result: &[Goldilocks; 4],
    aux: Goldilocks,
    balance_acc: Goldilocks,
) {
    let offset = row * TRACE_WIDTH;
    values[offset + COL_ROW_TYPE] = <Goldilocks as QuotientMap<u64>>::from_int(row_type);
    values[offset + COL_INDEX] = <Goldilocks as QuotientMap<u64>>::from_int(index);
    for i in 0..8 {
        values[offset + COL_STATE_START + i] = state[i];
    }
    for i in 0..4 {
        values[offset + COL_RESULT_START + i] = result[i];
    }
    values[offset + COL_AUX] = aux;
    values[offset + COL_BALANCE_ACC] = balance_acc;
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_matrix::Matrix;

    fn make_test_spend(value: u64) -> SpendWitness {
        let mut merkle_path = Vec::with_capacity(MERKLE_DEPTH);
        for i in 0..MERKLE_DEPTH {
            let mut sibling = [0u8; 32];
            sibling[0] = i as u8;
            merkle_path.push(sibling);
        }

        SpendWitness {
            value,
            recipient_pk_hash: [1u8; 32],
            randomness: [2u8; 32],
            nullifier_key: [3u8; 32],
            position: 0,
            merkle_path,
            leaf_index: 0,
        }
    }

    fn make_test_output(value: u64) -> OutputWitness {
        OutputWitness {
            value,
            recipient_pk_hash: [4u8; 32],
            randomness: [5u8; 32],
        }
    }

    #[test]
    fn test_trace_generation_basic() {
        let witness = ZkTransactionWitness {
            spends: vec![make_test_spend(1000)],
            outputs: vec![make_test_output(950)],
            fee: 50,
        };

        let (trace, public_values) = generate_transaction_trace(&witness);

        // La largeur doit être TRACE_WIDTH
        assert_eq!(trace.width(), TRACE_WIDTH);

        // La hauteur doit être une puissance de 2
        let h = trace.height();
        assert!(h.is_power_of_two(), "Height {} is not power of 2", h);

        // Lignes utiles : 1 spend * (1 + 32 + 2) + 1 output * 1 + 1 balance = 37
        assert!(h >= 37, "Height {} should be >= 37", h);

        // Public values : 4 (merkle_root) + 4 (nullifier) + 4 (output_commitment) + 1 (fee) = 13
        assert_eq!(
            public_values.len(),
            13,
            "Expected 13 public values, got {}",
            public_values.len()
        );

        // Le fee doit être le dernier élément
        let fee_val = public_values.last().unwrap().as_canonical_u64();
        assert_eq!(fee_val, 50);
    }

    #[test]
    fn test_trace_generation_multiple_spends() {
        let witness = ZkTransactionWitness {
            spends: vec![make_test_spend(500), make_test_spend(600)],
            outputs: vec![make_test_output(800), make_test_output(250)],
            fee: 50,
        };

        let (trace, public_values) = generate_transaction_trace(&witness);

        assert_eq!(trace.width(), TRACE_WIDTH);
        assert!(trace.height().is_power_of_two());

        // 2 spends * 35 + 2 outputs + 1 balance = 73
        assert!(trace.height() >= 73);

        // Public values : 2*(4+4) + 2*4 + 1 = 25
        assert_eq!(public_values.len(), 25);
    }

    #[test]
    fn test_trace_power_of_two_padding() {
        let witness = ZkTransactionWitness {
            spends: vec![make_test_spend(100)],
            outputs: vec![make_test_output(90)],
            fee: 10,
        };

        let (trace, _) = generate_transaction_trace(&witness);
        let h = trace.height();

        // Vérifier que les lignes de padding sont toutes à zéro
        let useful = 1 * 35 + 1 + 1; // 37
        for row in useful..h {
            let offset = row * TRACE_WIDTH;
            for col in 0..TRACE_WIDTH {
                assert_eq!(
                    trace.values[offset + col],
                    Goldilocks::ZERO,
                    "Padding row {} col {} should be zero",
                    row,
                    col
                );
            }
        }
    }

    #[test]
    fn test_trace_row_types() {
        let witness = ZkTransactionWitness {
            spends: vec![make_test_spend(1000)],
            outputs: vec![make_test_output(950)],
            fee: 50,
        };

        let (trace, _) = generate_transaction_trace(&witness);

        // Ligne 0 : commitment du spend
        assert_eq!(
            trace.values[0 * TRACE_WIDTH + COL_ROW_TYPE].as_canonical_u64(),
            ROW_TYPE_COMMITMENT
        );

        // Lignes 1..33 : merkle
        for i in 1..33 {
            assert_eq!(
                trace.values[i * TRACE_WIDTH + COL_ROW_TYPE].as_canonical_u64(),
                ROW_TYPE_MERKLE
            );
        }

        // Lignes 33..35 : nullifier
        assert_eq!(
            trace.values[33 * TRACE_WIDTH + COL_ROW_TYPE].as_canonical_u64(),
            ROW_TYPE_NULLIFIER
        );
        assert_eq!(
            trace.values[34 * TRACE_WIDTH + COL_ROW_TYPE].as_canonical_u64(),
            ROW_TYPE_NULLIFIER
        );

        // Ligne 35 : output commitment
        assert_eq!(
            trace.values[35 * TRACE_WIDTH + COL_ROW_TYPE].as_canonical_u64(),
            ROW_TYPE_OUTPUT_COMMITMENT
        );

        // Ligne 36 : balance
        assert_eq!(
            trace.values[36 * TRACE_WIDTH + COL_ROW_TYPE].as_canonical_u64(),
            ROW_TYPE_BALANCE
        );
    }

    #[test]
    fn test_balance_constraint() {
        let witness = ZkTransactionWitness {
            spends: vec![make_test_spend(1000)],
            outputs: vec![make_test_output(950)],
            fee: 50,
        };

        let (trace, _) = generate_transaction_trace(&witness);

        // La ligne de balance (dernière ligne utile = 36)
        let balance_row = 36;
        let offset = balance_row * TRACE_WIDTH;

        // sum_inputs dans state[0]
        let sum_inputs = trace.values[offset + COL_STATE_START].as_canonical_u64();
        assert_eq!(sum_inputs, 1000);

        // sum_outputs dans state[1]
        let sum_outputs = trace.values[offset + COL_STATE_START + 1].as_canonical_u64();
        assert_eq!(sum_outputs, 950);

        // fee dans state[2]
        let fee = trace.values[offset + COL_STATE_START + 2].as_canonical_u64();
        assert_eq!(fee, 50);

        // diff dans result[0] devrait être 0
        let diff = trace.values[offset + COL_RESULT_START].as_canonical_u64();
        assert_eq!(diff, 0, "Balance difference should be zero");
    }

    #[test]
    fn test_deterministic() {
        let witness = ZkTransactionWitness {
            spends: vec![make_test_spend(500)],
            outputs: vec![make_test_output(450)],
            fee: 50,
        };

        let (trace1, pv1) = generate_transaction_trace(&witness);
        let (trace2, pv2) = generate_transaction_trace(&witness);

        assert_eq!(trace1.values, trace2.values);
        assert_eq!(pv1, pv2);
    }

    #[test]
    fn test_empty_transaction() {
        let witness = ZkTransactionWitness {
            spends: vec![],
            outputs: vec![],
            fee: 0,
        };

        let (trace, public_values) = generate_transaction_trace(&witness);

        assert_eq!(trace.width(), TRACE_WIDTH);
        assert!(trace.height().is_power_of_two());
        // Seule la ligne de balance
        assert!(trace.height() >= 1);
        // Public values : juste le fee
        assert_eq!(public_values.len(), 1);
        assert_eq!(public_values[0].as_canonical_u64(), 0);
    }
}
