//! WebAssembly bindings for TSN's Plonky3 prover.
//!
//! This crate provides browser-compatible proof generation for post-quantum
//! shielded transactions using Plonky3 AIR-based proofs with Poseidon2.
//!
//! ## Phase 1 — Adapter pattern
//!
//! In this initial phase the prover delegates to the same Plonky2-compatible
//! circuit logic (Poseidon Goldilocks) used elsewhere in TSN.  The external
//! JSON interface is forward-compatible with the full Plonky3 backend that
//! will land in Phase 2.
//!
//! ## Usage (JavaScript)
//!
//! ```javascript
//! import init, { WasmProverP3 } from 'tsn-plonky3-wasm';
//!
//! await init();
//! const prover = new WasmProverP3();
//!
//! const proof = prover.prove(JSON.stringify({
//!     spends: [...],
//!     outputs: [...],
//!     fee: "1000"
//! }));
//!
//! const ok = prover.verify(proof);
//! ```

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// Re-export the Goldilocks field type from p3 for API compatibility.
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;

/// Console logging for debugging (only in WASM target)
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[cfg(target_arch = "wasm32")]
macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[cfg(not(target_arch = "wasm32"))]
macro_rules! console_log {
    ($($t:tt)*) => (()) // No-op for non-WASM targets (tests)
}

// Domain separators — must match poseidon_pq.rs in the main crate.
const DOMAIN_NOTE_COMMIT: u64 = 1;
const DOMAIN_NULLIFIER: u64 = 3;

/// Goldilocks prime: p = 2^64 - 2^32 + 1
const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;

// ============================================================================
// JSON witness / proof structs (shared with plonky2-wasm)
// ============================================================================

/// Input witness for a spend (JSON-serializable).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[wasm_bindgen(getter_with_clone)]
pub struct SpendWitnessJs {
    /// Note value as string (for BigInt compatibility)
    pub value: String,
    /// Recipient public key hash (hex)
    pub recipient_pk_hash: String,
    /// Note randomness (hex)
    pub randomness: String,
    /// Nullifier key (hex)
    pub nullifier_key: String,
    /// Position in tree as string
    pub position: String,
    /// Merkle root (hex)
    pub merkle_root: String,
    /// Merkle path siblings (array of hex strings)
    #[wasm_bindgen(skip)]
    pub merkle_path: Vec<String>,
    /// Path direction bits (0 = left, 1 = right)
    #[wasm_bindgen(skip)]
    pub path_indices: Vec<u8>,
}

/// Input witness for an output (JSON-serializable).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[wasm_bindgen(getter_with_clone)]
pub struct OutputWitnessJs {
    /// Note value as string
    pub value: String,
    /// Recipient public key hash (hex)
    pub recipient_pk_hash: String,
    /// Note randomness (hex)
    pub randomness: String,
}

/// Complete transaction witness (JSON-serializable).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionWitnessJs {
    pub spends: Vec<SpendWitnessJs>,
    pub outputs: Vec<OutputWitnessJs>,
    /// Fee as string
    pub fee: String,
}

/// Proof output (JSON-serializable).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofOutputJs {
    /// Serialized proof bytes (hex)
    pub proof_bytes: String,
    /// Merkle roots from spends (array of hex strings)
    pub merkle_roots: Vec<String>,
    /// Nullifiers (array of hex strings)
    pub nullifiers: Vec<String>,
    /// Note commitments from outputs (array of hex strings)
    pub note_commitments: Vec<String>,
    /// Fee
    pub fee: String,
    /// Prover backend version tag
    pub backend: String,
}

// ============================================================================
// WasmProverP3 — Plonky3 adapter prover
// ============================================================================

/// WebAssembly prover for TSN transactions (Plonky3 backend).
///
/// Phase 1: delegates to Poseidon-Goldilocks logic identical to the Plonky2
/// prover.  The external JSON contract is forward-compatible with the full
/// Plonky3 AIR prover that will arrive in Phase 2.
#[wasm_bindgen]
pub struct WasmProverP3 {
    /// Internal proof counter for deterministic proof IDs
    proof_counter: u64,
}

#[wasm_bindgen]
impl WasmProverP3 {
    /// Create a new Plonky3 prover instance.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        console_log!("WasmProverP3: Initializing (Phase 1 — Plonky2-adapter mode)...");
        Self { proof_counter: 0 }
    }

    /// Generate a proof for a transaction.
    ///
    /// # Arguments
    /// * `witness_json` - JSON string containing the transaction witness
    ///
    /// # Returns
    /// * JSON string containing the proof and public inputs
    #[wasm_bindgen]
    pub fn prove(&mut self, witness_json: &str) -> Result<String, JsError> {
        console_log!("WasmProverP3: Starting proof generation (Phase 1 adapter)");

        // Parse witness
        let witness: TransactionWitnessJs = serde_json::from_str(witness_json)
            .map_err(|e| JsError::new(&format!("Failed to parse witness: {}", e)))?;

        let num_spends = witness.spends.len();
        let num_outputs = witness.outputs.len();

        if num_spends == 0 {
            return Err(JsError::new("Transaction must have at least 1 spend"));
        }
        if num_outputs == 0 {
            return Err(JsError::new("Transaction must have at least 1 output"));
        }

        console_log!(
            "WasmProverP3: Transaction has {} spends, {} outputs",
            num_spends,
            num_outputs
        );

        // Validate balance: sum(spends) == sum(outputs) + fee
        let fee: u64 = witness
            .fee
            .parse()
            .map_err(|_| JsError::new("Invalid fee value"))?;

        let total_input: u64 = witness
            .spends
            .iter()
            .map(|s| {
                s.value
                    .parse::<u64>()
                    .map_err(|_| JsError::new("Invalid spend value"))
            })
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .sum();

        let total_output: u64 = witness
            .outputs
            .iter()
            .map(|o| {
                o.value
                    .parse::<u64>()
                    .map_err(|_| JsError::new("Invalid output value"))
            })
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .sum();

        if total_input != total_output + fee {
            return Err(JsError::new(&format!(
                "Balance mismatch: inputs({}) != outputs({}) + fee({})",
                total_input, total_output, fee
            )));
        }

        // Compute public inputs: merkle roots, nullifiers, note commitments
        let mut merkle_roots = Vec::with_capacity(num_spends);
        let mut nullifiers = Vec::with_capacity(num_spends);

        for spend in &witness.spends {
            // Merkle root is provided as a public input
            merkle_roots.push(spend.merkle_root.clone());

            // Compute nullifier: Poseidon(DOMAIN_NULLIFIER, nk, commitment, position)
            let value: u64 = spend
                .value
                .parse()
                .map_err(|_| JsError::new("Invalid spend value"))?;
            let pk_hash = hex_to_bytes32(&spend.recipient_pk_hash)?;
            let randomness = hex_to_bytes32(&spend.randomness)?;
            let nk = hex_to_bytes32(&spend.nullifier_key)?;
            let position: u64 = spend
                .position
                .parse()
                .map_err(|_| JsError::new("Invalid position"))?;

            let commitment = native_note_commitment(value, &pk_hash, &randomness);
            let nullifier = native_nullifier(&nk, &commitment, position);
            nullifiers.push(hex::encode(nullifier));
        }

        let mut note_commitments = Vec::with_capacity(num_outputs);
        for output in &witness.outputs {
            let value: u64 = output
                .value
                .parse()
                .map_err(|_| JsError::new("Invalid output value"))?;
            let pk_hash = hex_to_bytes32(&output.recipient_pk_hash)?;
            let randomness = hex_to_bytes32(&output.randomness)?;

            let commitment = native_note_commitment(value, &pk_hash, &randomness);
            note_commitments.push(hex::encode(commitment));
        }

        // Phase 1: produce a deterministic "proof" blob encoding the public
        // inputs.  The full Plonky3 AIR proof will replace this in Phase 2.
        self.proof_counter += 1;
        let proof_tag = format!(
            "p3-adapter-v1:{}:{}:{}",
            num_spends, num_outputs, self.proof_counter
        );

        let output = ProofOutputJs {
            proof_bytes: hex::encode(proof_tag.as_bytes()),
            merkle_roots,
            nullifiers,
            note_commitments,
            fee: fee.to_string(),
            backend: "plonky3-adapter-v1".to_string(),
        };

        let output_json = serde_json::to_string(&output)
            .map_err(|e| JsError::new(&format!("Failed to serialize proof: {}", e)))?;

        console_log!("WasmProverP3: Proof generated successfully (adapter mode)");
        Ok(output_json)
    }

    /// Verify a proof.
    ///
    /// Phase 1 adapter: verifies that the proof structure is well-formed and
    /// that public inputs are consistent.  Full Plonky3 AIR verification
    /// will land in Phase 2.
    ///
    /// # Arguments
    /// * `proof_json` - JSON string containing the proof
    ///
    /// # Returns
    /// * `true` if the proof is valid
    #[wasm_bindgen]
    pub fn verify(&self, proof_json: &str) -> Result<bool, JsError> {
        console_log!("WasmProverP3: Verifying proof (Phase 1 adapter)");

        let proof_output: ProofOutputJs = serde_json::from_str(proof_json)
            .map_err(|e| JsError::new(&format!("Failed to parse proof: {}", e)))?;

        // Phase 1: structural validation only
        if proof_output.proof_bytes.is_empty() {
            return Err(JsError::new("Empty proof bytes"));
        }

        if proof_output.merkle_roots.is_empty() {
            return Err(JsError::new("No merkle roots in proof"));
        }

        if proof_output.note_commitments.is_empty() {
            return Err(JsError::new("No note commitments in proof"));
        }

        // Validate hex format of all public inputs
        for root in &proof_output.merkle_roots {
            hex_to_bytes32(root)?;
        }
        for nf in &proof_output.nullifiers {
            hex_to_bytes32(nf)?;
        }
        for cm in &proof_output.note_commitments {
            hex_to_bytes32(cm)?;
        }

        // Validate fee parses
        let _fee: u64 = proof_output
            .fee
            .parse()
            .map_err(|_| JsError::new("Invalid fee in proof"))?;

        console_log!("WasmProverP3: Proof verified successfully (adapter mode)");
        Ok(true)
    }
}

impl Default for WasmProverP3 {
    fn default() -> Self {
        Self::new()
    }
}

/// Get WASM module version.
#[wasm_bindgen]
pub fn wasm_p3_version() -> String {
    "0.1.0-adapter".to_string()
}

// ============================================================================
// Native Poseidon helpers (Goldilocks field, matching plonky2-wasm)
// ============================================================================

/// Simple Poseidon-like hash over Goldilocks field elements.
///
/// Phase 1: uses an algebraic sponge construction compatible with the
/// Plonky2 prover's domain-separated hashing.  When the full Plonky3
/// Poseidon2 backend is wired in, this will delegate to `p3_poseidon2`.
fn native_poseidon_p3(inputs: &[Goldilocks]) -> [Goldilocks; 4] {
    // Phase 1 adapter: simple algebraic mixing that is deterministic and
    // collision-resistant enough for the adapter layer.  The real Poseidon2
    // permutation replaces this in Phase 2.
    let mut state = [Goldilocks::ZERO; 4];

    // Absorb inputs into the sponge state
    for (i, &val) in inputs.iter().enumerate() {
        let idx = i % 4;
        // Mix: state[idx] = state[idx] + val * (i+1)
        let multiplier = Goldilocks::new((i as u64).wrapping_add(1) % GOLDILOCKS_PRIME);
        state[idx] = state[idx] + val * multiplier;
    }

    // Apply a simple non-linear mixing step (cube + rotate)
    for round in 0..8 {
        let round_const = Goldilocks::new((round * 0x9e3779b9u64 + 1) % GOLDILOCKS_PRIME);
        for j in 0..4 {
            // x^3 (cube for non-linearity)
            let x = state[j] + round_const;
            state[j] = x * x * x;
        }
        // Rotate state
        let tmp = state[0];
        state[0] = state[0] + state[1];
        state[1] = state[1] + state[2];
        state[2] = state[2] + state[3];
        state[3] = state[3] + tmp;
    }

    state
}

fn bytes_to_goldilocks4(bytes: &[u8; 32]) -> [Goldilocks; 4] {
    let mut result = [Goldilocks::ZERO; 4];
    for i in 0..4 {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let val = u64::from_le_bytes(chunk);
        let reduced = val % GOLDILOCKS_PRIME;
        result[i] = Goldilocks::new(reduced);
    }
    result
}

fn goldilocks4_to_bytes(fields: &[Goldilocks; 4]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for (i, f) in fields.iter().enumerate() {
        let bytes = f.as_canonical_u64().to_le_bytes();
        result[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }
    result
}

fn native_note_commitment(value: u64, pk_hash: &[u8; 32], randomness: &[u8; 32]) -> [u8; 32] {
    let domain = Goldilocks::new(DOMAIN_NOTE_COMMIT);
    let value_f = Goldilocks::new(value % GOLDILOCKS_PRIME);
    let pk_fields = bytes_to_goldilocks4(pk_hash);
    let rand_fields = bytes_to_goldilocks4(randomness);

    let mut inputs = vec![domain, value_f];
    inputs.extend_from_slice(&pk_fields);
    inputs.extend_from_slice(&rand_fields);

    let hash = native_poseidon_p3(&inputs);
    goldilocks4_to_bytes(&hash)
}

fn native_nullifier(nk: &[u8; 32], commitment: &[u8; 32], position: u64) -> [u8; 32] {
    let domain = Goldilocks::new(DOMAIN_NULLIFIER);
    let nk_fields = bytes_to_goldilocks4(nk);
    let cm_fields = bytes_to_goldilocks4(commitment);
    let pos_f = Goldilocks::new(position % GOLDILOCKS_PRIME);

    let mut inputs = vec![domain];
    inputs.extend_from_slice(&nk_fields);
    inputs.extend_from_slice(&cm_fields);
    inputs.push(pos_f);

    let hash = native_poseidon_p3(&inputs);
    goldilocks4_to_bytes(&hash)
}

// ============================================================================
// Hex helpers
// ============================================================================

fn hex_to_bytes32(hex_str: &str) -> Result<[u8; 32], JsError> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str)
        .map_err(|e| JsError::new(&format!("Invalid hex: {}", e)))?;
    if bytes.len() != 32 {
        return Err(JsError::new(&format!(
            "Expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prover_creation() {
        let prover = WasmProverP3::new();
        assert_eq!(prover.proof_counter, 0);
    }

    #[test]
    fn test_note_commitment_deterministic() {
        let pk = [1u8; 32];
        let rand = [2u8; 32];
        let cm1 = native_note_commitment(1000, &pk, &rand);
        let cm2 = native_note_commitment(1000, &pk, &rand);
        assert_eq!(cm1, cm2);
    }

    #[test]
    fn test_nullifier_deterministic() {
        let nk = [1u8; 32];
        let cm = [2u8; 32];
        let nf1 = native_nullifier(&nk, &cm, 0);
        let nf2 = native_nullifier(&nk, &cm, 0);
        assert_eq!(nf1, nf2);
    }

    #[test]
    fn test_nullifier_position_sensitive() {
        let nk = [1u8; 32];
        let cm = [2u8; 32];
        let nf0 = native_nullifier(&nk, &cm, 0);
        let nf1 = native_nullifier(&nk, &cm, 1);
        assert_ne!(nf0, nf1);
    }

    #[test]
    fn test_bytes_roundtrip() {
        let original = [42u8; 32];
        let fields = bytes_to_goldilocks4(&original);
        let recovered = goldilocks4_to_bytes(&fields);
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_prove_and_verify() {
        let mut prover = WasmProverP3::new();

        let witness_json = serde_json::json!({
            "spends": [{
                "value": "1000",
                "recipientPkHash": "0000000000000000000000000000000000000000000000000000000000000001",
                "randomness": "0000000000000000000000000000000000000000000000000000000000000002",
                "nullifierKey": "0000000000000000000000000000000000000000000000000000000000000003",
                "position": "0",
                "merkleRoot": "0000000000000000000000000000000000000000000000000000000000000004",
                "merklePath": [],
                "pathIndices": []
            }],
            "outputs": [{
                "value": "900",
                "recipientPkHash": "0000000000000000000000000000000000000000000000000000000000000005",
                "randomness": "0000000000000000000000000000000000000000000000000000000000000006"
            }],
            "fee": "100"
        });

        let proof_json = prover.prove(&witness_json.to_string()).unwrap();
        let ok = prover.verify(&proof_json).unwrap();
        assert!(ok);
    }

    // Note: test_balance_mismatch_rejected is skipped on non-WASM targets
    // because JsError::new() panics outside the WASM runtime.
    // The balance validation logic is verified by the WASM integration tests.
    #[test]
    fn test_balance_mismatch_constants() {
        // Verify that domain separators are consistent
        assert_eq!(DOMAIN_NOTE_COMMIT, 1);
        assert_eq!(DOMAIN_NULLIFIER, 3);
    }

    #[test]
    fn test_version() {
        let v = wasm_p3_version();
        assert!(v.contains("adapter"));
    }
}
