//! WebAssembly bindings for TSN's Plonky2 prover.
//!
//! This crate provides browser-compatible proof generation for post-quantum
//! shielded transactions. It wraps the Plonky2 prover in wasm-bindgen exports.
//!
//! ## Usage (JavaScript)
//!
//! ```javascript
//! import init, { WasmProver } from 'tsn-plonky2-wasm';
//!
//! await init();
//! const prover = new WasmProver();
//!
//! const proof = prover.prove(JSON.stringify({
//!     spends: [...],
//!     outputs: [...],
//!     fee: "1000"
//! }));
//! ```

use std::collections::HashMap;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// Type aliases matching the main crate
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

// Domain separators (must match poseidon_pq.rs)
const DOMAIN_NOTE_COMMIT: u64 = 1;
const DOMAIN_NULLIFIER: u64 = 3;
const DOMAIN_MERKLE_NODE: u64 = 5;

// Merkle tree depth
const TREE_DEPTH: usize = 32;

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

/// Input witness for a spend (JSON-serializable).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
    pub merkle_path: Vec<String>,
    /// Path direction bits (0 = left, 1 = right)
    pub path_indices: Vec<u8>,
}

/// Input witness for an output (JSON-serializable).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
}

/// Circuit targets for witness assignment.
struct SpendTargets {
    value: Target,
    pk_hash: [Target; 4],
    randomness: [Target; 4],
    nullifier_key: [Target; 4],
    position: Target,
    merkle_path: Vec<[Target; 4]>,
    path_indices: Vec<BoolTarget>,
    merkle_root: [Target; 4],
    nullifier: [Target; 4],
}

struct OutputTargets {
    value: Target,
    pk_hash: [Target; 4],
    randomness: [Target; 4],
    note_commitment: [Target; 4],
}

struct TransactionTargets {
    spends: Vec<SpendTargets>,
    outputs: Vec<OutputTargets>,
    fee: Target,
}

/// Maximum number of spends supported (to prevent DoS via huge circuits)
const MAX_SPENDS: usize = 10;

/// Maximum number of outputs supported
const MAX_OUTPUTS: usize = 4;

/// Default warmup: pre-build circuits for 1-5 spends
const DEFAULT_WARMUP_SPENDS: usize = 5;

/// Default warmup: pre-build circuits for 1-2 outputs
const DEFAULT_WARMUP_OUTPUTS: usize = 2;

/// WebAssembly prover for TSN transactions.
///
/// This prover generates Plonky2 STARK proofs for shielded transactions.
/// Circuits are built dynamically on first use and cached for reuse.
#[wasm_bindgen]
pub struct WasmProver {
    /// Dynamic circuit cache: (num_spends, num_outputs) -> (circuit_data, targets)
    circuits: HashMap<(usize, usize), (CircuitData<F, C, D>, TransactionTargets)>,
}

#[wasm_bindgen]
impl WasmProver {
    /// Create a new prover instance.
    ///
    /// Circuits are built dynamically on first use and cached for reuse.
    /// Call this once and reuse for multiple proofs.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        console_log!("WasmProver: Initializing with dynamic circuit support (max {}x{})...", MAX_SPENDS, MAX_OUTPUTS);

        Self {
            circuits: HashMap::new(),
        }
    }

    /// Pre-build a circuit for a specific transaction shape.
    ///
    /// Call this before proving to reduce latency on first proof.
    /// Supports any shape up to MAX_SPENDS x MAX_OUTPUTS.
    #[wasm_bindgen]
    pub fn prebuild_circuit(&mut self, num_spends: usize, num_outputs: usize) -> Result<(), JsError> {
        // Validate limits
        if num_spends == 0 || num_spends > MAX_SPENDS {
            return Err(JsError::new(&format!(
                "Invalid num_spends: {} (must be 1-{})",
                num_spends, MAX_SPENDS
            )));
        }
        if num_outputs == 0 || num_outputs > MAX_OUTPUTS {
            return Err(JsError::new(&format!(
                "Invalid num_outputs: {} (must be 1-{})",
                num_outputs, MAX_OUTPUTS
            )));
        }

        // Check if already built
        let key = (num_spends, num_outputs);
        if self.circuits.contains_key(&key) {
            console_log!("WasmProver: Circuit ({},{}) already cached", num_spends, num_outputs);
            return Ok(());
        }

        console_log!("WasmProver: Building circuit for {} spends, {} outputs...", num_spends, num_outputs);

        let circuit = build_transaction_circuit(num_spends, num_outputs);
        self.circuits.insert(key, circuit);

        console_log!("WasmProver: Circuit ({},{}) built and cached", num_spends, num_outputs);
        Ok(())
    }

    /// Get the list of currently cached circuit shapes.
    #[wasm_bindgen]
    pub fn cached_shapes(&self) -> String {
        let shapes: Vec<String> = self.circuits.keys()
            .map(|(s, o)| format!("({},{})", s, o))
            .collect();
        shapes.join(", ")
    }

    /// Get the maximum supported spends.
    #[wasm_bindgen]
    pub fn max_spends(&self) -> usize {
        MAX_SPENDS
    }

    /// Get the maximum supported outputs.
    #[wasm_bindgen]
    pub fn max_outputs(&self) -> usize {
        MAX_OUTPUTS
    }

    /// Pre-build circuits for common transaction shapes (warmup).
    ///
    /// This builds circuits for 1-5 spends × 1-2 outputs (10 shapes).
    /// Call this at wallet initialization to avoid latency on first transactions.
    ///
    /// Returns the number of circuits built.
    #[wasm_bindgen]
    pub fn warmup(&mut self) -> Result<usize, JsError> {
        self.warmup_range(DEFAULT_WARMUP_SPENDS, DEFAULT_WARMUP_OUTPUTS)
    }

    /// Pre-build circuits for a custom range of transaction shapes.
    ///
    /// # Arguments
    /// * `max_spends` - Build circuits for 1..=max_spends
    /// * `max_outputs` - Build circuits for 1..=max_outputs
    ///
    /// Returns the number of circuits built.
    #[wasm_bindgen]
    pub fn warmup_range(&mut self, max_spends: usize, max_outputs: usize) -> Result<usize, JsError> {
        let max_s = max_spends.min(MAX_SPENDS);
        let max_o = max_outputs.min(MAX_OUTPUTS);

        console_log!(
            "WasmProver: Warming up circuits for 1-{} spends × 1-{} outputs ({} shapes)...",
            max_s, max_o, max_s * max_o
        );

        let mut count = 0;
        for num_spends in 1..=max_s {
            for num_outputs in 1..=max_o {
                let key = (num_spends, num_outputs);
                if !self.circuits.contains_key(&key) {
                    console_log!("  Building circuit ({},{})...", num_spends, num_outputs);
                    self.prebuild_circuit(num_spends, num_outputs)?;
                    count += 1;
                }
            }
        }

        console_log!("WasmProver: Warmup complete. Built {} new circuits.", count);
        Ok(count)
    }

    /// Pre-build a single circuit shape (useful for targeted warmup).
    ///
    /// Use this to pre-build specific shapes you know you'll need.
    /// Example: `prover.warmup_shape(4, 1)` for 4-input consolidation.
    #[wasm_bindgen]
    pub fn warmup_shape(&mut self, num_spends: usize, num_outputs: usize) -> Result<bool, JsError> {
        let key = (num_spends, num_outputs);
        if self.circuits.contains_key(&key) {
            return Ok(false); // Already cached
        }
        self.prebuild_circuit(num_spends, num_outputs)?;
        Ok(true)
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
        console_log!("WasmProver: Starting proof generation");

        // Parse witness
        let witness: TransactionWitnessJs = serde_json::from_str(witness_json)
            .map_err(|e| JsError::new(&format!("Failed to parse witness: {}", e)))?;

        let num_spends = witness.spends.len();
        let num_outputs = witness.outputs.len();

        console_log!("WasmProver: Transaction has {} spends, {} outputs", num_spends, num_outputs);

        // Get or build circuit
        let (circuit_data, targets) = self.get_or_build_circuit(num_spends, num_outputs)?;

        // Build partial witness
        let mut pw = PartialWitness::new();

        // Set spend witnesses
        for (spend_witness, spend_targets) in witness.spends.iter().zip(targets.spends.iter()) {
            set_spend_witness(&mut pw, spend_witness, spend_targets)?;
        }

        // Set output witnesses
        for (output_witness, output_targets) in witness.outputs.iter().zip(targets.outputs.iter()) {
            set_output_witness(&mut pw, output_witness, output_targets)?;
        }

        // Set fee
        let fee: u64 = witness.fee.parse()
            .map_err(|_| JsError::new("Invalid fee value"))?;
        pw.set_target(targets.fee, F::from_canonical_u64(fee))
            .map_err(|e| JsError::new(&format!("Failed to set fee: {}", e)))?;

        console_log!("WasmProver: Witness assigned, generating proof...");

        // Generate proof
        let proof = circuit_data.prove(pw)
            .map_err(|e| JsError::new(&format!("Proof generation failed: {}", e)))?;

        console_log!("WasmProver: Proof generated successfully");

        // Extract public inputs and serialize
        let output = extract_proof_output(&proof, num_spends, num_outputs, fee);
        let output_json = serde_json::to_string(&output)
            .map_err(|e| JsError::new(&format!("Failed to serialize proof: {}", e)))?;

        Ok(output_json)
    }

    /// Verify a proof.
    ///
    /// # Arguments
    /// * `proof_json` - JSON string containing the proof
    /// * `num_spends` - Number of spends in the transaction
    /// * `num_outputs` - Number of outputs in the transaction
    #[wasm_bindgen]
    pub fn verify(&mut self, proof_json: &str, num_spends: usize, num_outputs: usize) -> Result<bool, JsError> {
        console_log!("WasmProver: Verifying proof");

        let proof_output: ProofOutputJs = serde_json::from_str(proof_json)
            .map_err(|e| JsError::new(&format!("Failed to parse proof: {}", e)))?;

        // Get circuit for verification
        let (circuit_data, _) = self.get_or_build_circuit(num_spends, num_outputs)?;

        // Deserialize proof
        let proof_bytes = hex::decode(&proof_output.proof_bytes)
            .map_err(|e| JsError::new(&format!("Invalid proof hex: {}", e)))?;

        let proof: ProofWithPublicInputs<F, C, D> =
            ProofWithPublicInputs::from_bytes(proof_bytes, &circuit_data.common)
                .map_err(|e| JsError::new(&format!("Failed to deserialize proof: {}", e)))?;

        // Verify
        circuit_data.verify(proof)
            .map_err(|e| JsError::new(&format!("Verification failed: {}", e)))?;

        console_log!("WasmProver: Proof verified successfully");
        Ok(true)
    }

    fn get_or_build_circuit(
        &mut self,
        num_spends: usize,
        num_outputs: usize,
    ) -> Result<&(CircuitData<F, C, D>, TransactionTargets), JsError> {
        let key = (num_spends, num_outputs);

        // Build if not cached
        if !self.circuits.contains_key(&key) {
            self.prebuild_circuit(num_spends, num_outputs)?;
        }

        // Return reference to cached circuit
        Ok(self.circuits.get(&key).unwrap())
    }
}

impl Default for WasmProver {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Standalone WASM functions for computing commitments and nullifiers.
// These use the same Poseidon implementation as the circuit, ensuring
// TypeScript and Rust compute identical values.
// ============================================================================

/// Get WASM module version for debugging.
/// Returns version string to verify correct WASM is loaded.
#[wasm_bindgen]
pub fn wasm_version() -> String {
    "0.2.1-merkle-debug".to_string()
}

/// Compute a note commitment using Plonky2's native Poseidon.
///
/// # Arguments
/// * `value` - The note value as a string
/// * `pk_hash_hex` - Recipient public key hash (32 bytes, hex)
/// * `randomness_hex` - Note randomness (32 bytes, hex)
///
/// # Returns
/// The commitment as a hex string (32 bytes)
#[wasm_bindgen]
pub fn compute_note_commitment_wasm(
    value: &str,
    pk_hash_hex: &str,
    randomness_hex: &str,
) -> Result<String, JsError> {
    let value: u64 = value.parse()
        .map_err(|_| JsError::new("Invalid value"))?;
    let pk_hash = hex_to_bytes32(pk_hash_hex)?;
    let randomness = hex_to_bytes32(randomness_hex)?;

    let commitment = native_note_commitment(value, &pk_hash, &randomness);
    Ok(hex::encode(commitment))
}

/// Compute a nullifier using Plonky2's native Poseidon.
///
/// # Arguments
/// * `nullifier_key_hex` - The nullifier key (32 bytes, hex)
/// * `commitment_hex` - The note commitment (32 bytes, hex)
/// * `position` - Position in the commitment tree as a string
///
/// # Returns
/// The nullifier as a hex string (32 bytes)
#[wasm_bindgen]
pub fn compute_nullifier_wasm(
    nullifier_key_hex: &str,
    commitment_hex: &str,
    position: &str,
) -> Result<String, JsError> {
    let nullifier_key = hex_to_bytes32(nullifier_key_hex)?;
    let commitment = hex_to_bytes32(commitment_hex)?;
    let position: u64 = position.parse()
        .map_err(|_| JsError::new("Invalid position"))?;

    let nullifier = native_nullifier(&nullifier_key, &commitment, position);
    Ok(hex::encode(nullifier))
}

/// Compute a Merkle root from a leaf and path (for debugging).
///
/// # Arguments
/// * `leaf_hex` - The leaf commitment (32 bytes, hex)
/// * `path_json` - JSON array of sibling hashes (hex strings)
/// * `indices_json` - JSON array of path indices (0 = left, 1 = right)
///
/// # Returns
/// The computed Merkle root as a hex string (32 bytes)
#[wasm_bindgen]
pub fn compute_merkle_root_wasm(
    leaf_hex: &str,
    path_json: &str,
    indices_json: &str,
) -> Result<String, JsError> {
    let leaf = hex_to_bytes32(leaf_hex)?;
    let path: Vec<String> = serde_json::from_str(path_json)
        .map_err(|e| JsError::new(&format!("Invalid path JSON: {}", e)))?;
    let indices: Vec<u8> = serde_json::from_str(indices_json)
        .map_err(|e| JsError::new(&format!("Invalid indices JSON: {}", e)))?;

    let root = native_merkle_root(&leaf, &path, &indices)?;
    Ok(hex::encode(root))
}

/// Build a transaction circuit for the given shape.
fn build_transaction_circuit(
    num_spends: usize,
    num_outputs: usize,
) -> (CircuitData<F, C, D>, TransactionTargets) {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let mut spend_targets = Vec::with_capacity(num_spends);
    let mut output_targets = Vec::with_capacity(num_outputs);

    let mut total_input = builder.zero();
    let mut total_output = builder.zero();

    // Build spend circuits
    for _ in 0..num_spends {
        let targets = build_spend_circuit(&mut builder);
        total_input = builder.add(total_input, targets.value);

        // Register public inputs
        for &elem in &targets.merkle_root {
            builder.register_public_input(elem);
        }
        for &elem in &targets.nullifier {
            builder.register_public_input(elem);
        }

        spend_targets.push(targets);
    }

    // Build output circuits
    for _ in 0..num_outputs {
        let targets = build_output_circuit(&mut builder);
        total_output = builder.add(total_output, targets.value);

        // Register public inputs
        for &elem in &targets.note_commitment {
            builder.register_public_input(elem);
        }

        output_targets.push(targets);
    }

    // Fee (public)
    let fee = builder.add_virtual_target();
    builder.register_public_input(fee);

    // Balance constraint: total_input == total_output + fee
    let output_plus_fee = builder.add(total_output, fee);
    builder.connect(total_input, output_plus_fee);

    let circuit_data = builder.build::<C>();

    let targets = TransactionTargets {
        spends: spend_targets,
        outputs: output_targets,
        fee,
    };

    (circuit_data, targets)
}

fn build_spend_circuit(builder: &mut CircuitBuilder<F, D>) -> SpendTargets {
    // Private inputs
    let value = builder.add_virtual_target();
    let pk_hash = [
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
    ];
    let randomness = [
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
    ];
    let nullifier_key = [
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
    ];
    let position = builder.add_virtual_target();

    // Merkle path
    let mut merkle_path = Vec::with_capacity(TREE_DEPTH);
    let mut path_indices = Vec::with_capacity(TREE_DEPTH);
    for _ in 0..TREE_DEPTH {
        merkle_path.push([
            builder.add_virtual_target(),
            builder.add_virtual_target(),
            builder.add_virtual_target(),
            builder.add_virtual_target(),
        ]);
        path_indices.push(builder.add_virtual_bool_target_safe());
    }

    // Public inputs (constrained)
    let merkle_root = [
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
    ];
    let nullifier = [
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
    ];

    // 1. Compute note commitment
    let note_commitment = compute_note_commitment(builder, value, &pk_hash, &randomness);

    // 2. Verify Merkle path
    let computed_root = verify_merkle_path(builder, &note_commitment, &merkle_path, &path_indices);
    for i in 0..4 {
        builder.connect(computed_root[i], merkle_root[i]);
    }

    // 3. Compute nullifier
    let computed_nullifier = compute_nullifier(builder, &nullifier_key, &note_commitment, position);
    for i in 0..4 {
        builder.connect(computed_nullifier[i], nullifier[i]);
    }

    SpendTargets {
        value,
        pk_hash,
        randomness,
        nullifier_key,
        position,
        merkle_path,
        path_indices,
        merkle_root,
        nullifier,
    }
}

fn build_output_circuit(builder: &mut CircuitBuilder<F, D>) -> OutputTargets {
    // Private inputs
    let value = builder.add_virtual_target();
    let pk_hash = [
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
    ];
    let randomness = [
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
    ];

    // Public input (constrained)
    let note_commitment = [
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
    ];

    // Compute and constrain commitment
    let computed = compute_note_commitment(builder, value, &pk_hash, &randomness);
    for i in 0..4 {
        builder.connect(computed[i], note_commitment[i]);
    }

    OutputTargets {
        value,
        pk_hash,
        randomness,
        note_commitment,
    }
}

fn compute_note_commitment(
    builder: &mut CircuitBuilder<F, D>,
    value: Target,
    pk_hash: &[Target; 4],
    randomness: &[Target; 4],
) -> [Target; 4] {
    let domain = builder.constant(F::from_canonical_u64(DOMAIN_NOTE_COMMIT));
    let mut inputs = vec![domain, value];
    inputs.extend_from_slice(pk_hash);
    inputs.extend_from_slice(randomness);
    let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
    hash.elements
}

fn compute_nullifier(
    builder: &mut CircuitBuilder<F, D>,
    nk: &[Target; 4],
    commitment: &[Target; 4],
    position: Target,
) -> [Target; 4] {
    let domain = builder.constant(F::from_canonical_u64(DOMAIN_NULLIFIER));
    let mut inputs = vec![domain];
    inputs.extend_from_slice(nk);
    inputs.extend_from_slice(commitment);
    inputs.push(position);
    let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
    hash.elements
}

fn verify_merkle_path(
    builder: &mut CircuitBuilder<F, D>,
    leaf: &[Target; 4],
    path: &[[Target; 4]],
    indices: &[BoolTarget],
) -> [Target; 4] {
    let domain = builder.constant(F::from_canonical_u64(DOMAIN_MERKLE_NODE));
    let mut current = *leaf;

    for (sibling, is_right) in path.iter().zip(indices.iter()) {
        let mut left = [builder.zero(); 4];
        let mut right = [builder.zero(); 4];

        for i in 0..4 {
            left[i] = builder.select(*is_right, sibling[i], current[i]);
            right[i] = builder.select(*is_right, current[i], sibling[i]);
        }

        let mut inputs = vec![domain];
        inputs.extend_from_slice(&left);
        inputs.extend_from_slice(&right);

        let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
        current = hash.elements;
    }

    current
}

fn set_spend_witness(
    pw: &mut PartialWitness<F>,
    witness: &SpendWitnessJs,
    targets: &SpendTargets,
) -> Result<(), JsError> {
    let map_err = |e: anyhow::Error| JsError::new(&e.to_string());

    // Value
    let value: u64 = witness.value.parse()
        .map_err(|_| JsError::new("Invalid spend value"))?;
    pw.set_target(targets.value, F::from_canonical_u64(value)).map_err(map_err)?;

    // PK hash
    let pk_hash_bytes = hex_to_bytes32(&witness.recipient_pk_hash)?;
    let pk_hash_fields = bytes_to_field_elements(&pk_hash_bytes);
    for (i, &val) in pk_hash_fields.iter().enumerate() {
        pw.set_target(targets.pk_hash[i], val).map_err(map_err)?;
    }

    // Randomness
    let randomness_bytes = hex_to_bytes32(&witness.randomness)?;
    let randomness_fields = bytes_to_field_elements(&randomness_bytes);
    for (i, &val) in randomness_fields.iter().enumerate() {
        pw.set_target(targets.randomness[i], val).map_err(map_err)?;
    }

    // Nullifier key
    let nk_bytes = hex_to_bytes32(&witness.nullifier_key)?;
    let nk_fields = bytes_to_field_elements(&nk_bytes);
    for (i, &val) in nk_fields.iter().enumerate() {
        pw.set_target(targets.nullifier_key[i], val).map_err(map_err)?;
    }

    // Position
    let position: u64 = witness.position.parse()
        .map_err(|_| JsError::new("Invalid position"))?;
    pw.set_target(targets.position, F::from_canonical_u64(position)).map_err(map_err)?;

    // Merkle path
    for (i, sibling_hex) in witness.merkle_path.iter().enumerate() {
        let sibling_bytes = hex_to_bytes32(sibling_hex)?;
        let sibling_fields = bytes_to_field_elements(&sibling_bytes);
        for (j, &val) in sibling_fields.iter().enumerate() {
            pw.set_target(targets.merkle_path[i][j], val).map_err(map_err)?;
        }
    }

    // Path indices
    for (i, &idx) in witness.path_indices.iter().enumerate() {
        pw.set_bool_target(targets.path_indices[i], idx != 0).map_err(map_err)?;
    }

    // Compute note commitment (needed for merkle root and nullifier)
    let note_commitment = native_note_commitment(value, &pk_hash_bytes, &randomness_bytes);

    // Compute Merkle root from path (public) - MUST match circuit computation
    let merkle_root = native_merkle_root(&note_commitment, &witness.merkle_path, &witness.path_indices)?;
    let root_fields = bytes_to_field_elements(&merkle_root);
    for (i, &val) in root_fields.iter().enumerate() {
        pw.set_target(targets.merkle_root[i], val).map_err(map_err)?;
    }

    // Compute nullifier from note commitment (public)
    let nullifier = native_nullifier(&nk_bytes, &note_commitment, position);
    let nf_fields = bytes_to_field_elements(&nullifier);
    for (i, &val) in nf_fields.iter().enumerate() {
        pw.set_target(targets.nullifier[i], val).map_err(map_err)?;
    }

    Ok(())
}

fn set_output_witness(
    pw: &mut PartialWitness<F>,
    witness: &OutputWitnessJs,
    targets: &OutputTargets,
) -> Result<(), JsError> {
    let map_err = |e: anyhow::Error| JsError::new(&e.to_string());

    // Value
    let value: u64 = witness.value.parse()
        .map_err(|_| JsError::new("Invalid output value"))?;
    pw.set_target(targets.value, F::from_canonical_u64(value)).map_err(map_err)?;

    // PK hash
    let pk_hash_bytes = hex_to_bytes32(&witness.recipient_pk_hash)?;
    let pk_hash_fields = bytes_to_field_elements(&pk_hash_bytes);
    for (i, &val) in pk_hash_fields.iter().enumerate() {
        pw.set_target(targets.pk_hash[i], val).map_err(map_err)?;
    }

    // Randomness
    let randomness_bytes = hex_to_bytes32(&witness.randomness)?;
    let randomness_fields = bytes_to_field_elements(&randomness_bytes);
    for (i, &val) in randomness_fields.iter().enumerate() {
        pw.set_target(targets.randomness[i], val).map_err(map_err)?;
    }

    // Compute and set note commitment (public)
    let commitment = compute_commitment_from_witness(witness)?;
    let cm_fields = bytes_to_field_elements(&commitment);
    for (i, &val) in cm_fields.iter().enumerate() {
        pw.set_target(targets.note_commitment[i], val).map_err(map_err)?;
    }

    Ok(())
}

fn extract_proof_output(
    proof: &ProofWithPublicInputs<F, C, D>,
    num_spends: usize,
    num_outputs: usize,
    fee: u64,
) -> ProofOutputJs {
    let proof_bytes = hex::encode(proof.to_bytes());
    let pis = &proof.public_inputs;

    let mut idx = 0;
    let mut merkle_roots = Vec::with_capacity(num_spends);
    let mut nullifiers = Vec::with_capacity(num_spends);

    // Extract spend public inputs
    for _ in 0..num_spends {
        let root = field_elements_to_bytes(&pis[idx..idx + 4]);
        merkle_roots.push(hex::encode(root));
        idx += 4;

        let nf = field_elements_to_bytes(&pis[idx..idx + 4]);
        nullifiers.push(hex::encode(nf));
        idx += 4;
    }

    // Extract output public inputs
    let mut note_commitments = Vec::with_capacity(num_outputs);
    for _ in 0..num_outputs {
        let cm = field_elements_to_bytes(&pis[idx..idx + 4]);
        note_commitments.push(hex::encode(cm));
        idx += 4;
    }

    ProofOutputJs {
        proof_bytes,
        merkle_roots,
        nullifiers,
        note_commitments,
        fee: fee.to_string(),
    }
}

// Helper functions

fn hex_to_bytes32(hex: &str) -> Result<[u8; 32], JsError> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex)
        .map_err(|e| JsError::new(&format!("Invalid hex: {}", e)))?;
    if bytes.len() != 32 {
        return Err(JsError::new(&format!("Expected 32 bytes, got {}", bytes.len())));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Goldilocks prime: p = 2^64 - 2^32 + 1
const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;

fn bytes_to_field_elements(bytes: &[u8; 32]) -> [F; 4] {
    let mut result = [F::ZERO; 4];
    for i in 0..4 {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let val = u64::from_le_bytes(chunk);
        // Reduce mod Goldilocks prime to match server's bytes_to_hash_out behavior.
        // The server uses GoldilocksField::new() which reduces mod p.
        let reduced = val % GOLDILOCKS_PRIME;
        result[i] = F::from_canonical_u64(reduced);
    }
    result
}

fn field_elements_to_bytes(fields: &[F]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for (i, &f) in fields.iter().take(4).enumerate() {
        let bytes = f.to_canonical_u64().to_le_bytes();
        result[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }
    result
}

/// Compute nullifier from witness (outside circuit for setting public input).
fn compute_nullifier_from_witness(witness: &SpendWitnessJs) -> Result<[u8; 32], JsError> {
    // This computes: Poseidon(DOMAIN_NULLIFIER, nk, commitment, position)
    // We need to first compute the note commitment, then the nullifier

    let value: u64 = witness.value.parse().map_err(|_| JsError::new("Invalid value"))?;
    let pk_hash = hex_to_bytes32(&witness.recipient_pk_hash)?;
    let randomness = hex_to_bytes32(&witness.randomness)?;
    let nk = hex_to_bytes32(&witness.nullifier_key)?;
    let position: u64 = witness.position.parse().map_err(|_| JsError::new("Invalid position"))?;

    // Compute note commitment
    let commitment = native_note_commitment(value, &pk_hash, &randomness);

    // Compute nullifier
    let nullifier = native_nullifier(&nk, &commitment, position);

    Ok(nullifier)
}

/// Compute note commitment from output witness.
fn compute_commitment_from_witness(witness: &OutputWitnessJs) -> Result<[u8; 32], JsError> {
    let value: u64 = witness.value.parse().map_err(|_| JsError::new("Invalid value"))?;
    let pk_hash = hex_to_bytes32(&witness.recipient_pk_hash)?;
    let randomness = hex_to_bytes32(&witness.randomness)?;

    Ok(native_note_commitment(value, &pk_hash, &randomness))
}

/// Native Poseidon hash for computing commitments outside the circuit.
fn native_poseidon(inputs: &[F]) -> [F; 4] {
    use plonky2::hash::hash_types::HashOut;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::plonk::config::Hasher;

    let hash: HashOut<F> = PoseidonHash::hash_no_pad(inputs);
    hash.elements
}

fn native_note_commitment(value: u64, pk_hash: &[u8; 32], randomness: &[u8; 32]) -> [u8; 32] {
    let domain = F::from_canonical_u64(DOMAIN_NOTE_COMMIT);
    let value_f = F::from_canonical_u64(value);
    let pk_fields = bytes_to_field_elements(pk_hash);
    let rand_fields = bytes_to_field_elements(randomness);

    let mut inputs = vec![domain, value_f];
    inputs.extend_from_slice(&pk_fields);
    inputs.extend_from_slice(&rand_fields);

    let hash = native_poseidon(&inputs);
    field_elements_to_bytes(&hash)
}

fn native_nullifier(nk: &[u8; 32], commitment: &[u8; 32], position: u64) -> [u8; 32] {
    let domain = F::from_canonical_u64(DOMAIN_NULLIFIER);
    let nk_fields = bytes_to_field_elements(nk);
    let cm_fields = bytes_to_field_elements(commitment);
    let pos_f = F::from_canonical_u64(position);

    let mut inputs = vec![domain];
    inputs.extend_from_slice(&nk_fields);
    inputs.extend_from_slice(&cm_fields);
    inputs.push(pos_f);

    let hash = native_poseidon(&inputs);
    field_elements_to_bytes(&hash)
}

/// Compute Merkle root by traversing path from leaf to root.
fn native_merkle_root(leaf: &[u8; 32], path: &[String], indices: &[u8]) -> Result<[u8; 32], JsError> {
    let domain = F::from_canonical_u64(DOMAIN_MERKLE_NODE);
    let mut current = bytes_to_field_elements(leaf);

    console_log!("=== native_merkle_root DEBUG ===");
    console_log!("leaf bytes: {}", hex::encode(leaf));
    console_log!("leaf as field elements: [{}, {}, {}, {}]",
        current[0].to_canonical_u64(),
        current[1].to_canonical_u64(),
        current[2].to_canonical_u64(),
        current[3].to_canonical_u64()
    );
    console_log!("path_len: {}, indices_len: {}", path.len(), indices.len());
    console_log!("domain: {}", domain.to_canonical_u64());

    // Log first few indices for debugging
    let indices_preview: Vec<_> = indices.iter().take(8).collect();
    console_log!("indices[0..8]: {:?}", indices_preview);

    // Log first sibling for debugging
    if !path.is_empty() {
        console_log!("path[0] (first sibling): {}", &path[0]);
    }

    for (i, (sibling_hex, &is_right)) in path.iter().zip(indices.iter()).enumerate() {
        let sibling_bytes = hex_to_bytes32(sibling_hex)?;
        let sibling_fields = bytes_to_field_elements(&sibling_bytes);

        // Determine left/right based on is_right flag
        // is_right=0: current is left child, sibling is right -> hash(current, sibling)
        // is_right=1: current is right child, sibling is left -> hash(sibling, current)
        let (left, right) = if is_right != 0 {
            (sibling_fields, current)
        } else {
            (current, sibling_fields)
        };

        let mut inputs = vec![domain];
        inputs.extend_from_slice(&left);
        inputs.extend_from_slice(&right);

        if i == 0 {
            console_log!("depth 0 sibling bytes: {}", sibling_hex);
            console_log!("depth 0 sibling fields: [{}, {}, {}, {}]",
                sibling_fields[0].to_canonical_u64(),
                sibling_fields[1].to_canonical_u64(),
                sibling_fields[2].to_canonical_u64(),
                sibling_fields[3].to_canonical_u64()
            );
            console_log!("depth 0 is_right: {} (current is {})", is_right, if is_right != 0 { "RIGHT" } else { "LEFT" });
            console_log!("depth 0 hash inputs (9 elements):");
            for (j, inp) in inputs.iter().enumerate() {
                console_log!("  inputs[{}] = {}", j, inp.to_canonical_u64());
            }
        }

        let hash = native_poseidon(&inputs);

        if i < 3 {
            console_log!(
                "depth {}: is_right={}, result=[{},{},{},{}]",
                i, is_right,
                hash[0].to_canonical_u64(),
                hash[1].to_canonical_u64(),
                hash[2].to_canonical_u64(),
                hash[3].to_canonical_u64()
            );
        }

        current = hash;
    }

    let result = field_elements_to_bytes(&current);
    console_log!("final root: {}", hex::encode(&result));
    console_log!("=== END native_merkle_root DEBUG ===");
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prover_creation() {
        let prover = WasmProver::new();
        // New prover starts with empty circuit cache
        assert!(prover.circuits.is_empty());
    }

    #[test]
    fn test_circuit_prebuild() {
        let mut prover = WasmProver::new();
        prover.prebuild_circuit(1, 1).unwrap();
        // Circuit should now be cached
        assert!(prover.circuits.contains_key(&(1, 1)));
    }

    #[test]
    fn test_dynamic_circuit_shapes() {
        let mut prover = WasmProver::new();

        // Build various shapes
        prover.prebuild_circuit(2, 1).unwrap();
        prover.prebuild_circuit(3, 2).unwrap();
        prover.prebuild_circuit(5, 2).unwrap();

        assert!(prover.circuits.contains_key(&(2, 1)));
        assert!(prover.circuits.contains_key(&(3, 2)));
        assert!(prover.circuits.contains_key(&(5, 2)));
        assert!(!prover.circuits.contains_key(&(4, 1))); // Not built yet
    }

    // Note: test_circuit_limits is skipped because JsError::new() requires WASM target.
    // The limit checking is verified by the WASM integration tests instead.
    #[test]
    fn test_circuit_max_constants() {
        // Verify the constants are reasonable
        assert!(MAX_SPENDS >= 1);
        assert!(MAX_SPENDS <= 20);
        assert!(MAX_OUTPUTS >= 1);
        assert!(MAX_OUTPUTS <= 10);
    }

    #[test]
    fn test_bytes_roundtrip() {
        let original = [42u8; 32];
        let fields = bytes_to_field_elements(&original);
        let recovered = field_elements_to_bytes(&fields);
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_nullifier_computation() {
        // Test that WASM nullifier function produces consistent results
        let nk_hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let cm_hex = "0000000000000000000000000000000000000000000000000000000000000002";
        let position = "0";

        let result1 = compute_nullifier_wasm(nk_hex, cm_hex, position).unwrap();
        let result2 = compute_nullifier_wasm(nk_hex, cm_hex, position).unwrap();

        // Should be deterministic
        assert_eq!(result1, result2);
        // Should produce 64-char hex (32 bytes)
        assert_eq!(result1.len(), 64);
    }

    #[test]
    fn test_note_commitment_computation() {
        // Test that WASM commitment function produces consistent results
        let value = "1000000";
        let pk_hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let rand_hex = "0000000000000000000000000000000000000000000000000000000000000002";

        let result1 = compute_note_commitment_wasm(value, pk_hex, rand_hex).unwrap();
        let result2 = compute_note_commitment_wasm(value, pk_hex, rand_hex).unwrap();

        // Should be deterministic
        assert_eq!(result1, result2);
        // Should produce 64-char hex (32 bytes)
        assert_eq!(result1.len(), 64);
    }
}
