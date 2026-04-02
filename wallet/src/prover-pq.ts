/**
 * Plonky2 proof generation for post-quantum transactions.
 *
 * This module provides the interface to Plonky2's STARK-based proving system
 * for V2 transactions. It uses the WASM prover for browser-based proving.
 *
 * ## Architecture
 *
 * The prover generates a combined STARK proof that verifies:
 * 1. All spends are valid (Merkle paths, nullifier derivation)
 * 2. All outputs are valid (commitment formation)
 * 3. Balance constraint: sum(inputs) = sum(outputs) + fee
 *
 * This replaces the individual Groth16 proofs + binding signature from V1.
 *
 * ## Browser Support
 *
 * Plonky2 compiles to WebAssembly, enabling client-side proving in browsers.
 * This is critical for self-custody wallets where users shouldn't need to
 * trust a third-party proving service.
 */

import { bytesToHex, hexToBytes } from './crypto';

// @ts-ignore - WASM module is loaded dynamically
import init, { WasmProver } from 'tsn-plonky2-wasm';

// Singleton prover instance
let wasmProver: WasmProver | null = null;
let initPromise: Promise<void> | null = null;

/**
 * Spend witness for V2 transactions.
 */
export interface SpendWitnessPQ {
  value: bigint;
  recipientPkHash: Uint8Array;
  randomness: Uint8Array;
  nullifierKey: Uint8Array;
  position: bigint;
  merkleRoot: Uint8Array;
  merklePath: Uint8Array[];  // Array of 32-byte siblings
  pathIndices: number[];     // 0 = left, 1 = right
  noteCommitment: Uint8Array; // The stored commitment (32 bytes) - used for Merkle verification
}

/**
 * Output witness for V2 transactions.
 */
export interface OutputWitnessPQ {
  value: bigint;
  recipientPkHash: Uint8Array;
  randomness: Uint8Array;
}

/**
 * Public inputs from a transaction proof.
 */
export interface TransactionPublicInputs {
  merkleRoots: Uint8Array[];
  nullifiers: Uint8Array[];
  noteCommitments: Uint8Array[];
  fee: bigint;
}

/**
 * A Plonky2 proof for a V2 transaction.
 */
export interface Plonky2Proof {
  proofBytes: Uint8Array;
  publicInputs: TransactionPublicInputs;
}

/**
 * Proof generation error.
 */
export class ProofError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProofError';
  }
}

/**
 * Initialize the WASM prover.
 *
 * Call this once before generating proofs. Multiple calls are safe.
 */
export async function initProver(): Promise<void> {
  if (wasmProver) return;

  if (initPromise) {
    await initPromise;
    return;
  }

  initPromise = (async () => {
    try {
      await init();
      wasmProver = new WasmProver();
      console.log('Plonky2 WASM prover initialized');
    } catch (e) {
      initPromise = null;
      throw new ProofError(`Failed to initialize WASM prover: ${e}`);
    }
  })();

  await initPromise;
}

/**
 * Pre-build a circuit for a specific transaction shape.
 *
 * This reduces latency on the first proof of each shape.
 *
 * @param numSpends - Number of spends in the transaction
 * @param numOutputs - Number of outputs in the transaction
 */
export async function prebuildCircuit(numSpends: number, numOutputs: number): Promise<void> {
  await initProver();
  wasmProver!.prebuild_circuit(numSpends, numOutputs);
}

/**
 * Warm up the prover by pre-building common circuit shapes.
 *
 * This builds circuits for 1-5 spends × 1-2 outputs (10 shapes).
 * Call this at wallet initialization to avoid latency on first transactions.
 *
 * @param onProgress - Optional callback for progress updates
 * @returns Number of circuits built
 */
export async function warmupProver(onProgress?: (msg: string) => void): Promise<number> {
  await initProver();
  onProgress?.('Warming up Plonky2 circuits (1-5 spends × 1-2 outputs)...');
  const count = wasmProver!.warmup();
  onProgress?.(`Warmup complete. ${count} circuits ready.`);
  return count;
}

/**
 * Warm up the prover with a custom range of circuit shapes.
 *
 * @param maxSpends - Build circuits for 1..=maxSpends (max 10)
 * @param maxOutputs - Build circuits for 1..=maxOutputs (max 4)
 * @param onProgress - Optional callback for progress updates
 * @returns Number of circuits built
 */
export async function warmupProverRange(
  maxSpends: number,
  maxOutputs: number,
  onProgress?: (msg: string) => void
): Promise<number> {
  await initProver();
  onProgress?.(`Warming up Plonky2 circuits (1-${maxSpends} spends × 1-${maxOutputs} outputs)...`);
  const count = wasmProver!.warmup_range(maxSpends, maxOutputs);
  onProgress?.(`Warmup complete. ${count} circuits ready.`);
  return count;
}

/**
 * Get the maximum supported number of spends.
 */
export async function getMaxSpends(): Promise<number> {
  await initProver();
  return wasmProver!.max_spends();
}

/**
 * Get the maximum supported number of outputs.
 */
export async function getMaxOutputs(): Promise<number> {
  await initProver();
  return wasmProver!.max_outputs();
}

/**
 * Get the list of currently cached circuit shapes.
 */
export async function getCachedShapes(): Promise<string> {
  await initProver();
  return wasmProver!.cached_shapes();
}

/**
 * Warmup progress information.
 */
export interface WarmupProgress {
  /** Current circuit being built (e.g., "(3,2)") */
  currentShape: string;
  /** Number of circuits completed */
  completed: number;
  /** Total number of circuits to build */
  total: number;
  /** Percentage complete (0-100) */
  percent: number;
  /** Whether warmup is complete */
  done: boolean;
  /** Estimated time remaining in seconds (rough estimate) */
  estimatedSecondsRemaining: number;
}

/**
 * Persisted warmup state.
 */
interface PersistedWarmupState {
  /** Shapes that were warmed up */
  warmedShapes: string[];
  /** Max spends that were warmed */
  maxSpends: number;
  /** Max outputs that were warmed */
  maxOutputs: number;
  /** Timestamp of last warmup completion */
  completedAt: number;
  /** Version for cache invalidation */
  version: number;
}

const WARMUP_STORAGE_KEY = 'tsn_plonky2_warmup';
const WARMUP_VERSION = 1; // Increment to invalidate old caches

/**
 * Warmup state for tracking background warmup progress.
 */
let warmupState: WarmupProgress | null = null;
let warmupPromise: Promise<number> | null = null;

/**
 * Load persisted warmup state from localStorage.
 */
function loadPersistedWarmupState(): PersistedWarmupState | null {
  try {
    const stored = localStorage.getItem(WARMUP_STORAGE_KEY);
    if (!stored) return null;

    const state = JSON.parse(stored) as PersistedWarmupState;

    // Check version - invalidate if outdated
    if (state.version !== WARMUP_VERSION) {
      localStorage.removeItem(WARMUP_STORAGE_KEY);
      return null;
    }

    return state;
  } catch {
    return null;
  }
}

/**
 * Save warmup state to localStorage.
 */
function savePersistedWarmupState(state: PersistedWarmupState): void {
  try {
    localStorage.setItem(WARMUP_STORAGE_KEY, JSON.stringify(state));
  } catch {
    // localStorage might be full or disabled
  }
}

/**
 * Clear persisted warmup state.
 */
export function clearWarmupCache(): void {
  localStorage.removeItem(WARMUP_STORAGE_KEY);
}

/**
 * Check if warmup was previously completed for the given configuration.
 */
export function wasWarmupCompleted(maxSpends: number = 5, maxOutputs: number = 2): boolean {
  const persisted = loadPersistedWarmupState();
  if (!persisted) return false;

  // Check if the persisted warmup covers the requested range
  return persisted.maxSpends >= maxSpends && persisted.maxOutputs >= maxOutputs;
}

/**
 * Get the timestamp of the last warmup completion, or null if never completed.
 */
export function getWarmupCompletedAt(): Date | null {
  const persisted = loadPersistedWarmupState();
  return persisted ? new Date(persisted.completedAt) : null;
}

/**
 * Get the current warmup progress.
 * Returns null if no warmup is in progress.
 */
export function getWarmupProgress(): WarmupProgress | null {
  return warmupState;
}

/**
 * Check if warmup is currently in progress.
 */
export function isWarmupInProgress(): boolean {
  return warmupState !== null && !warmupState.done;
}

/**
 * Options for background warmup.
 */
export interface WarmupOptions {
  /** Build circuits for 1..=maxSpends (default: 5, max: 10) */
  maxSpends?: number;
  /** Build circuits for 1..=maxOutputs (default: 2, max: 4) */
  maxOutputs?: number;
  /** Callback for progress updates */
  onProgress?: (progress: WarmupProgress) => void;
  /** Skip if warmup was already completed for this config (default: true) */
  skipIfCached?: boolean;
  /** Run silently without updating warmupState (for background re-warming) */
  silent?: boolean;
}

/**
 * Start background warmup of the prover.
 *
 * This builds circuits incrementally, yielding to the event loop between each
 * circuit to keep the UI responsive. Progress can be tracked via getWarmupProgress().
 *
 * Warmup state is persisted to localStorage, so subsequent visits will skip
 * the warmup if it was already completed for the same configuration.
 *
 * @param options - Warmup options
 * @returns Promise that resolves with number of circuits built
 */
export async function startBackgroundWarmup(
  optionsOrMaxSpends?: WarmupOptions | number,
  maxOutputsLegacy?: number,
  onProgressLegacy?: (progress: WarmupProgress) => void
): Promise<number> {
  // Handle legacy signature: (maxSpends, maxOutputs, onProgress)
  let options: WarmupOptions;
  if (typeof optionsOrMaxSpends === 'number') {
    options = {
      maxSpends: optionsOrMaxSpends,
      maxOutputs: maxOutputsLegacy,
      onProgress: onProgressLegacy,
    };
  } else {
    options = optionsOrMaxSpends || {};
  }

  const {
    maxSpends = 5,
    maxOutputs = 2,
    onProgress,
    skipIfCached = true,
    silent = false,
  } = options;

  const clampedSpends = Math.min(Math.max(1, maxSpends), 10);
  const clampedOutputs = Math.min(Math.max(1, maxOutputs), 4);

  // Check if we can skip (already warmed in a previous session)
  if (skipIfCached && wasWarmupCompleted(clampedSpends, clampedOutputs)) {
    console.log('Warmup: Using cached warmup state, re-building circuits silently...');
    // Still need to rebuild in WASM memory, but do it silently
    return startBackgroundWarmup({
      maxSpends: clampedSpends,
      maxOutputs: clampedOutputs,
      skipIfCached: false,
      silent: true,
    });
  }

  // If already warming up (non-silent), return existing promise
  if (!silent && warmupPromise && warmupState && !warmupState.done) {
    return warmupPromise;
  }

  await initProver();

  const total = clampedSpends * clampedOutputs;

  // Initialize progress state (unless silent)
  if (!silent) {
    warmupState = {
      currentShape: '',
      completed: 0,
      total,
      percent: 0,
      done: false,
      estimatedSecondsRemaining: total * 5,
    };
  }

  const buildPromise = (async () => {
    let built = 0;
    const startTime = Date.now();
    const warmedShapes: string[] = [];

    for (let spends = 1; spends <= clampedSpends; spends++) {
      for (let outputs = 1; outputs <= clampedOutputs; outputs++) {
        const shape = `(${spends},${outputs})`;

        // Update progress (unless silent)
        if (!silent && warmupState) {
          warmupState = {
            ...warmupState,
            currentShape: shape,
          };
          onProgress?.(warmupState);
        }

        // Build circuit (this is the slow part)
        const wasBuilt = wasmProver!.warmup_shape(spends, outputs);
        if (wasBuilt) {
          built++;
        }
        warmedShapes.push(shape);

        // Update progress
        const completed = (spends - 1) * clampedOutputs + outputs;

        if (!silent && warmupState) {
          const elapsed = (Date.now() - startTime) / 1000;
          const avgTimePerCircuit = completed > 0 ? elapsed / completed : 5;
          const remaining = total - completed;

          warmupState = {
            currentShape: shape,
            completed,
            total,
            percent: Math.round((completed / total) * 100),
            done: false,
            estimatedSecondsRemaining: Math.round(remaining * avgTimePerCircuit),
          };
          onProgress?.(warmupState);
        }

        // Yield to event loop to keep UI responsive
        await new Promise(resolve => setTimeout(resolve, 0));
      }
    }

    // Mark as complete and persist
    if (!silent && warmupState) {
      warmupState = {
        ...warmupState,
        currentShape: '',
        done: true,
        percent: 100,
        estimatedSecondsRemaining: 0,
      };
      onProgress?.(warmupState);
    }

    // Persist to localStorage
    savePersistedWarmupState({
      warmedShapes,
      maxSpends: clampedSpends,
      maxOutputs: clampedOutputs,
      completedAt: Date.now(),
      version: WARMUP_VERSION,
    });

    console.log(`Warmup complete: built ${built} circuits (${silent ? 'silent' : 'with UI'})`);
    return built;
  })();

  if (!silent) {
    warmupPromise = buildPromise;
  }

  return buildPromise;
}

/**
 * Wait for any in-progress warmup to complete.
 */
export async function waitForWarmup(): Promise<void> {
  if (warmupPromise) {
    await warmupPromise;
  }
}

// NOTE: Local Merkle validation removed - TypeScript's Poseidon differs from Plonky2's
// The WASM prover uses Plonky2's native Poseidon which matches the server
// The server will reject invalid proofs anyway

/**
 * Generate a transaction proof using Plonky2 WASM prover.
 *
 * @param spendWitnesses - Witnesses for all spends
 * @param outputWitnesses - Witnesses for all outputs
 * @param fee - Transaction fee
 * @returns Plonky2 proof with public inputs
 */
export async function generateTransactionProofPQ(
  spendWitnesses: SpendWitnessPQ[],
  outputWitnesses: OutputWitnessPQ[],
  fee: bigint
): Promise<Plonky2Proof> {
  await initProver();

  // 1. Validate balance constraint
  const totalInputs = spendWitnesses.reduce((sum, s) => sum + s.value, 0n);
  const totalOutputs = outputWitnesses.reduce((sum, o) => sum + o.value, 0n);

  if (totalInputs !== totalOutputs + fee) {
    throw new ProofError(
      `Balance mismatch: inputs=${totalInputs}, outputs=${totalOutputs}, fee=${fee}`
    );
  }

  // 2. Skip local merkle validation - TypeScript Poseidon differs from Plonky2's
  // The WASM prover uses Plonky2's native Poseidon which matches the server
  // Local validation would fail due to different round constants
  // The server will reject invalid proofs anyway

  // 3. Convert witnesses to JSON for WASM prover
  const witnessJson = JSON.stringify({
    spends: spendWitnesses.map(s => ({
      value: s.value.toString(),
      recipientPkHash: bytesToHex(s.recipientPkHash),
      randomness: bytesToHex(s.randomness),
      nullifierKey: bytesToHex(s.nullifierKey),
      position: s.position.toString(),
      merkleRoot: bytesToHex(s.merkleRoot),
      merklePath: s.merklePath.map(bytesToHex),
      pathIndices: s.pathIndices,
    })),
    outputs: outputWitnesses.map(o => ({
      value: o.value.toString(),
      recipientPkHash: bytesToHex(o.recipientPkHash),
      randomness: bytesToHex(o.randomness),
    })),
    fee: fee.toString(),
  });

  // 4. Generate proof using WASM prover
  console.log('Generating Plonky2 proof...');
  const startTime = Date.now();

  let proofJson: string;
  try {
    proofJson = wasmProver!.prove(witnessJson);
  } catch (e) {
    throw new ProofError(`WASM proof generation failed: ${e}`);
  }

  const elapsed = Date.now() - startTime;
  console.log(`Proof generated in ${elapsed}ms`);

  // 5. Parse proof output
  const proofOutput = JSON.parse(proofJson) as {
    proofBytes: string;
    merkleRoots: string[];
    nullifiers: string[];
    noteCommitments: string[];
    fee: string;
  };

  return {
    proofBytes: hexToBytes(proofOutput.proofBytes),
    publicInputs: {
      merkleRoots: proofOutput.merkleRoots.map(hexToBytes),
      nullifiers: proofOutput.nullifiers.map(hexToBytes),
      noteCommitments: proofOutput.noteCommitments.map(hexToBytes),
      fee: BigInt(proofOutput.fee),
    },
  };
}

/**
 * Verify a Plonky2 proof.
 *
 * @param proof - The proof to verify
 * @param numSpends - Number of spends
 * @param numOutputs - Number of outputs
 * @returns True if valid
 */
export async function verifyProofPQ(
  proof: Plonky2Proof,
  numSpends: number,
  numOutputs: number
): Promise<boolean> {
  await initProver();

  const proofJson = JSON.stringify({
    proofBytes: bytesToHex(proof.proofBytes),
    merkleRoots: proof.publicInputs.merkleRoots.map(bytesToHex),
    nullifiers: proof.publicInputs.nullifiers.map(bytesToHex),
    noteCommitments: proof.publicInputs.noteCommitments.map(bytesToHex),
    fee: proof.publicInputs.fee.toString(),
  });

  try {
    return wasmProver!.verify(proofJson, numSpends, numOutputs);
  } catch (e) {
    throw new ProofError(`Verification failed: ${e}`);
  }
}

/**
 * Get the size of a proof in bytes.
 */
export function getProofSize(proof: Plonky2Proof): number {
  return proof.proofBytes.length;
}

/**
 * Serialize a proof to bytes for network transmission.
 */
export function serializeProof(proof: Plonky2Proof): Uint8Array {
  const json = JSON.stringify({
    proofBytes: bytesToHex(proof.proofBytes),
    publicInputs: {
      merkleRoots: proof.publicInputs.merkleRoots.map(bytesToHex),
      nullifiers: proof.publicInputs.nullifiers.map(bytesToHex),
      noteCommitments: proof.publicInputs.noteCommitments.map(bytesToHex),
      fee: proof.publicInputs.fee.toString(),
    },
  });
  return new TextEncoder().encode(json);
}

/**
 * Deserialize a proof from bytes.
 */
export function deserializeProof(bytes: Uint8Array): Plonky2Proof {
  const json = new TextDecoder().decode(bytes);
  const data = JSON.parse(json) as {
    proofBytes: string;
    publicInputs: {
      merkleRoots: string[];
      nullifiers: string[];
      noteCommitments: string[];
      fee: string;
    };
  };

  return {
    proofBytes: hexToBytes(data.proofBytes),
    publicInputs: {
      merkleRoots: data.publicInputs.merkleRoots.map(hexToBytes),
      nullifiers: data.publicInputs.nullifiers.map(hexToBytes),
      noteCommitments: data.publicInputs.noteCommitments.map(hexToBytes),
      fee: BigInt(data.publicInputs.fee),
    },
  };
}

