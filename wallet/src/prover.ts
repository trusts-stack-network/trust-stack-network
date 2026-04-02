/**
 * ZK Proof generation for browser using snarkjs.
 *
 * This module provides functions to generate Groth16 proofs for
 * spend and output circuits. The proofs can be verified by the
 * Rust backend.
 */

import * as snarkjs from 'snarkjs';

// Proof and public signals from snarkjs
export interface SnarkJsProof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: string;
  curve: string;
}

export interface ProofResult {
  proof: SnarkJsProof;
  publicSignals: string[];
}

// Cached proving keys (loaded once, ~50-100MB each)
let spendZkey: ArrayBuffer | null = null;
let outputZkey: ArrayBuffer | null = null;

// Paths to circuit files (configurable)
let circuitBasePath = '/circuits';

/**
 * Set the base path for circuit files.
 */
export function setCircuitBasePath(path: string): void {
  circuitBasePath = path;
}

/**
 * Load a file as ArrayBuffer, supporting both browser (fetch) and Node.js (fs).
 */
async function loadFile(path: string): Promise<ArrayBuffer> {
  // Check if we're in Node.js and the path is a local file
  // @ts-ignore - process may not exist in browser
  const isNode = typeof globalThis.process !== 'undefined' && globalThis.process.versions?.node;

  if (isNode && !path.startsWith('http')) {
    // Dynamic import fs for Node.js (won't be bundled for browser)
    // @ts-ignore - dynamic import for Node.js only
    const fs = await import(/* @vite-ignore */ 'fs');
    const buffer = fs.readFileSync(path);
    return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
  }

  // Browser or HTTP URL - use fetch
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`Failed to load ${path}: ${response.status}`);
  }
  return response.arrayBuffer();
}

/**
 * Load proving keys from the server or filesystem.
 * Should be called once when the wallet initializes.
 */
export async function loadProvingKeys(): Promise<void> {
  const [spendBuffer, outputBuffer] = await Promise.all([
    loadFile(`${circuitBasePath}/spend_final.zkey`),
    loadFile(`${circuitBasePath}/output_final.zkey`),
  ]);

  spendZkey = spendBuffer;
  outputZkey = outputBuffer;
}

/**
 * Check if proving keys are loaded.
 */
export function areProvingKeysLoaded(): boolean {
  return spendZkey !== null && outputZkey !== null;
}

/**
 * Spend circuit witness inputs.
 */
export interface SpendWitness {
  merkleRoot: string;           // Field element as decimal string
  nullifier: string;            // Field element as decimal string
  valueCommitmentHash: string;  // Field element as decimal string
  value: string;                // u64 as decimal string
  recipientPkHash: string;      // Field element as decimal string
  noteRandomness: string;       // Field element as decimal string
  nullifierKey: string;         // Field element as decimal string
  pathElements: string[];       // 32 field elements as decimal strings
  pathIndices: number[];        // 32 bits (0 or 1)
  position: string;             // u64 as decimal string
}

/**
 * Output circuit witness inputs.
 */
export interface OutputWitness {
  noteCommitment: string;       // Field element as decimal string
  valueCommitmentHash: string;  // Field element as decimal string
  value: string;                // u64 as decimal string
  recipientPkHash: string;      // Field element as decimal string
  noteRandomness: string;       // Field element as decimal string
}

/**
 * Generate a spend proof.
 *
 * @param witness - Spend circuit witness values
 * @returns Proof and public signals
 */
export async function generateSpendProof(witness: SpendWitness): Promise<ProofResult> {
  if (!spendZkey) {
    throw new Error('Proving keys not loaded. Call loadProvingKeys() first.');
  }

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    witness as unknown as Record<string, unknown>,
    `${circuitBasePath}/spend.wasm`,
    new Uint8Array(spendZkey)
  );

  return { proof, publicSignals };
}

/**
 * Generate an output proof.
 *
 * @param witness - Output circuit witness values
 * @returns Proof and public signals
 */
export async function generateOutputProof(witness: OutputWitness): Promise<ProofResult> {
  if (!outputZkey) {
    throw new Error('Proving keys not loaded. Call loadProvingKeys() first.');
  }

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    witness as unknown as Record<string, unknown>,
    `${circuitBasePath}/output.wasm`,
    new Uint8Array(outputZkey)
  );

  return { proof, publicSignals };
}

/**
 * Verify a spend proof locally (for testing).
 */
export async function verifySpendProof(
  proof: SnarkJsProof,
  publicSignals: string[]
): Promise<boolean> {
  const vkeyResponse = await fetch(`${circuitBasePath}/spend_vkey.json`);
  const vkey = await vkeyResponse.json();
  return snarkjs.groth16.verify(vkey, publicSignals, proof);
}

/**
 * Verify an output proof locally (for testing).
 */
export async function verifyOutputProof(
  proof: SnarkJsProof,
  publicSignals: string[]
): Promise<boolean> {
  const vkeyResponse = await fetch(`${circuitBasePath}/output_vkey.json`);
  const vkey = await vkeyResponse.json();
  return snarkjs.groth16.verify(vkey, publicSignals, proof);
}

/**
 * Convert a snarkjs proof to a format suitable for Rust backend.
 * The Rust backend expects the proof as serialized bytes.
 */
export function proofToBytes(proof: SnarkJsProof): Uint8Array {
  // Groth16 proof consists of:
  // - A (G1 point): 2 * 48 bytes (x, y in compressed form ~48 bytes for BLS12-381)
  // - B (G2 point): 4 * 48 bytes
  // - C (G1 point): 2 * 48 bytes
  // Total: ~192 bytes for BLS12-381

  // For snarkjs, the proof is already in a serializable format.
  // The backend should be able to parse this JSON format.
  const proofJson = JSON.stringify(proof);
  return new TextEncoder().encode(proofJson);
}

/**
 * Convert public signals to field element bytes for Rust backend.
 */
export function publicSignalsToBytes(signals: string[]): Uint8Array[] {
  return signals.map(signal => {
    const n = BigInt(signal);
    const bytes = new Uint8Array(32);
    let temp = n;
    for (let i = 0; i < 32; i++) {
      bytes[i] = Number(temp & 0xFFn);
      temp >>= 8n;
    }
    return bytes;
  });
}

/**
 * Helper to convert a bigint to a decimal string (for witness inputs).
 */
export function bigintToString(n: bigint): string {
  return n.toString(10);
}

/**
 * Helper to convert bytes to a decimal string field element.
 */
export function bytes32ToString(bytes: Uint8Array): string {
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result.toString(10);
}
