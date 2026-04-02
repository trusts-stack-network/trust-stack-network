/**
 * Node.js test for Plonky2 WASM prover.
 * Run with: node test-node.mjs
 */

import { readFile } from 'fs/promises';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { createHash } from 'crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Goldilocks prime
const GOLDILOCKS_PRIME = 0xFFFFFFFF00000001n;

// Domain separators (must match Rust)
const DOMAIN_NOTE_COMMIT = 1n;
const DOMAIN_NULLIFIER = 3n;
const DOMAIN_MERKLE_NODE = 5n;

// Simple field reduction
function reduce(x) {
  return ((x % GOLDILOCKS_PRIME) + GOLDILOCKS_PRIME) % GOLDILOCKS_PRIME;
}

// Convert 32 bytes to 4 field elements
function bytesToFields(bytes) {
  const result = [];
  for (let i = 0; i < 4; i++) {
    let val = 0n;
    for (let j = 0; j < 8; j++) {
      val |= BigInt(bytes[i * 8 + j]) << BigInt(j * 8);
    }
    result.push(reduce(val));
  }
  return result;
}

// Convert 4 field elements to 32 bytes
function fieldsToBytes(fields) {
  const result = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let val = fields[i];
    for (let j = 0; j < 8; j++) {
      result[i * 8 + j] = Number(val & 0xFFn);
      val >>= 8n;
    }
  }
  return result;
}

// Simple Poseidon-like hash (for testing - NOT cryptographically secure)
// This is a placeholder - the real hash is computed in WASM
function simpleHash(inputs) {
  // Use SHA256 and reduce to Goldilocks field
  const inputBytes = new Uint8Array(inputs.length * 8);
  for (let i = 0; i < inputs.length; i++) {
    let val = inputs[i];
    for (let j = 0; j < 8; j++) {
      inputBytes[i * 8 + j] = Number(val & 0xFFn);
      val >>= 8n;
    }
  }
  const hash = createHash('sha256').update(inputBytes).digest();
  return bytesToFields(hash);
}

// Generate random hex
function randomHex32() {
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Load WASM
const wasmPath = join(__dirname, 'pkg', 'tsn_plonky2_wasm_bg.wasm');
const wasmBytes = await readFile(wasmPath);
const { WasmProver, default: init } = await import(join(__dirname, 'pkg', 'tsn_plonky2_wasm.js'));

console.log('Initializing WASM module...');
await init(wasmBytes);
console.log('WASM initialized');

console.log('Creating WasmProver...');
const prover = new WasmProver();
console.log('WasmProver created');

console.log('Pre-building circuit (1 spend, 1 output)...');
const prebuildStart = Date.now();
prover.prebuild_circuit(1, 1);
const prebuildTime = Date.now() - prebuildStart;
console.log(`Circuit pre-built in ${prebuildTime}ms`);

// Generate consistent witness values
// The key insight: we need to generate values that the WASM prover will
// compute correctly. The WASM prover computes the note commitment, nullifier,
// and Merkle root internally, so we need to match those computations.

// Generate random private inputs
const value = '1000';
const recipientPkHash = randomHex32();
const randomness = randomHex32();
const nullifierKey = randomHex32();
const position = '0';

// Generate a Merkle path with all zeros (empty tree siblings)
// This ensures consistency since an empty tree has a known structure
const merklePath = [];
const pathIndices = [];
for (let i = 0; i < 32; i++) {
  merklePath.push('0'.repeat(64)); // 32 zero bytes in hex
  pathIndices.push(0);
}

// The WASM prover will compute:
// 1. note_commitment = Poseidon(DOMAIN_NOTE_COMMIT, value, pk_hash, randomness)
// 2. merkle_root by walking up the path from note_commitment
// 3. nullifier = Poseidon(DOMAIN_NULLIFIER, nk, commitment, position)
//
// Since we can't easily compute Poseidon in JS without the same implementation,
// we let the WASM prover compute these and set them as public inputs.
// The merkle_root we pass is ignored - the prover computes it.

// For merkle_root, we pass a placeholder - the WASM will compute the real one
const merkleRootPlaceholder = '0'.repeat(64);

// Same for output - we generate random values and let WASM compute commitment
const outputValue = '900';
const outputPkHash = randomHex32();
const outputRandomness = randomHex32();

const witness = {
  spends: [{
    value: value,
    recipientPkHash: recipientPkHash,
    randomness: randomness,
    nullifierKey: nullifierKey,
    position: position,
    merkleRoot: merkleRootPlaceholder,
    merklePath: merklePath,
    pathIndices: pathIndices,
  }],
  outputs: [{
    value: outputValue,
    recipientPkHash: outputPkHash,
    randomness: outputRandomness,
  }],
  fee: '100',
};

console.log('Test witness generated');
console.log(`  Spend value: ${value}`);
console.log(`  Output value: ${outputValue}`);
console.log(`  Fee: 100`);
console.log(`  Balance: ${parseInt(value)} = ${parseInt(outputValue)} + 100 ✓`);

console.log('\nGenerating proof (this may take a moment)...');
const proveStart = Date.now();

try {
  const proofJson = prover.prove(JSON.stringify(witness));
  const proveTime = Date.now() - proveStart;
  console.log(`Proof generated in ${proveTime}ms`);

  const proof = JSON.parse(proofJson);
  const proofSize = proof.proofBytes.length / 2;
  console.log(`Proof size: ${proofSize} bytes (${(proofSize / 1024).toFixed(1)} KB)`);

  console.log('\nVerifying proof...');
  const verifyStart = Date.now();
  const isValid = prover.verify(proofJson, 1, 1);
  const verifyTime = Date.now() - verifyStart;
  console.log(`Proof verified in ${verifyTime}ms: ${isValid ? 'VALID' : 'INVALID'}`);

  prover.free();

  console.log('\n=== RESULTS ===');
  console.log(`Pre-build time: ${prebuildTime}ms`);
  console.log(`Proof generation: ${proveTime}ms`);
  console.log(`Verification: ${verifyTime}ms`);
  console.log(`Proof size: ${proofSize} bytes (${(proofSize / 1024).toFixed(1)} KB)`);
  console.log(`Status: ${isValid ? '✅ SUCCESS' : '❌ FAILED'}`);

} catch (error) {
  console.error('Error during proof generation:', error.message);

  // Additional debug info
  console.log('\nDebug: The error typically means witness values are inconsistent.');
  console.log('The circuit expects:');
  console.log('  1. note_commitment matches computed value from (value, pk_hash, randomness)');
  console.log('  2. merkle_root matches computed value from path verification');
  console.log('  3. nullifier matches computed value from (nk, commitment, position)');

  prover.free();
  process.exit(1);
}
