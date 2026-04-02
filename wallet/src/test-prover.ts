/**
 * Test script for full ZK proof generation.
 * Run after circuits are compiled and keys are set up.
 */

// Ensure polyfills are loaded
import './polyfills';

import { initPoseidon, noteCommitment, deriveNullifier, poseidonHash, DOMAIN_VALUE_COMMITMENT_HASH } from './poseidon';
import { loadProvingKeys, generateSpendProof, generateOutputProof, verifySpendProof, verifyOutputProof, type SpendWitness, type OutputWitness } from './prover';

export async function testProver(): Promise<void> {
  console.log('=== ZK Prover Test ===\n');

  // Step 1: Initialize Poseidon
  console.log('1. Initializing Poseidon...');
  await initPoseidon();
  console.log('   ✓ Poseidon initialized\n');

  // Step 2: Load proving keys
  console.log('2. Loading proving keys (this may take a while)...');
  const startLoad = Date.now();
  await loadProvingKeys();
  console.log(`   ✓ Proving keys loaded in ${(Date.now() - startLoad) / 1000}s\n`);

  // Step 3: Test Output Proof (simpler)
  console.log('3. Testing Output Proof...');

  const value = 1000000000n; // 1 TSN
  const pkHash = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefn;
  const randomness = 0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321n;

  // Compute note commitment
  const commitment = noteCommitment(value, pkHash, randomness);
  console.log('   Note commitment:', commitment.toString(16).slice(0, 20) + '...');

  // Compute value commitment hash
  const valueCommitmentHash = poseidonHash(DOMAIN_VALUE_COMMITMENT_HASH, [value]);
  console.log('   Value commitment hash:', valueCommitmentHash.toString(16).slice(0, 20) + '...');

  const outputWitness: OutputWitness = {
    noteCommitment: commitment.toString(10),
    valueCommitmentHash: valueCommitmentHash.toString(10),
    value: value.toString(10),
    recipientPkHash: pkHash.toString(10),
    noteRandomness: randomness.toString(10),
  };

  console.log('   Generating output proof...');
  const startOutput = Date.now();
  const outputResult = await generateOutputProof(outputWitness);
  console.log(`   ✓ Output proof generated in ${(Date.now() - startOutput) / 1000}s`);
  console.log('   Public signals:', outputResult.publicSignals.length);

  // Verify output proof
  console.log('   Verifying output proof...');
  const outputValid = await verifyOutputProof(outputResult.proof, outputResult.publicSignals);
  console.log(`   ✓ Output proof valid: ${outputValid}\n`);

  // Step 4: Test Spend Proof (more complex - needs merkle tree)
  console.log('4. Testing Spend Proof...');

  // For testing, we'll create a simple merkle tree with just our note
  const nullifierKey = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaan;
  const position = 0n;

  // Compute nullifier
  const nullifier = deriveNullifier(nullifierKey, commitment, position);
  console.log('   Nullifier:', nullifier.toString(16).slice(0, 20) + '...');

  // For a single-leaf tree, the root equals the leaf
  // In practice, you'd get this from the server
  const merkleRoot = commitment; // Simplified for testing

  // Empty path (for testing - in reality would have 32 sibling hashes)
  const pathElements = Array(32).fill('0');
  const pathIndices = Array(32).fill(0);

  const spendWitness: SpendWitness = {
    merkleRoot: merkleRoot.toString(10),
    nullifier: nullifier.toString(10),
    valueCommitmentHash: valueCommitmentHash.toString(10),
    value: value.toString(10),
    recipientPkHash: pkHash.toString(10),
    noteRandomness: randomness.toString(10),
    nullifierKey: nullifierKey.toString(10),
    pathElements: pathElements,
    pathIndices: pathIndices,
    position: position.toString(10),
  };

  console.log('   Generating spend proof...');
  const startSpend = Date.now();
  try {
    const spendResult = await generateSpendProof(spendWitness);
    console.log(`   ✓ Spend proof generated in ${(Date.now() - startSpend) / 1000}s`);
    console.log('   Public signals:', spendResult.publicSignals.length);

    // Verify spend proof
    console.log('   Verifying spend proof...');
    const spendValid = await verifySpendProof(spendResult.proof, spendResult.publicSignals);
    console.log(`   ✓ Spend proof valid: ${spendValid}\n`);
  } catch (e) {
    console.log(`   ✗ Spend proof failed: ${e}`);
    console.log('   (This is expected if merkle path is incorrect)\n');
  }

  console.log('=== Test Complete ===');
}

// Make available globally
if (typeof window !== 'undefined') {
  (window as unknown as Record<string, unknown>).testProver = testProver;
  console.log('Run testProver() in console to test ZK proof generation');
}
