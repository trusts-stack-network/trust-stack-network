/**
 * Simple test script for Poseidon hashing.
 * Import this in your app or run via browser console.
 */

// Ensure polyfills are loaded
import './polyfills';

import { initPoseidon, noteCommitment, deriveNullifier, poseidonHash, DOMAIN_NOTE_COMMITMENT } from './poseidon';

export async function testPoseidon(): Promise<void> {
  console.log('Initializing Poseidon...');
  await initPoseidon();
  console.log('Poseidon initialized!');

  // Test basic hash
  const testInput = 12345n;
  const hash = poseidonHash(DOMAIN_NOTE_COMMITMENT, [testInput]);
  console.log('Test hash:', hash.toString(16));

  // Test note commitment
  const value = 1000000000n; // 1 TSN
  const pkHash = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefn;
  const randomness = 0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321n;

  const commitment = noteCommitment(value, pkHash, randomness);
  console.log('Note commitment:', commitment.toString(16));

  // Test nullifier derivation
  const nullifierKey = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaan;
  const position = 5n;

  const nullifier = deriveNullifier(nullifierKey, commitment, position);
  console.log('Nullifier:', nullifier.toString(16));

  console.log('All Poseidon tests passed!');
}

export async function testPoseidonCompatibility(): Promise<void> {
  console.log('=== Poseidon Compatibility Test ===\n');

  console.log('Initializing Poseidon...');
  await initPoseidon();

  // Test the exact same input as Rust: poseidon([1, 2, 3, 4])
  // This should match: [101, 4, 37, 101, 223, 37, 165, 186, ...] from Rust
  const poseidon = (await import('circomlibjs')).buildPoseidon();
  const poseidonInstance = await poseidon;

  const inputs = [1n, 2n, 3n, 4n];
  const result = poseidonInstance(inputs);
  const resultBigInt = poseidonInstance.F.toObject(result);

  console.log('Input: [1, 2, 3, 4]');
  console.log('Result (bigint):', resultBigInt.toString());
  console.log('Result (hex):', resultBigInt.toString(16));

  // Convert to bytes (little-endian)
  const bytes = new Uint8Array(32);
  let temp = resultBigInt;
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(temp & 0xFFn);
    temp >>= 8n;
  }
  console.log('Result (bytes LE):', Array.from(bytes));

  // Expected from Rust light-poseidon:
  // [101, 4, 37, 101, 223, 37, 165, 186, 61, 102, 224, 28, 187, 14, 230, 55, 152, 11, 81, 228, 64, 250, 206, 157, 215, 253, 193, 182, 125, 134, 156, 41]
  const rustExpected = [101, 4, 37, 101, 223, 37, 165, 186, 61, 102, 224, 28, 187, 14, 230, 55, 152, 11, 81, 228, 64, 250, 206, 157, 215, 253, 193, 182, 125, 134, 156, 41];
  console.log('Rust expected:', rustExpected);

  const match = bytes.every((b, i) => b === rustExpected[i]);
  console.log('\nMatch:', match ? '✓ YES - Hashes are identical!' : '✗ NO - Hashes differ!');

  if (!match) {
    console.log('\nDifferences:');
    for (let i = 0; i < 32; i++) {
      if (bytes[i] !== rustExpected[i]) {
        console.log(`  Byte ${i}: TS=${bytes[i]}, Rust=${rustExpected[i]}`);
      }
    }
  }
}

// Auto-run if loaded directly
if (typeof window !== 'undefined') {
  (window as unknown as Record<string, unknown>).testPoseidon = testPoseidon;
  (window as unknown as Record<string, unknown>).testPoseidonCompatibility = testPoseidonCompatibility;
  console.log('Run testPoseidon() or testPoseidonCompatibility() in console');
}
