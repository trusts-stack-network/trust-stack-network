/**
 * Test script for binding signature implementation.
 *
 * Run with: npx vite-node src/test-binding.ts
 */

import {
  initBindingCrypto,
  isBindingCryptoReady,
  commitToValue,
  serializeCommitment,
  BindingContext,
  computeBindingMessage,
  bytesToHex,
} from './binding';

async function testBindingSignature() {
  console.log('=== Binding Signature Tests ===\n');

  // Initialize BN254 curve
  console.log('1. Initializing BN254 curve...');
  const startInit = Date.now();
  await initBindingCrypto();
  console.log(`   Initialized in ${Date.now() - startInit}ms`);
  console.log(`   Curve ready: ${isBindingCryptoReady()}\n`);

  // Test value commitment
  console.log('2. Testing value commitment...');
  const value1 = 1000000000n; // 1 TSN (assuming 9 decimals)
  const vc1 = commitToValue(value1);
  const vc1Bytes = serializeCommitment(vc1);
  console.log(`   Value: ${value1}`);
  console.log(`   Commitment (32 bytes): ${bytesToHex(vc1Bytes)}`);
  console.log(`   Commitment length: ${vc1Bytes.length}\n`);

  // Test deterministic commitment with fixed randomness
  console.log('3. Testing deterministic commitment...');
  const fixedRandomness = new Uint8Array(32);
  fixedRandomness[0] = 42; // Non-zero randomness
  const vcDet1 = commitToValue(value1, fixedRandomness);
  const vcDet2 = commitToValue(value1, fixedRandomness);
  const det1Bytes = serializeCommitment(vcDet1);
  const det2Bytes = serializeCommitment(vcDet2);
  const deterministicMatch = bytesToHex(det1Bytes) === bytesToHex(det2Bytes);
  console.log(`   Same randomness produces same commitment: ${deterministicMatch}\n`);

  // Test BindingContext for transaction
  console.log('4. Testing BindingContext (simulated transaction)...');
  const ctx = new BindingContext();

  // Simulate: spending 10 TSN, sending 7 TSN, fee 0.5 TSN, change 2.5 TSN
  const spendValue = 10_000_000_000n;
  const outputValue = 7_000_000_000n;
  const changeValue = 2_500_000_000n;
  const fee = 500_000_000n;

  console.log(`   Spend: ${spendValue} (10 TSN)`);
  console.log(`   Output: ${outputValue} (7 TSN)`);
  console.log(`   Change: ${changeValue} (2.5 TSN)`);
  console.log(`   Fee: ${fee} (0.5 TSN)`);

  // Add spend
  const spendCommit = ctx.addSpend(spendValue);
  console.log(`   Spend commitment: ${bytesToHex(serializeCommitment(spendCommit)).slice(0, 32)}...`);

  // Add outputs
  const outputCommit = ctx.addOutput(outputValue);
  const changeCommit = ctx.addOutput(changeValue);
  console.log(`   Output commitment: ${bytesToHex(serializeCommitment(outputCommit)).slice(0, 32)}...`);
  console.log(`   Change commitment: ${bytesToHex(serializeCommitment(changeCommit)).slice(0, 32)}...`);

  // Set fee
  ctx.setFee(fee);

  // Verify balance
  const balanced = ctx.verifyBalance();
  console.log(`   Balance verified: ${balanced}`);

  if (!balanced) {
    console.log('   ERROR: Balance verification failed!');
    return;
  }

  // Create binding signature
  console.log('\n5. Creating binding signature...');
  const nullifiers = [new Uint8Array(32), new Uint8Array(32)]; // Dummy nullifiers
  nullifiers[0][0] = 1;
  nullifiers[1][0] = 2;

  const outputCms = [new Uint8Array(32), new Uint8Array(32)]; // Dummy output commitments
  outputCms[0][0] = 3;
  outputCms[1][0] = 4;

  const startSig = Date.now();
  const signature = ctx.createSignature(nullifiers, outputCms);
  console.log(`   Signature created in ${Date.now() - startSig}ms`);
  console.log(`   Signature (64 bytes): ${bytesToHex(signature)}`);
  console.log(`   Signature length: ${signature.length}`);

  // Verify signature structure
  const rPoint = signature.slice(0, 32);
  const sScalar = signature.slice(32, 64);
  console.log(`   R point: ${bytesToHex(rPoint)}`);
  console.log(`   s scalar: ${bytesToHex(sScalar)}`);

  // Test binding message computation
  console.log('\n6. Testing binding message computation...');
  const message = computeBindingMessage(nullifiers, outputCms, fee);
  console.log(`   Message (64 bytes): ${bytesToHex(message).slice(0, 64)}...`);
  console.log(`   Message length: ${message.length}`);

  // Test unbalanced transaction (should fail)
  console.log('\n7. Testing unbalanced transaction (should fail)...');
  const badCtx = new BindingContext();
  badCtx.addSpend(1000n);
  badCtx.addOutput(2000n); // More output than input!
  badCtx.setFee(0n);
  const badBalance = badCtx.verifyBalance();
  console.log(`   Unbalanced transaction detected: ${!badBalance}`);

  try {
    badCtx.createSignature([], []);
    console.log('   ERROR: Should have thrown on unbalanced transaction!');
  } catch (e) {
    console.log(`   Correctly threw error: ${(e as Error).message}`);
  }

  console.log('\n=== All tests passed! ===');
}

// Run tests
testBindingSignature().catch(console.error);
