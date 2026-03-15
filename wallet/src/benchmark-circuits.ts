/**
 * Benchmark Plonky2 circuit building and proving times.
 *
 * Run with: npx tsx wallet/src/benchmark-circuits.ts
 */

// @ts-ignore - WASM module
import init, { WasmProver } from 'tsn-plonky2-wasm';

function randomHex32(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateMerklePath(): { siblings: string[], indices: number[] } {
  const siblings: string[] = [];
  const indices: number[] = [];
  for (let i = 0; i < 32; i++) {
    siblings.push(randomHex32());
    indices.push(Math.random() > 0.5 ? 1 : 0);
  }
  return { siblings, indices };
}

function generateWitness(numSpends: number, numOutputs: number): object {
  const spends = [];
  let totalInput = 0n;

  for (let i = 0; i < numSpends; i++) {
    const value = BigInt(1000 + i * 100);
    totalInput += value;
    const merkle = generateMerklePath();
    spends.push({
      value: value.toString(),
      recipientPkHash: randomHex32(),
      randomness: randomHex32(),
      nullifierKey: randomHex32(),
      position: i.toString(),
      merkleRoot: randomHex32(),
      merklePath: merkle.siblings,
      pathIndices: merkle.indices,
    });
  }

  const fee = 100n;
  const outputTotal = totalInput - fee;
  const perOutput = outputTotal / BigInt(numOutputs);
  const outputs = [];

  for (let i = 0; i < numOutputs; i++) {
    const isLast = i === numOutputs - 1;
    const value = isLast ? outputTotal - perOutput * BigInt(numOutputs - 1) : perOutput;
    outputs.push({
      value: value.toString(),
      recipientPkHash: randomHex32(),
      randomness: randomHex32(),
    });
  }

  return { spends, outputs, fee: fee.toString() };
}

async function benchmark() {
  console.log('=== Plonky2 Circuit Benchmark ===\n');

  // Initialize WASM
  console.log('Initializing WASM...');
  await init();
  const prover = new WasmProver();
  console.log('WASM initialized\n');

  const shapes = [
    [1, 1],
    [1, 2],
    [2, 1],
    [2, 2],
  ];

  const results: { shape: string; prebuild: number; prove: number; verify: number; proofSize: number }[] = [];

  for (const [numSpends, numOutputs] of shapes) {
    const shape = `(${numSpends},${numOutputs})`;
    console.log(`\n--- Testing shape ${shape} ---`);

    // Prebuild (first-time circuit compilation)
    console.log('  Prebuilding circuit...');
    const prebuildStart = Date.now();
    prover.prebuild_circuit(numSpends, numOutputs);
    const prebuildTime = Date.now() - prebuildStart;
    console.log(`  Prebuild: ${prebuildTime}ms`);

    // Generate witness
    const witness = generateWitness(numSpends, numOutputs);

    // Prove
    console.log('  Generating proof...');
    const proveStart = Date.now();
    const proofJson = prover.prove(JSON.stringify(witness));
    const proveTime = Date.now() - proveStart;
    console.log(`  Prove: ${proveTime}ms`);

    // Parse proof size
    const proof = JSON.parse(proofJson);
    const proofSize = proof.proofBytes.length / 2;

    // Verify
    console.log('  Verifying proof...');
    const verifyStart = Date.now();
    const valid = prover.verify(proofJson, numSpends, numOutputs);
    const verifyTime = Date.now() - verifyStart;
    console.log(`  Verify: ${verifyTime}ms (valid: ${valid})`);

    // Second prove (should be faster - circuit already built)
    console.log('  Second proof (warm cache)...');
    const witness2 = generateWitness(numSpends, numOutputs);
    const prove2Start = Date.now();
    prover.prove(JSON.stringify(witness2));
    const prove2Time = Date.now() - prove2Start;
    console.log(`  Second prove: ${prove2Time}ms`);

    results.push({
      shape,
      prebuild: prebuildTime,
      prove: proveTime,
      verify: verifyTime,
      proofSize,
    });
  }

  // Summary
  console.log('\n\n=== SUMMARY ===\n');
  console.log('| Shape   | Prebuild | 1st Prove | Verify | Proof Size |');
  console.log('|---------|----------|-----------|--------|------------|');
  for (const r of results) {
    console.log(`| ${r.shape.padEnd(7)} | ${(r.prebuild + 'ms').padEnd(8)} | ${(r.prove + 'ms').padEnd(9)} | ${(r.verify + 'ms').padEnd(6)} | ${(r.proofSize + ' B').padEnd(10)} |`);
  }

  console.log('\nNotes:');
  console.log('- Prebuild only happens once per shape (cached in WasmProver)');
  console.log('- First prove includes some JIT warmup');
  console.log('- Subsequent proofs of same shape are faster');

  prover.free();
}

benchmark().catch(console.error);
