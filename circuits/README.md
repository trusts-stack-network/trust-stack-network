# TSN Circom Circuits

Circom circuits for browser-side ZK proof generation in TSN shielded transactions.

## Overview

These circuits mirror the Rust arkworks circuits exactly, enabling:
- **Browser proving**: Generate proofs client-side using snarkjs
- **Server verification**: Verify proofs on the Rust backend
- **Cross-platform compatibility**: Same constraints, same verification

## Circuits

### spend.circom
Proves valid consumption of a note:
1. Note commitment was correctly computed
2. Note exists in the commitment tree (Merkle proof)
3. Nullifier was correctly derived

### output.circom
Proves valid creation of a note:
1. Note commitment was correctly computed

## Setup

### Prerequisites
- Node.js >= 16
- circom >= 2.1.0
- snarkjs

### Install Dependencies
```bash
npm install
```

### Compile Circuits
```bash
npm run compile:all
```

### Trusted Setup

Download powers of tau ceremony file:
```bash
wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_20.ptau
```

Generate circuit-specific keys:
```bash
npm run setup:spend
npm run setup:output
```

Contribute randomness (optional but recommended):
```bash
snarkjs zkey contribute build/spend_0000.zkey build/spend_final.zkey
snarkjs zkey contribute build/output_0000.zkey build/output_final.zkey
```

Export verification keys:
```bash
npm run export:spend-vkey
npm run export:output-vkey
```

## Domain Constants

These MUST match the Rust implementation:
- `DOMAIN_NOTE_COMMITMENT = 1`
- `DOMAIN_VALUE_COMMITMENT_HASH = 2`
- `DOMAIN_NULLIFIER = 3`
- `DOMAIN_MERKLE_EMPTY = 4`
- `DOMAIN_MERKLE_NODE = 5`

## Input Format

### Spend Circuit Inputs
```json
{
  "merkleRoot": "field_element_as_decimal_string",
  "nullifier": "field_element_as_decimal_string",
  "valueCommitmentHash": "field_element_as_decimal_string",
  "value": 1000,
  "recipientPkHash": "field_element_as_decimal_string",
  "noteRandomness": "field_element_as_decimal_string",
  "nullifierKey": "field_element_as_decimal_string",
  "pathElements": ["field_element", ...],  // 32 elements
  "pathIndices": [0, 1, 0, ...],           // 32 bits
  "position": 5
}
```

### Output Circuit Inputs
```json
{
  "noteCommitment": "field_element_as_decimal_string",
  "valueCommitmentHash": "field_element_as_decimal_string",
  "value": 1000,
  "recipientPkHash": "field_element_as_decimal_string",
  "noteRandomness": "field_element_as_decimal_string"
}
```

## Files Distribution

After setup, distribute these files with your wallet:
- `build/spend.wasm` - Spend circuit WASM (~1-2MB)
- `build/output.wasm` - Output circuit WASM (~1-2MB)
- `build/spend_final.zkey` - Spend proving key (~50-100MB)
- `build/output_final.zkey` - Output proving key (~50-100MB)
- `build/spend_vkey.json` - Spend verification key (~1KB)
- `build/output_vkey.json` - Output verification key (~1KB)

## Browser Usage

```javascript
import * as snarkjs from 'snarkjs';

async function generateSpendProof(witness) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    witness,
    '/circuits/spend.wasm',
    '/circuits/spend_final.zkey'
  );
  return { proof, publicSignals };
}
```

## Testing

```bash
npm test
```

## Security Notes

- The trusted setup ceremony should involve multiple independent contributors
- Proving keys should be verified against the verification keys before use
- Circuit parameters must match the Rust backend exactly
