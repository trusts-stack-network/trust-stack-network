# Threat Model - Crypto Module

## Adversary Model
- **Capability**: Can measure timing, memory access patterns, electromagnetic emissions
- **Access**: Network messages, public API, block data
- **Goal**: Extract private keys, forge signatures, break anonymity

## STRIDE Analysis

### Spoofing
- **Threat**: Signature forgery via timing attacks
- **Mitigation**: Constant-time signature verification
- **Status**: FIXED (see tests/crypto/test_signature_ct.rs)

### Tampering
- **Threat**: Invalid nullifier generation causing state corruption
- **Mitigation**: Input validation with secure error handling
- **Status**: FIXED (see fuzz/fuzz_targets/nullifier.rs)

### Repudiation
- **Threat**: Transaction repudiation via malleability
- **Mitigation**: SIGHASH_ALL equivalent binding
- **Status**: IMPLEMENTED (see src/crypto/binding.rs)

### Information Disclosure
- **Threat**: Private key leakage via side-channels
- **Mitigation**: Constant-time operations, blinding
- **Status**: PARTIAL (see tests/crypto/test_key_ct.rs)

### Denial of Service
- **Threat**: Panic via malicious inputs
- **Mitigation**: Bounds checking, no unwrap() in crypto code
- **Status**: FIXED (see fuzz/fuzz_targets/crypto_parsers.rs)

### Elevation of Privilege
- **Threat**: Bypassing crypto validation
- **Mitigation**: Formal verification of state transitions
- **Status**: IN PROGRESS (see tests/crypto/test_state_transitions.rs)

## Critical Functions Audit

### Signature Verification
- **Risk**: Timing attack revealing valid signatures
- **CVSS**: 7.5 HIGH
- **Test**: `tests/crypto/test_signature_ct.rs`

### Key Derivation
- **Risk**: Side-channel leakage of private key material
- **CVSS**: 8.8 CRITICAL
- **Test**: `tests/crypto/test_key_derivation_ct.rs`

### Nullifier Generation
- **Risk**: Panic on invalid input leading to DoS
- **CVSS**: 6.5 MEDIUM
- **Test**: `fuzz/fuzz_targets/nullifier_generation.rs`

### Poseidon Hash
- **Risk**: Non-constant time revealing pre-image
- **CVSS**: 7.1 HIGH
- **Test**: `tests/crypto/test_poseidon_ct.rs`