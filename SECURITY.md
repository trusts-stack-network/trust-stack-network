# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

## Reporting a Vulnerability

### Responsible Disclosure

We take security seriously at Trust Stack Network. If you believe you have found a security vulnerability, please report it to us following these guidelines:

1. **Do NOT** open a public issue
2. **Do NOT** discuss the vulnerability in public channels
3. **DO** email security@tsn.network with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

### Response Timeline

- **24 hours**: Acknowledgment of receipt
- **72 hours**: Initial assessment
- **7 days**: Fix development or mitigation plan
- **30 days**: Coordinated disclosure (if applicable)

### Bug Bounty

Critical vulnerabilities in consensus, cryptography, or network layers may be eligible for a bug bounty. Contact security@tsn.network for details.

## Security Architecture

### Post-Quantum Cryptography

TSN implements multiple layers of post-quantum security:

1. **ML-DSA-65 (FIPS 204)**: Digital signatures
2. **Plonky2 STARKs**: Zero-knowledge proofs
3. **Poseidon2**: Quantum-resistant hash function

### Threat Model

#### Adversary Capabilities

- **Network**: Can intercept, modify, delay, or drop messages
- **Compute**: Has access to quantum computers (future threat)
- **Byzantine**: Can control up to f < n/3 validators

#### Security Properties

| Property | Mechanism | Status |
|----------|-----------|--------|
| Confidentiality | ChaCha20Poly1305 | ✅ Implemented |
| Integrity | SHA-256 + Poseidon2 | ✅ Implemented |
| Authentication | ML-DSA-65 | ✅ Implemented |
| Non-repudiation | On-chain signatures | ✅ Implemented |
| Availability | BFT consensus | ✅ Implemented |

## Known Limitations

### Current Release

1. **Signature Aggregation**: Not yet implemented (planned v0.2)
2. **Light Client**: In development (planned v0.3)
3. **Formal Verification**: Partial (ongoing)

### Security Debt

See [docs/security/PANIC_AUDIT_REPORT.md](docs/security/PANIC_AUDIT_REPORT.md) for ongoing security improvements.

## Security Checklist

### Pre-Release Audit

- [ ] All `unwrap()` reviewed in crypto/consensus modules
- [ ] Fuzzing targets pass 1M+ iterations
- [ ] Property-based tests pass
- [ ] Adversarial scenarios tested
- [ ] Dependencies audited (`cargo audit`)
- [ ] No unsafe blocks in hot paths
- [ ] Timing attack review completed

### Runtime Monitoring

- [ ] Panic rate monitoring
- [ ] Invalid transaction rate
- [ ] Network partition detection
- [ ] Consensus stall detection

## Security Contacts

- **Email**: security@tsn.network
- **PGP Key**: [security@tsn.network.asc](https://tsn.network/security.asc)
- **Emergency**: +1-XXX-XXX-XXXX (24/7 hotline)

## References

- [OWASP Blockchain Security](https://owasp.org/www-project-blockchain-security/)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [CWE Top 25](https://cwe.mitre.org/top25/)

---

Last updated: 2024
