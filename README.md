<p align="center">
  <img src="tsn-logo.png" alt="Trust Stack Network" width="200">
</p>

<h1 align="center">Trust Stack Network (TSN)</h1>

<p align="center">
  <strong>Post-quantum privacy blockchain</strong><br>
  Plonky3 STARKs &bull; SLH-DSA &bull; Poseidon2 &bull; Shielded Transactions
</p>

<p align="center">
  <a href="https://tsnchain.com">Website</a> &bull;
  <a href="https://tsnchain.com/whitepaper.html">Whitepaper</a> &bull;
  <a href="https://explorer.tsnchain.com">Explorer</a> &bull;
  <a href="https://tsnchain.com/docs.html">Docs</a> &bull;
  <a href="https://tsnchain.com/network-simulation.html">Network Simulation</a>
</p>

---

## What is TSN?

Trust Stack Network is a **Layer 1 blockchain** designed from the ground up for **privacy** and **post-quantum security**. Every transaction is shielded by default using zero-knowledge proofs, and all cryptographic primitives are quantum-resistant.

## Key Features

| Feature | Description |
|---------|-------------|
| **Plonky3 STARKs** | Hash-based zero-knowledge proofs — no trusted setup, truly post-quantum |
| **SLH-DSA (SPHINCS+)** | NIST FIPS-205 post-quantum digital signatures |
| **Poseidon2** | ZK-friendly hash function, 3x faster than Poseidon |
| **Shielded Transactions** | Amounts and addresses hidden by default via ZK proofs |
| **UTXO Model** | Bitcoin-inspired unspent transaction outputs with privacy |
| **MIK Consensus** | Mining Identity Key — Proof of Work with anti-sybil protection |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   TSN Node                          │
├──────────┬──────────┬───────────┬──────────────────-┤
│  Core    │ Crypto   │ Consensus │    Network        │
│  Block   │ Poseidon2│ PoW + MIK │    P2P Protocol   │
│  TX      │ SLH-DSA  │ Difficulty│    Sync & Relay   │
│  UTXO    │ Plonky3  │ Validation│    Discovery      │
├──────────┴──────────┴───────────┴──────────────────-┤
│  Storage (RocksDB)  │  Wallet (Shielded)  │  RPC    │
└─────────────────────┴─────────────────────┴─────────┘
```

## Node Types

| Type | Role | Reward |
|------|------|--------|
| **Miner** | Produces blocks, earns block reward | 85% of block reward |
| **Relay/Seed** | Stores chain, relays blocks & transactions | 8% relay pool |
| **Prover** | Generates ZK proofs on demand | Proving fees |
| **Light Client** | Wallet-only, verifies via proofs | — |

## Codebase

- **80,000+ lines** of Rust
- **766 unit tests**
- **268 source files** across 20+ modules
- **5 nodes** running on private testnet

## Roadmap

| Phase | Status |
|-------|--------|
| Core, Crypto, Consensus, Network, Storage | Done |
| Wallet, RPC, Explorer, Faucet | Done |
| Multi-Role Nodes (Miner, Relay, Prover, Light Client) | In Progress |
| Plonky3 Migration & Halo2 Removal | Planned |
| zkVM & Smart Contracts | Planned |
| Private Testnet (April 2026) | Active |
| Incentivized Testnet (May-July 2026) | Planned |
| Mainnet Launch (Q3 2026) | Planned |
| Gold-Backed Stablecoin ZST (Post-Mainnet L2) | Planned |

## Links

- **Website**: [tsnchain.com](https://tsnchain.com)
- **Explorer**: [explorer.tsnchain.com](https://explorer.tsnchain.com)
- **Whitepaper**: [tsnchain.com/whitepaper.html](https://tsnchain.com/whitepaper.html)

## License

Proprietary — source code is not yet public. Open-source release planned for mainnet.
