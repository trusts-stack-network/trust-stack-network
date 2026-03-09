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
├──────────┬──────────┬───────────┬───────────────────┤
│  Core    │ Crypto   │ Consensus │    Network        │
│  Block   │ Poseidon2│ PoW + MIK │    P2P Protocol   │
│  TX      │ SLH-DSA  │ Difficulty│    Sync & Relay   │
│  UTXO    │ Plonky3  │ Validation│    Discovery      │
├──────────┴──────────┴───────────┴───────────────────┤
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

### Phase 1 — Foundations (Done)
Core blockchain engine: blocks, transactions, UTXO, Poseidon2 hashing, SLH-DSA signatures, Proof of Work consensus, P2P networking, storage, wallet, RPC API, block explorer, and faucet.

### Phase 2 — Advanced Features (In Progress)
Multi-role nodes (Miner, Relay, Prover, Light Client), Plonky3 STARK migration (replacing Halo2), and shielded wallet with full privacy.

### Phase 3 — Smart Contracts
zkVM (zero-knowledge virtual machine) for executing smart contracts inside ZK proofs. Multi-asset UTXO support, TSN-20 token standard, and Ethereum bridge.

### Phase 4 — Launch Roadmap

```
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│  APRIL 2026          MAY — JULY 2026            Q3 2026          │
│  ───────────         ──────────────────         ────────         │
│                                                                  │
│  ┌──────────┐        ┌──────────────────┐       ┌────────────┐  │
│  │ PRIVATE  │───────>│   INCENTIVIZED   │──────>│  MAINNET   │  │
│  │ TESTNET  │        │  PUBLIC TESTNET  │       │  LAUNCH    │  │
│  └──────────┘        └──────────────────┘       └────────────┘  │
│                                                                  │
│  • 5 internal nodes   • Open to everyone        • Genesis block  │
│  • Stress testing     • Bug bounty program      • Fair launch    │
│  • Bug hunting        • Node operator rewards   • No premine     │
│  • Core validation    • Smart contract testing  • Full privacy   │
│  • ZK proof testing   • Security audit          • zkVM live      │
│                       • 2-3 months duration                      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Phase 5 — Post-Mainnet
Gold-backed stablecoin **ZST** (1 ZST = 1g gold) as an independent Layer 2, with decentralized oracle price feeds and 150% over-collateralization.

## Links

- **Website**: [tsnchain.com](https://tsnchain.com)
- **Explorer**: [explorer.tsnchain.com](https://explorer.tsnchain.com)
- **Whitepaper**: [tsnchain.com/whitepaper.html](https://tsnchain.com/whitepaper.html)

## License

Proprietary — source code is not yet public. Open-source release planned for mainnet.
