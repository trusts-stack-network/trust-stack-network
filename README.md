<p align="center">
  <img src="tsn-logo.png" alt="Trust Stack Network" width="200">
</p>

<h1 align="center">Trust Stack Network (TSN)</h1>

<p align="center">
  <strong>Post-quantum privacy blockchain — Plonky3 STARKs · ML-DSA-65 · Poseidon2 · Shielded Transactions</strong>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-0.6.0-blue">
  <img alt="Rust" src="https://img.shields.io/badge/rust-84k+_lines-orange">
  <img alt="Tests" src="https://img.shields.io/badge/tests-800+-brightgreen">
  <img alt="Testnet" src="https://img.shields.io/badge/testnet-live-success">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
</p>

<p align="center">
  <a href="https://tsnchain.com">Website</a> &bull;
  <a href="https://tsnchain.com/whitepaper.html">Whitepaper</a> &bull;
  <a href="https://tsnchain.com/docs.html">Docs</a> &bull;
  <a href="https://tsnchain.com/blog.html">Blog</a> &bull;
  <a href="https://explorer.tsnchain.com">Explorer</a> &bull;
  <a href="https://tsnchain.com/testnet.html">Testnet</a> &bull;
  <a href="https://tsnchain.com/run-node.html">Run a Node</a> &bull;
  <a href="https://discord.gg/wxxNVDVn6N">Discord</a>
</p>

---

## What is TSN?

Trust Stack Network is a **Layer 1 blockchain** designed from the ground up for **privacy** and **post-quantum security**. Every transaction is shielded by default using zero-knowledge proofs, and all cryptographic primitives are quantum-resistant — protecting funds against both classical and future quantum adversaries.

## Key Features

| Feature | Description |
|---------|-------------|
| **Plonky3 STARKs** | AIR-based zero-knowledge proofs wired into block validation — no trusted setup, truly post-quantum |
| **ML-DSA-65 (FIPS 204)** | NIST post-quantum digital signatures for all transactions and blocks |
| **SLH-DSA (FIPS 205)** | Stateless hash-based signatures as secondary post-quantum layer |
| **Poseidon2** | ZK-friendly hash function over the Goldilocks field (p = 2⁶⁴ - 2³² + 1) |
| **Shielded Transactions** | Amounts and addresses hidden by default via ZK commitments and nullifiers |
| **zkVM Smart Contracts** | Stack-based VM with 30+ opcodes, gas metering, and ZK execution traces |
| **MIK Consensus** | Mining Identity Key — Proof of Work with numeric difficulty and 512-bit nonce |
| **Fast Sync** | Snapshot-based synchronization — full sync in ~20 seconds |
| **BIP39 Wallet** | 24-word mnemonic seed phrase for wallet backup and recovery |
| **DNS Seed Discovery** | Automatic peer discovery via seed1-4.tsnchain.com |
| **4 Node Roles** | Miner, Relay, Prover, Light Client — each contributes uniquely |

## Security Model

TSN is designed to be **fully quantum-safe** — not just signatures, but the entire stack:

| Layer | Primitive | Standard | Purpose |
|-------|-----------|----------|---------|
| Signatures | ML-DSA-65 | FIPS 204 | Transaction & block signing |
| Backup Signatures | SLH-DSA (SPHINCS+) | FIPS 205 | Stateless hash-based fallback |
| ZK Proofs | Plonky3 STARKs (AIR) | — | Shielded transaction validity |
| Hash Function | Poseidon2 | — | PoW mining (numeric difficulty, 512-bit nonce), Merkle trees, commitments |
| Field | Goldilocks | p = 2⁶⁴ - 2³² + 1 | ZK-friendly arithmetic |
| Encryption | ChaCha20-Poly1305 | RFC 8439 | Note payload encryption |
| Anti-Sybil | MIK | — | One identity per miner |

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         TSN Node v0.6.0                              │
├──────────────┬──────────────┬──────────────┬─────────────────────────┤
│    Core      │    Crypto    │  Consensus   │        Network          │
│  Block       │  Poseidon2   │  PoW Mining  │  P2P Protocol           │
│  Transaction │  ML-DSA-65   │  MIK Anti-   │  Kademlia DHT           │
│  UTXO State  │  Plonky3 ZK  │    Sybil     │  Gossip & Sync          │
│  Validation  │  SLH-DSA     │  Difficulty   │  Rate Limiting          │
│              │  Nullifiers  │    Adjust    │  Anti-Eclipse            │
├──────────────┴──────────────┴──────────────┴─────────────────────────┤
│  VM (zkVM)   │  Contracts (Escrow, Multisig)  │  WASM Prover          │
├──────────────┼────────────────────────────────┼───────────────────────┤
│  Storage     │  Wallet (Shielded ZK)          │  RPC (REST + JSON-RPC)│
├──────────────┼────────────────────────────────┼───────────────────────┤
│  Explorer    │  Faucet (Testnet)              │  Metrics & Health     │
└──────────────┴────────────────────────────────┴───────────────────────┘
```

## Smart Contracts (v0.6.0)

TSN includes a **stack-based zkVM** that executes smart contracts with gas metering and produces execution traces for ZK proof generation.

- **30+ opcodes**: arithmetic, storage, memory, crypto (Poseidon hash, signature verify), control flow, inter-contract calls, events
- **Contract templates**: Escrow (with arbitration & timeout), Multisig (N-of-M), Governance
- **Transaction types**: `ContractDeploy` + `ContractCall` with ML-DSA-65 signatures
- **Gas model**: per-opcode costs, block gas limit 1M, max 64KB bytecode, 100K storage slots

## Node Types

| Type | Stores Full Chain | Mines | Relays | ZK Proofs | Reward |
|------|:-:|:-:|:-:|:-:|--------|
| **Miner** `--role miner` | ✅ | ✅ | ✅ | ✅ | 92% block reward |
| **Relay** `--role relay` | ✅ | — | ✅ | — | 3% relay pool |
| **Light Client** `--role light` | — | — | — | — | — |

## Quick Start

```bash
# Clone and build
git clone https://github.com/trusts-stack-network/trust-stack-network.git
cd trust-stack-network
cargo build --release

# Run a miner node (DNS seeds are built-in — no IPs needed)
./target/release/tsn --role miner --port 9333

# Run a relay node
./target/release/tsn --role relay --port 9333

# Run a light client
./target/release/tsn --role light --port 9333
```

Peer discovery is automatic via DNS seeds (seed1-4.tsnchain.com). New nodes fast-sync from a snapshot in ~20 seconds.

See the full [Run a Node guide](https://tsnchain.com/run-node.html) for requirements and configuration.

## Network

| Parameter | Value |
|-----------|-------|
| Default Port | 9333 |
| Block Reward | 50 TSN (92% miner, 5% dev fees, 3% relay pool) |
| Target Block Time | ~10 seconds |
| Difficulty Adjustment | Every 10 blocks |
| Max Reorg Depth | 100 blocks |
| Checkpoint Interval | Every 100 blocks |

## Testnet Status

The private testnet is live with **6 nodes** and **39,000+ blocks** mined.

**Roadmap:**
1. **Private Testnet** — Active now. Internal testing.
2. **Open Testnet** — Code released on GitHub. Anyone can run a node. No rewards.
3. **Incentivized Testnet** — Multi-week. Rewards for miners and node operators.
4. **Mainnet** — Genesis block. Fair launch. No premine.

See [tsnchain.com/testnet.html](https://tsnchain.com/testnet.html) for details.

## API

| Endpoint | Description |
|----------|-------------|
| `GET /chain/info` | Block height, difficulty, latest hash |
| `GET /peers` | Connected peers |
| `GET /sync/status` | Sync progress and peer count |
| `GET /block/height/:n` | Get block by height |
| `POST /tx/submit` | Submit transaction |
| `POST /faucet/claim` | Claim testnet tokens |
| `GET /explorer` | Built-in block explorer |
| `GET /wallet` | Built-in web wallet |

## Codebase

- **84,000+ lines** of Rust
- **800+ tests** across 20+ modules
- **280+ source files**
- **700+ commits** of active development
- **6 nodes** running on private testnet
- Written in Rust 2021 edition, zero unsafe code

## Comparison

See how TSN compares to other blockchains: [tsnchain.com/comparison.html](https://tsnchain.com/comparison.html)

## Links

- **Website**: [tsnchain.com](https://tsnchain.com)
- **Testnet**: [tsnchain.com/testnet.html](https://tsnchain.com/testnet.html)
- **Run a Node**: [tsnchain.com/run-node.html](https://tsnchain.com/run-node.html)
- **Whitepaper**: [tsnchain.com/whitepaper.html](https://tsnchain.com/whitepaper.html)
- **Documentation**: [tsnchain.com/docs.html](https://tsnchain.com/docs.html)
- **Blog**: [tsnchain.com/blog.html](https://tsnchain.com/blog.html)
- **Explorer**: [explorer.tsnchain.com](https://explorer.tsnchain.com)
- **Discord**: [discord.gg/wxxNVDVn6N](https://discord.gg/wxxNVDVn6N)

## License

MIT — Open source.
