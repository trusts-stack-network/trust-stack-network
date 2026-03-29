<p align="center">
  <img src="tsn-logo.png" alt="Trust Stack Network" width="200">
</p>

<h1 align="center">Trust Stack Network (TSN)</h1>

<p align="center">
  <strong>Post-quantum privacy blockchain — Plonky3 STARKs · ML-DSA-65 · Poseidon2 · Shielded Transactions</strong>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-1.2.0-blue">
  <img alt="Rust" src="https://img.shields.io/badge/rust-94k+_lines-orange">
  <img alt="Tests" src="https://img.shields.io/badge/tests-369_passing-brightgreen">
  <img alt="Testnet" src="https://img.shields.io/badge/testnet-live-success">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
</p>

<p align="center">
  <a href="https://tsnchain.com">Website</a> &bull;
  <a href="https://tsnchain.com/whitepaper.html">Whitepaper</a> &bull;
  <a href="https://tsnchain.com/docs.html">Docs</a> &bull;
  <a href="https://tsnchain.com/blog.html">Blog</a> &bull;
  <a href="https://explorer.tsnchain.com">Explorer</a> &bull;
  <a href="https://tsnchain.com/run-node.html">Run a Node</a> &bull;
  <a href="https://discord.gg/wxxNVDVn6N">Discord</a>
</p>

---

> **Note:** TSN is currently in **private testnet**. TSN tokens have **no monetary value** at this stage. They will only become meaningful once the incentivized testnet and eventually mainnet are launched. Do not purchase or trade TSN tokens — they can be mined for free by running a node.

---

## What is TSN?

Trust Stack Network is a **Layer 1 blockchain** designed from the ground up for **privacy** and **post-quantum security**. Every transaction is shielded by default using zero-knowledge proofs, and all cryptographic primitives are quantum-resistant — protecting funds against both classical and future quantum adversaries.

## Key Features

| Feature | Description |
|---------|-------------|
| **Plonky3 STARKs** | AIR-based zero-knowledge proofs wired into block validation — no trusted setup, truly post-quantum |
| **ML-DSA-65 (FIPS 204)** | NIST post-quantum digital signatures for all transactions and blocks |
| **SLH-DSA (FIPS 205)** | Stateless hash-based signatures as secondary post-quantum layer |
| **Poseidon2 PoW** | ZK-friendly hash function over Goldilocks field — same hash for mining AND ZK proofs |
| **Shielded Transactions** | Working V2 transactions with ZK proofs, broadcast and validated across the network |
| **Interactive Wallet** | `./tsn wallet` — generate, restore (BIP39 24-word seed), send, receive, history |
| **P2P Auto-Update** | Nodes detect new versions via peer handshake, download, verify, and self-update |
| **Anti-Reorg Protection** | MAX_REORG_DEPTH=100, Fork ID verification, anchor block filtering |
| **zkVM Smart Contracts** | Stack-based VM with 30+ opcodes, gas metering, and ZK execution traces |
| **MIK Consensus** | Mining Identity Key — Proof of Work with numeric difficulty and 512-bit nonce |
| **Fast Sync** | Snapshot-based synchronization — full sync in ~2 seconds |
| **3 Node Roles** | Miner, Relay, Light Client — each with auto-update capability |

## Security Model

TSN is designed to be **fully quantum-safe** — not just signatures, but the entire stack:

| Layer | Primitive | Standard | Purpose |
|-------|-----------|----------|---------|
| Signatures | ML-DSA-65 | FIPS 204 | Transaction & block signing |
| Backup Signatures | SLH-DSA (SPHINCS+) | FIPS 205 | Stateless hash-based fallback |
| ZK Proofs | Plonky3 STARKs (AIR) | — | Shielded transaction validity |
| Hash Function | Poseidon2 | — | PoW mining, Merkle trees, commitments |
| Field | Goldilocks | p = 2⁶⁴ - 2³² + 1 | ZK-friendly arithmetic |
| Encryption | ChaCha20-Poly1305 | RFC 8439 | Note payload encryption |
| Anti-Sybil | MIK | — | One identity per miner |

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         TSN Node v1.2.0                              │
├──────────────┬──────────────┬──────────────┬─────────────────────────┤
│    Core      │    Crypto    │  Consensus   │        Network          │
│  Block       │  Poseidon2   │  PoW Mining  │  libp2p (GossipSub)     │
│  Transaction │  ML-DSA-65   │  MIK Anti-   │  Kademlia DHT           │
│  UTXO State  │  Plonky3 ZK  │    Sybil     │  Auto-Update (P2P)      │
│  Validation  │  SLH-DSA     │  LWMA Diff   │  Anti-Eclipse           │
│              │  Nullifiers  │    Adjust    │  Rate Limiting          │
├──────────────┴──────────────┴──────────────┴─────────────────────────┤
│  VM (zkVM)   │  Contracts (Escrow, Multisig, AMM)  │  Stablecoin    │
├──────────────┼─────────────────────────────────────┼────────────────┤
│  Storage     │  Wallet (Shielded ZK + BIP39)       │  RPC (REST)    │
├──────────────┼─────────────────────────────────────┼────────────────┤
│  Explorer    │  Faucet (Testnet)                   │  Metrics       │
└──────────────┴─────────────────────────────────────┴────────────────┘
```

## Quick Start

### Download binary (recommended)

```bash
# Download latest release
curl -LO https://github.com/trusts-stack-network/trust-stack-network/releases/latest/download/tsn-linux-x86_64.tar.gz
tar xzf tsn-linux-x86_64.tar.gz
cd tsn-*

# Run a miner (4 threads)
./tsn miner -t 4

# Run a relay node
./tsn relay

# Run a light client
./tsn light
```

### Build from source

```bash
git clone https://github.com/trusts-stack-network/trust-stack-network.git
cd trust-stack-network
cargo build --release

# Run (seeds and wallet auto-detected)
./target/release/tsn miner -t 4
```

That's it. Peer discovery is automatic via DNS seeds (seed1-4.tsnchain.com). New nodes fast-sync from a snapshot in ~2 seconds.

### CLI Reference

```bash
./tsn miner -t 4           # Mine with 4 threads
./tsn relay                 # Run relay node
./tsn light                 # Run light client
./tsn wallet                # Interactive wallet menu
./tsn balance               # Check balance
./tsn send --to <addr> --amount 10  # Send TSN
./tsn new-wallet            # Generate new wallet (24-word BIP39 seed)
./tsn --version             # Print version info
```

## Node Types

| Type | Stores Chain | Mines | Relays | Auto-Update | Reward |
|------|:-:|:-:|:-:|:-:|--------|
| **Miner** `./tsn miner` | Yes | Yes | Yes | Yes | 92% block reward |
| **Relay** `./tsn relay` | Yes | — | Yes | Yes | 3% relay pool |
| **Light Client** `./tsn light` | — | — | — | Yes | — |

All node types auto-update when a new version is detected on the network.

## P2P Auto-Update

TSN is one of the first blockchains with **fully decentralized automatic updates**. No other blockchain combines P2P version signaling with multi-source download and cryptographic verification.

**How it works:**
1. Peers announce their version during the libp2p Identify handshake
2. If a peer has a newer version, the node queries the official release
3. Binary is downloaded from GitHub (primary) or tsnchain.com (fallback)
4. SHA256 integrity check + Ed25519 signature verification
5. Current binary backed up, new binary installed, node restarts

```
Node A (v1.1.0) connects to Node B (v1.2.0)
  → A detects newer version via P2P handshake
  → A downloads v1.2.0 from GitHub, verifies signature
  → A self-updates and restarts
  → A is now v1.2.0
  → A's other peers detect the update via handshake
  → Network propagates the update in minutes
```

Manual update: `./tsn update`

## Mining & Hashrate — Poseidon2 Proof of Work

TSN uses **Poseidon2** as its PoW hash function instead of SHA-256 (Bitcoin) or RandomX (Monero):

- **ZK-native**: Same hash for mining AND shielded transaction proofs (Plonky3 STARKs). One hash for the entire stack.
- **Post-quantum friendly**: Algebraic hashes over large fields resist Grover's algorithm.
- **ASIC-resistant**: Field arithmetic is complex enough that ASICs offer limited advantage over CPUs.

### How Mining Works

```
1. Build block template (transactions + coinbase)
2. Generate random 512-bit nonce
3. Hash: Poseidon2(header_fields, nonce) → 32 bytes
4. Check: first_8_bytes_as_u64 < (u64::MAX / difficulty)
5. Valid → broadcast block. Invalid → new nonce.
```

### Hashrate Benchmarks

| CPU | Threads | Hashrate |
|-----|---------|----------|
| EPYC 7742 | 1T | 121 KH/s |
| EPYC 7742 | 4T | 257 KH/s |
| EPYC 7742 | 8T | 454 KH/s |
| Xeon E5-2697A v4 | 2T | ~80 KH/s |

**Note:** Poseidon2 hashrates are not comparable to SHA-256 or RandomX. Different hash functions have different work-per-hash. TSN's difficulty adjusts via LWMA (45-block window) to target 10-second blocks.

### Network Hashrate Formula

```
network_hashrate = difficulty / block_time
```

Displayed in the explorer and `/chain/info` API.

## Smart Contracts

TSN includes a **stack-based zkVM** with gas metering and ZK execution traces:

- **30+ opcodes**: arithmetic, storage, memory, crypto (Poseidon hash, signature verify), control flow, events
- **Contract templates**: Escrow (with arbitration & timeout), Multisig (N-of-M), AMM Pool, Governance
- **Gas model**: per-opcode costs, block gas limit 1M, max 64KB bytecode, 100K storage slots

## Network Parameters

| Parameter | Value |
|-----------|-------|
| Default Port | 9333 |
| Block Reward | 50 TSN (92% miner, 5% dev fees, 3% relay pool) |
| Target Block Time | ~10 seconds |
| Difficulty Adjustment | LWMA per-block (N=45 window) |
| P2P Protocol | libp2p GossipSub mesh (D=6, heartbeat 700ms) |
| Max Reorg Depth | 100 blocks |
| Min Difficulty | 1000 |
| Nonce Size | 512 bits |
| Max TX Size | 1 MB |

## Testnet Status

The private testnet is live with **5 nodes** and **29,000+ blocks** mined.

> **TSN tokens currently have no value.** The testnet is for development and testing only. Tokens can be mined for free by anyone running a node. Economic value will only be introduced at the incentivized testnet phase.

**Roadmap:**
1. **Private Testnet** — Active now. Internal testing and development.
2. **Open Testnet** — Code on GitHub. Anyone can run a node and mine. No value.
3. **Incentivized Testnet** — Rewards for miners and node operators. Tokens begin to have value.
4. **Mainnet** — Genesis block. Fair launch. No premine.

## Changelog

### v1.1.0 — Performance & Production Hardening

| Feature | Before | After |
|---------|--------|-------|
| Mining Hot Loop | Full header rebuilt per hash | MiningHashContext — zero heap alloc |
| Hashrate Display | Truncated hash, no KH/s | Real-time KH/s, full hash |
| Explorer Hashrate | Wrong formula | Corrected: `difficulty / block_time` |
| Wallet TX History | Not saved | Sent + received persisted (WalletTxRecord) |
| Received TX Detection | Manual | Automatic at wallet scan |
| Nullifier Check | At send only | At scan + send (prevents double-spend) |
| P2P Version Gate | Accept all peers | Disconnect peers below MINIMUM_VERSION |
| CLI | Multiple flags required | `./tsn miner -t 4` — everything auto-detected |
| Auto-Update | None | P2P signaling + multi-source download + SHA256 verification |

### v0.8.0 — Transactions, Wallet & Security

- Working V2 shielded transactions (create, sign, broadcast, validate)
- Interactive wallet menu with BIP39 recovery
- MAX_REORG_DEPTH = 100, Fork ID verification, anchor block filtering
- Dual mining across multiple nodes

### v0.7.1 — Security Audit & Hardening

Full security audit: 29 findings, 23 fixes applied. Score: **5.4/10 → 8.1/10**. Zero critical vulnerabilities remaining.

### v0.7.0 — Scaling & Reliability

- LWMA per-block difficulty adjustment (N=45 window)
- GossipSub mesh P2P (replaced flood protocol)
- Cryptographic random nonces (zero miner collisions)
- Concurrent block relay, canonical height in DB

### v0.6.0 — Major Network Upgrade

- Numeric difficulty system with 512-bit nonce
- Poseidon2 PoW (plonky3)
- Fast sync (~2 seconds)
- BIP39 wallet recovery
- DNS seed discovery
- Chain Watchdog monitoring

## Codebase

| Metric | Value |
|--------|-------|
| Language | Rust 2021 edition |
| Lines of code | 94,000+ |
| Source files | 298 |
| Tests | 369 passing |
| Commits | 32+ |
| Nodes | 5 (1 miner + 4 seeds) |

## API

| Endpoint | Description |
|----------|-------------|
| `GET /chain/info` | Block height, difficulty, latest hash, version |
| `GET /peers` | Connected peers |
| `GET /sync/status` | Sync progress and peer count |
| `GET /block/height/:n` | Get block by height |
| `POST /tx/submit` | Submit shielded transaction |
| `GET /explorer` | Built-in block explorer |
| `GET /version.json` | Node version info (used by auto-update) |

## Links

- **Website**: [tsnchain.com](https://tsnchain.com)
- **Explorer**: [explorer.tsnchain.com](https://explorer.tsnchain.com)
- **Whitepaper**: [tsnchain.com/whitepaper.html](https://tsnchain.com/whitepaper.html)
- **Documentation**: [tsnchain.com/docs.html](https://tsnchain.com/docs.html)
- **Run a Node**: [tsnchain.com/run-node.html](https://tsnchain.com/run-node.html)
- **Blog**: [tsnchain.com/blog.html](https://tsnchain.com/blog.html)
- **Discord**: [discord.gg/wxxNVDVn6N](https://discord.gg/wxxNVDVn6N)

## License

MIT — Open source.
