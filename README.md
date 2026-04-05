<p align="center">
  <img src="https://avatars.githubusercontent.com/u/265249968?v=4" alt="Trust Stack Network" width="120">
</p>

<h1 align="center">Trust Stack Network (TSN)</h1>

<p align="center">
  <strong>Post-quantum privacy blockchain — Plonky3 STARKs · ML-DSA-65 · Poseidon2 · Shielded Transactions</strong>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-1.6.2-blue">
  <img alt="Rust" src="https://img.shields.io/badge/rust-84k+_lines-orange">
  <img alt="Tests" src="https://img.shields.io/badge/tests-370_passing-brightgreen">
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

### Mining Identity Key (MIK)

Every miner must register a **Mining Identity Key** before mining:

- Derived from their ML-DSA-65 public key: `MIK_ID = SHA-256("TSN_MIK_ID_v1" || pubkey || block_height)`
- One active MIK per public key — prevents Sybil attacks
- Lifecycle: registration → activation delay (10 blocks) → active → optional expiry/revocation
- Block signatures verified against the miner's registered MIK

### Signature Sizes

| Parameter | ML-DSA-65 |
|-----------|-----------|
| Public Key | 1,952 bytes |
| Secret Key | 4,032 bytes |
| Signature | 3,309 bytes |

### Commitment Scheme

```
Note Commitment = Poseidon(domain=1, value, pk_hash, randomness)
Nullifier       = Poseidon(domain=3, nullifier_key, commitment, position)
Merkle Node     = Poseidon(domain=5, left, right)
```

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         TSN Node v1.4.0                              │
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
│  Explorer    │  Metrics & Monitoring                │  CLI Tools     │
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

Requires **Rust nightly** (automatically selected via `rust-toolchain.toml`):

```bash
# Install Rust if needed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

git clone https://github.com/trusts-stack-network/trust-stack-network.git
cd trust-stack-network
cargo build --release

# Run (seeds and wallet auto-detected)
./target/release/tsn miner -t 4
```

Peer discovery is automatic via DNS seeds (seed1-4.tsnchain.com). New nodes fast-sync from a snapshot in ~2 seconds.

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

TSN supports 3 distinct node roles, selectable at startup:

### Miner Node (`./tsn miner`)
Full node that validates, stores the entire blockchain, relays transactions/blocks, **and mines new blocks**. Miners earn **92% of the block reward** (46 TSN per block). This is the default role.

### Relay Node (`./tsn relay`)
Full node that stores the complete chain and relays blocks/transactions to peers, but **does not mine**. Relays are the backbone of the network — they ensure fast block propagation via GossipSub and serve snapshots to new nodes via fast-sync. They earn from the **3% relay reward pool**.

### Light Client (`./tsn light`)
Minimal node that **does not store the full chain** — it syncs only block headers and verifies transactions using ZK proofs. Designed for mobile wallets and resource-constrained devices.

| Type | Stores Chain | Mines | Relays | Auto-Update | Reward |
|------|:-:|:-:|:-:|:-:|--------|
| **Miner** | Yes | Yes | Yes | Yes | 92% block reward |
| **Relay** | Yes | — | Yes | Yes | 3% relay pool |
| **Light Client** | — | — | — | Yes | — |

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
| HTTP API Port | 9333 |
| P2P Port (libp2p) | 9334 |
| Block Reward | 50 TSN (92% miner, 5% dev fees, 3% relay pool) |
| Halving Interval | 4,200,000 blocks (~16 months) |
| Target Block Time | ~10 seconds |
| Difficulty Adjustment | LWMA per-block (N=45 window) |
| P2P Protocol | libp2p GossipSub mesh (D=6, heartbeat 700ms) |
| Max Reorg Depth | 100 blocks |
| Min Difficulty | 1,500,000 |
| Nonce Size | 512 bits |
| Max TX Size | 1 MB |
| Max Supply | ~420,000,000 TSN (~10 years to reach) |

## Synchronization & Anti-Fork System

### Fast-Sync Protocol

New nodes join the network in **seconds** by downloading a compressed state snapshot:

```
┌─────────────┐     GET /snapshot/info      ┌─────────────┐
│  New Node   │ ──────────────────────────>  │  Seed Node  │
│             │     GET /snapshot/download   │             │
│  --fast-sync│ <────────────────────────── │  (gzip)     │
│             │                              │             │
│  Load state │     GET /blocks?from=N       │             │
│  Sync rest  │ ──────────────────────────>  │             │
└─────────────┘                              └─────────────┘
```

1. New node requests a **gzip-compressed state snapshot** from a peer
2. Loads the snapshot and verifies `state_root` integrity
3. Syncs only the **missing blocks** since the snapshot height
4. Ready to mine in ~2 seconds

### Anti-Fork Protections

| Protection | Description |
|------------|-------------|
| **Heaviest chain rule** | Fork choice based on cumulative work, not height |
| **MAX_REORG_DEPTH = 100** | Hard limit — no reorg deeper than 100 blocks |
| **Checkpoint finality** | Every 100 blocks, a checkpoint is created |
| **Fork ID verification** | Genesis hash checked at sync — prevents silent splits |
| **Anchor block filter** | Blocks must reference a recent valid ancestor |
| **P2P version gate** | Nodes below MINIMUM_VERSION (v1.3.0) are rejected |

## Testnet Status

The private testnet is live with **5 nodes** and **11,700+ blocks** mined.

> **TSN tokens currently have no value.** The testnet is for development and testing only. Tokens can be mined for free by anyone running a node. Economic value will only be introduced at the incentivized testnet phase.

**Roadmap:**
1. **Private Testnet** — Active now. Internal testing and development.
2. **Open Testnet** — Code on GitHub. Anyone can run a node and mine. No value.
3. **Incentivized Testnet** — Rewards for miners and node operators. Tokens begin to have value.
4. **Mainnet** — Genesis block. Fair launch. No premine.

## Roadmap

### Phase 1 — Foundations ✅
Core blockchain engine: blocks, transactions, UTXO, Poseidon2 hashing, ML-DSA-65 signatures, Proof of Work consensus with MIK anti-Sybil, P2P networking with Kademlia DHT, SledDB storage, shielded wallet, REST API, and block explorer.

### Phase 2 — Advanced Features ✅
Multi-role nodes (Miner, Relay, Light Client), Plonky3 STARK migration (AIR-based proofs via p3-uni-stark), enhanced shielded wallet with BIP39 recovery and viewing keys, hardened fast-sync with state_root verification, security audit (8.1/10 score).

### Phase 3 — Smart Contracts & DeFi ✅
zkVM (30+ opcodes), contract templates (Escrow, Multisig, AMM Pool, Governance), stablecoin module (ZST — gold-backed), P2P auto-update system.

### Phase 4 — Launch

```
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│  APRIL 2026          MAY — JULY 2026            Q3 2026          │
│                                                                  │
│  ┌──────────┐        ┌──────────────────┐       ┌────────────┐  │
│  │ PRIVATE  │───────>│   INCENTIVIZED   │──────>│  MAINNET   │  │
│  │ TESTNET  │        │  PUBLIC TESTNET  │       │  LAUNCH    │  │
│  └──────────┘        └──────────────────┘       └────────────┘  │
│                                                                  │
│  • 5 internal nodes   • Open to everyone        • Genesis block  │
│  • Stress testing     • Bug bounty program      • Fair launch    │
│  • Core validation    • Node operator rewards   • No premine     │
│  • ZK proof testing   • Security audit          • Full privacy   │
│                       • 2-3 months duration     • zkVM live      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

## Ecosystem

TSN is more than a blockchain — it's a full ecosystem of decentralized applications.

### Whispr — Decentralized Private Social Network (v0.4.0, Live)

A peer-to-peer social network with zero tracking, no email/phone required, and end-to-end encrypted messaging. Think Discord + Twitter + Medium, but decentralized and private.

- **Whisps** (short posts) + **Articles** (long-form blog) with upvote/downvote
- **Circles** — Community groups with rooms, roles, polls, auto-moderation
- **E2E Encrypted DMs** — ECDH P-256 + AES-256-GCM
- **BIP39 Identity** — 24-word seed phrase, no email, no phone
- **5 P2P Nodes** — Rust binary, libp2p gossipsub
- **App**: [whispr.tsnchain.com](https://whispr.tsnchain.com)
- **GitHub**: [github.com/trusts-stack-network/whispr](https://github.com/trusts-stack-network/whispr)
- **Releases**: [github.com/trusts-stack-network/whispr-releases](https://github.com/trusts-stack-network/whispr-releases) (Linux + Windows + macOS)

### ZST — Gold-Backed Stablecoin (In Development)

A stablecoin pegged to gold (1 ZST = 1g XAU), over-collateralized in TSN. Djed/Zephyr-inspired reserve model with stress fees, circuit breaker, and oracle price feeds.

- **3 assets**: TSN (collateral) → ZST (stablecoin) + ZRS (reserve share)
- **Reserve engine**: 76 tests passing, mint/burn with dynamic fees
- **Protections**: stress fees 0.3%-5%, circuit breaker at 120%, cooldown mechanism

### NetherSwap — Decentralized Exchange (In Development)

A cross-chain anonymous DEX built on TSN with AMM pools, escrow P2P, yield farming, governance DAO, and prediction markets.

- **AMM Swap** with smart router (multi-hop), limit orders
- **Liquidity Pools** with yield farming rewards
- **P2P Escrow** for trustless OTC trades
- **DAO Governance** — community-driven proposals and voting
- **Cross-chain** — relayers staked in TSN
- **Privacy** — anonymous trading via TSN shielded transactions

## Changelog

### v1.4.0 — Consensus Security Overhaul

Major consensus upgrade fixing 19 bugs in fork resolution, snapshot validation, and self-healing.

- **Heaviest chain rule**: Fork choice now ALWAYS uses cumulative_work (was height-based for short forks). Tiebreaker: difficulty then hash.
- **Persistent cumulative_work**: New sled tree stores cumulative_work per height. Survives LRU eviction and restarts.
- **PoW validation in trusted mode**: `add_block_trusted()` now verifies PoW and MIN_DIFFICULTY. Prevents importing invalid blocks during fast-sync.
- **Orphan PoW validation**: Orphan pool rejects blocks with invalid PoW or below MIN_DIFFICULTY before storing.
- **Graduated difficulty tolerance post fast-sync**: Within LWMA_WINDOW (45 blocks) of fast-sync base, accepts 25% margin. After that, enforces normal 10%.
- **Accurate rollback work**: Uses DB-stored cumulative_work instead of `difficulty * depth` estimation. Falls back to summing actual block difficulties.
- **Conservative snapshot work estimate**: When peer_cumulative_work is unavailable, uses MIN_DIFFICULTY * height (not difficulty * height).
- **Peer selection by work**: Fast-sync, stuck detection, and auto-resync now select peers by cumulative_work, not height alone.
- **Multi-peer agreement**: Auto-resync requires at least 2 peers agreeing (within 5% of max work) before triggering.
- **Peer work verification**: New `verify_peer_work_sample()` helper samples blocks to validate a peer's claimed work.
- **Faster trusted snapshots**: Snapshot interval in trusted mode reduced from 500 to 50 blocks for faster recovery.
- **MINIMUM_VERSION**: bumped to 1.4.0

### v1.3.7 — Self-Healing Nodes: Missing Snapshot Recovery

- **Missing snapshot recovery**: If state snapshot is lost but fast-sync placeholders exist, the node auto-wipes and re-syncs instead of crashing with `Missing block data at height 0`
- **MINIMUM_VERSION**: bumped to 1.3.7

### v1.3.6 — Windows Fix, Snapshot Sync at Height 0, Node Role Detection

- **Sync loop at height 0**: Nodes stuck at height 0 now use snapshot sync instead of block-by-block
- **Stuck detection at height 0**: Auto-resync watchdog now catches nodes stuck at height 0
- **Windows fix**: verification key checksum now normalizes line endings (CRLF → LF) before SHA256
- **nodes.html fix**: P2P peers fetched from correct API endpoint (shows miner badges correctly)
- **.gitattributes**: forces LF line endings for verification key files across platforms
- **MINIMUM_VERSION**: bumped to 1.3.6

### v1.3.0 — Chain Reset, Halving Fix & Sync Stability

- **Halving interval**: 210,000 → **4,200,000 blocks** (~16 months per halving, supply max in ~10 years)
- **Chain reset**: fresh genesis block with correct economics
- **Critical fix**: rollback `canonical_height` bug causing infinite sync loops
- **P2P Auto-Update**: nodes detect + download + verify + self-update
- **Explorer URL**: points to `explorer.tsnchain.com`
- **Default mode**: `./tsn` auto-creates wallet and mines (no subcommand needed)
- **Verification keys**: searched next to binary + parent dirs (build from source works)
- **Firewall**: port 9333 open on all nodes for HTTP sync

### v1.1.0 — Performance & Production Hardening

| Feature | Before | After |
|---------|--------|-------|
| Mining Hot Loop | Full header rebuilt per hash | MiningHashContext — zero heap alloc |
| Hashrate Display | Truncated hash, no KH/s | Real-time KH/s, full hash |
| Explorer Hashrate | Wrong formula | Corrected: `difficulty / block_time` |
| Wallet TX History | Not saved | Sent + received persisted (WalletTxRecord) |
| Received TX Detection | Manual | Automatic at wallet scan |
| Nullifier Check | At send only | At scan + send (prevents double-spend) |
| P2P Version Gate | Accept all peers | Reject peers below MINIMUM_VERSION |
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
- **Whispr**: [whispr.tsnchain.com](https://whispr.tsnchain.com)
- **Whitepaper**: [tsnchain.com/whitepaper.html](https://tsnchain.com/whitepaper.html)
- **Documentation**: [tsnchain.com/docs.html](https://tsnchain.com/docs.html)
- **Run a Node**: [tsnchain.com/run-node.html](https://tsnchain.com/run-node.html)
- **Blog**: [tsnchain.com/blog.html](https://tsnchain.com/blog.html)
- **X/Twitter**: [x.com/tsn_chain](https://x.com/tsn_chain)
- **Medium**: [medium.com/@trusts-stack-network](https://medium.com/@trusts-stack-network)
- **Discord**: [discord.gg/wxxNVDVn6N](https://discord.gg/wxxNVDVn6N)

## License

MIT — Open source.
