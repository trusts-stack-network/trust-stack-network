# PLAN — TSN Multi-Role Nodes Implementation

**Created:** 2026-03-09
**Status:** IN PROGRESS
**Last updated:** 2026-03-09 (session 2)

---

## Phases & Checklist

### Phase 0: Visualization & Documentation (NOW — Opus)
- [x] Create simulation graph page `/var/www/tsn/network-simulation.html` with 100 fake nodes (4 types, colors, interactions)
- [x] Deploy simulation to https://tsnchain.com/network-simulation.html
- [x] Update nodes.html to link to simulation (nav button + hero CTA)
- [x] Update whitepaper: section "9. Node Roles & Incentives" (reward model, node types table, prover marketplace, relay incentives)
- [x] Update docs: "Run a Relay / Miner / Prover / Light Client" (Node Roles section with CLI examples)
- [x] Update roadmap items for multi-role nodes (Phase 11 added in app.py, deployed)
- [x] Save this plan to /opt/tsn/AGENT_MAJ_TSN_TYPENODE.md

### Phase 1: NodeRole Enum + CLI Config (Sonnet — when credits return)
- [ ] Create `src/node/mod.rs` — `enum NodeRole { Relay, Miner, MinerProver, Prover }`
- [ ] Create `src/node/capabilities.rs` — bitflags for node features
- [ ] Modify `src/config/mod.rs` — add `--role` CLI flag
- [ ] Modify `src/main.rs` — route startup based on role
- [ ] P2P announce role in handshake message
- [ ] Tests: role switching, config validation

### Phase 2: Wallet (Sonnet)
- [ ] Create `src/wallet/mod.rs` — basic shielded wallet
- [ ] Create `src/wallet/shielded.rs` — create/spend notes
- [ ] Create `src/wallet/balance.rs` — scan blockchain for owned notes
- [ ] Transaction builder: inputs (nullifiers) + outputs (commitments)
- [ ] Integration with existing ZK proofs (Halo2/Circom)
- [ ] CLI: `tsn wallet send --to <addr> --amount <n>`
- [ ] Tests: send/receive, double-spend prevention

### Phase 3: Relay Rewards (Sonnet)
- [ ] Modify coinbase distribution: 85% miner, 8% relay pool, 2% prover reserve, 5% dev
- [ ] Implement RelayReceipt: signed proof of block propagation
- [ ] Relay scoring: blocks propagated first, uptime measurement
- [ ] Relay pool distribution logic per epoch (every N blocks)
- [ ] Modify `src/core/blockchain.rs` — multi-output coinbase
- [ ] Tests: reward calculation, relay scoring

### Phase 4: Light Client (Sonnet)
- [ ] Create `tsn-lightclient` crate (separate from main binary)
- [ ] SPV header-only sync
- [ ] RPC client to query relay nodes
- [ ] WASM compilation target for browser
- [ ] Verify block headers + Merkle proofs of inclusion
- [ ] Tests: header verification, SPV proofs

### Phase 5: Prover Service (Sonnet)
- [ ] Create `src/prover/mod.rs` — trait ProverService
- [ ] Local prover (in-wallet, for desktop clients)
- [ ] Remote prover protocol: ProofJob, ProofQuote, ProofResult messages
- [ ] Prover marketplace RPC endpoint: `/prover/market`
- [ ] Payment: proving fee in transaction, 5% dev fee on proving fees
- [ ] Miner+Prover mode: mine AND prove in same process
- [ ] Tests: proof generation, payment flow

### Phase 6: Plonky3 Migration & Halo2 Removal (Sonnet)
- [ ] Replace plonky2 crate with plonky3 in Cargo.toml
- [ ] Migrate ZK circuits (SpendWitness, OutputWitness, TransactionProver)
- [ ] Remove Halo2 entirely (halo2_prover.rs, halo2_proofs.rs, Groth16/BN254)
- [ ] Migrate V1 ShieldedTransaction to Plonky3 (single proof system)
- [ ] Regenerate verification keys (spend_vkey, output_vkey)
- [ ] Update faucet proofs to Plonky3
- [ ] V1→V2 transition period (support both during upgrade)
- [ ] Browser WASM prover with Plonky3

### Phase 7: zkVM & Smart Contracts (Sonnet)
- [ ] zkVM design: instruction set, execution model, gas metering
- [ ] zkVM core: src/zkvm/mod.rs — execute programs inside ZK proofs
- [ ] Contract deployment protocol (bytecode on-chain, contract addresses)
- [ ] Contract execution & state (read/write contract storage)
- [ ] Multi-asset UTXO support (asset_id in outputs)
- [ ] TSN-20 token standard (mint, transfer, burn)
- [ ] ETH Bridge (verify Ethereum headers, mint wrapped assets)

### Phase 8: Gold-Backed Stablecoin ZST (Sonnet)
- [ ] Oracle protocol design (decentralized XAU/USD price feed)
- [ ] Oracle node implementation (signed prices, median aggregation)
- [ ] ZST mint/burn contract (1 ZST = 1g gold, 150% collateral)
- [ ] ZST stability mechanism (collateral monitoring, auto-liquidation)
- [ ] Shielded conversions (ZK proof of valid conversion)

### Phase 9: Testnet & Mainnet Launch
- [x] Private Testnet — April 2026 (5 nodes, internal testing)
- [ ] Smart contracts deployed on testnet
- [ ] Incentivized Testnet — May-July 2026 (public, bug bounties)
- [ ] Security audit (crypto, consensus, zkVM, stablecoin)
- [ ] Mainnet launch — Q3 2026 (genesis, fair launch, no premine)

---

## Reward Model

```
Block Reward = 50 TSN (halving every 210K blocks)

Per-block distribution:
├── 5%  Dev Fee        = 2.50 TSN  [ALREADY IMPLEMENTED]
├── 85% Miner          = 42.50 TSN [block producer]
├── 8%  Relay Pool     = 4.00 TSN  [shared among active relays]
└── 2%  Prover Reserve = 1.00 TSN  [accumulated for future prover market]

Transaction fees:
├── 70% → Miner (block producer)
├── 20% → Relay (propagated the tx)
├── 5%  → Dev fee
└── 5%  → Prover (if external proof was used)

Proving fees (user pays prover directly):
├── 95% → Prover
└── 5%  → Dev fee
```

## Node Types & Graph Colors

| Type | Color | Icon | Description |
|------|-------|------|-------------|
| Miner | #00ffcc (green) | Hexagon rotating | Produces blocks, earns block reward |
| Relay/Seed | #7b61ff (purple) | Diamond | Stores chain, relays blocks/tx, earns relay pool share |
| Prover | #ffd700 (gold) | Triangle | Generates ZK proofs on demand, earns proving fees |
| Light Client | #ff6b9d (pink) | Small circle | Wallet-only, verifies via proofs, pays fees |
| Miner+Prover | #00ffcc→#ffd700 gradient | Hexagon+triangle | Both roles, earns both rewards |

## Files to Create/Modify

### New files:
- `src/node/mod.rs` — NodeRole enum, capabilities
- `src/node/capabilities.rs` — bitflags
- `src/node/rewards.rs` — reward distribution logic
- `src/prover/mod.rs` — ProverService trait
- `src/prover/local.rs` — local prover
- `src/prover/remote.rs` — remote prover client
- `src/wallet/mod.rs` — wallet core
- `src/wallet/shielded.rs` — shielded tx builder
- `src/wallet/wasm.rs` — WASM bindings

### Modified files:
- `src/config/mod.rs` — NodeRole config, reward percentages
- `src/main.rs` — role-based startup
- `src/core/transaction.rs` — relay_fee, prover_fee fields
- `src/core/blockchain.rs` — multi-role reward distribution
- `src/network/api.rs` — prover market endpoints
- `src/network/messages.rs` — ProofJob, ProofResult, RelayReceipt
- `src/network/discovery.rs` — announce role + capabilities
