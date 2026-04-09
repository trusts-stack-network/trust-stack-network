# User Guide — Trust Stack Network v0.1

## Quick Start

### Deploy a TSN Node

```bash
# Clone repository
git clone https://github.com/trust-stack-network/tsn.git
cd tsn

# Build from source
cargo build --release

# Run node
./target/release/tsn-node --mainnet
```

### Mining Basics

TSN uses a proof-of-stake consensus with post-quantum security. To participate:

1. Generate a quantum-safe keypair: `tsn-cli keygen --pq`
2. Stake tokens: `tsn-cli stake --amount 1000`
3. Start validator: `tsn-cli validator --start`

### Wallet Setup

```bash
# Create new wallet
tsn-cli wallet create --name my-wallet

# Generate address
tsn-cli address generate

# Check balance
tsn-cli balance --address <your-address>
```

---

*For complete documentation, visit [docs.truststack.network](https://docs.truststack.network)*