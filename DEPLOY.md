# Deploying TSN

This guide covers deploying TSN (Trust Stack Network) nodes for you and your friends.

## Quick Start with Fly.io

### 1. Install Fly CLI

```bash
# macOS
brew install flyctl

# Linux
curl -L https://fly.io/install.sh | sh

# Login (create account if needed)
fly auth login
```

### 2. Deploy Your First Node

```bash
# Clone the repo (if you haven't)
git clone <your-repo-url>
cd tsn

# Create the app (first time only)
fly launch --no-deploy

# Create persistent storage for blockchain data
fly volumes create tsn_data --region sjc --size 1

# Deploy!
fly deploy
```

### 3. Your Node is Live!

After deployment, you'll get a URL like `https://tsn-node.fly.dev`

- **Explorer**: `https://tsn-node.fly.dev/explorer`
- **Wallet**: `https://tsn-node.fly.dev/wallet`
- **API**: `https://tsn-node.fly.dev/chain/info`

## Deploy Multiple Nodes

For redundancy, deploy nodes in different regions:

```bash
# Node 1 (San Jose)
fly launch --name tsn-node-1 --region sjc
fly volumes create tsn_data --region sjc --size 1 -a tsn-node-1
fly deploy -a tsn-node-1

# Node 2 (New York) - connects to Node 1
fly launch --name tsn-node-2 --region ewr
fly volumes create tsn_data --region ewr --size 1 -a tsn-node-2
fly secrets set TSN_SEEDS=https://tsn-node-1.fly.dev -a tsn-node-2
fly deploy -a tsn-node-2
```

## Enable Mining

To have your node mine blocks:

```bash
# Generate a wallet first
cargo run -- new-wallet -o my-wallet.json

# Set the mining address (use your wallet's address)
fly secrets set TSN_MINE_ADDRESS=<your-address> -a tsn-node-1
fly deploy -a tsn-node-1
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TSN_PORT` | Port to listen on | 8080 |
| `TSN_DATA_DIR` | Blockchain data directory | /app/data |
| `TSN_SEEDS` | Comma-separated seed node URLs | (none) |
| `TSN_MINE_ADDRESS` | Address to receive mining rewards | (disabled) |
| `RUST_LOG` | Log level (error/warn/info/debug) | info |

### Setting Secrets

```bash
fly secrets set TSN_MINE_ADDRESS=abc123... -a your-app-name
fly secrets set TSN_SEEDS=https://node1.fly.dev,https://node2.fly.dev -a your-app-name
```

## For Your Friends

### Option 1: Use Your Hosted Wallet (Easiest)

Just share the wallet URL:
```
https://your-node.fly.dev/wallet
```

They can:
1. Create a wallet (keys stored in their browser)
2. Send you their address
3. You send them some coins
4. They can send coins to others!

### Option 2: Run Their Own Node

They can run a node that syncs with your network:

```bash
# Clone and build
git clone <your-repo-url>
cd tsn
cargo build --release

# Run node (connects to your seed node)
./target/release/tsn node --peer https://your-node.fly.dev
```

Or with Docker:
```bash
docker run -p 8333:8080 \
  -e TSN_SEEDS=https://your-node.fly.dev \
  -v tsn_data:/app/data \
  your-docker-image
```

## Update Seed Nodes

Once you have your nodes deployed, update `src/config.rs`:

```rust
pub const SEED_NODES: &[&str] = &[
    "https://tsn-node-1.fly.dev",
    "https://tsn-node-2.fly.dev",
];
```

Then rebuild and redeploy so new nodes automatically find the network.

## Local Development

### Run Multiple Nodes Locally

```bash
# Terminal 1: First node with mining
cargo run -- node --port 8333 --data-dir ./data1 --mine <your-address>

# Terminal 2: Second node
cargo run -- node --port 8334 --data-dir ./data2 --peer http://localhost:8333
```

### Docker Compose

```bash
# Start 3 nodes locally
docker-compose up

# Access nodes:
# - Node 1: http://localhost:8333 (mining)
# - Node 2: http://localhost:8334
# - Node 3: http://localhost:8335
```

## Monitoring

Check node health:
```bash
curl https://your-node.fly.dev/chain/info
```

View logs:
```bash
fly logs -a your-app-name
```

## Costs

Fly.io free tier includes:
- 3 shared-cpu-1x VMs
- 3GB persistent storage
- Unlimited outbound bandwidth

This is enough for a small network with 2-3 nodes!

## Troubleshooting

### Nodes not syncing?
- Check both nodes use the same genesis (GENESIS_DIFFICULTY = 12)
- Verify TSN_SEEDS is set correctly
- Check logs: `fly logs -a your-app-name`

### Out of storage?
```bash
fly volumes extend tsn_data --size 5 -a your-app-name
```

### Restart a node?
```bash
fly apps restart your-app-name
```
