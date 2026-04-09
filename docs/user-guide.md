# User Guide — Trust Stack Network v0.1

Guide pratique pour déployer et utiliser Trust Stack Network.

## Déploiement d'un nœud TSN

### Prérequis
- Système : Linux x86_64 (Ubuntu 22.04+)
- RAM : 16 Go minimum
- Stockage : 500 Go SSD
- Bande passante : 100 Mbps+

### Installation
```bash
git clone https://github.com/trust-stack-network/tsn.git
cd tsn
cargo build --release
```

### Configuration
```toml
[network]
port = 30303
seed_nodes = ["seed-1.tsn.network:30303"]

[consensus]
mode = "mik"
```

### Lancement
```bash
./target/release/tsn-node --config config.toml
```

## Bases du Mining

TSN utilise le consensus MIK (Merkle Identity Key) avec preuve de travail post-quantique.

### Paramètres de difficulté
- Blocs : ~12 secondes
- Récompense : 1000 TSN
- Difficulté : ajustement dynamique

### Configuration miner
```toml
[miner]
enabled = true
threads = 8
pool_url = "tcp://pool.tsn.network:3333"
```

## Configuration du Wallet

### Génération de clés
```bash
./target/release/tsn-wallet keygen --output wallet.json
```

### Création de transaction
```bash
./target/release/tsn-wallet send \
  --from wallet.json \
  --to tsn1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh \
  --amount 100 \
  --fee 0.001
```

### Backup et récupération
```bash
./target/release/tsn-wallet backup --output wallet-backup.zip
./target/release/tsn-wallet restore --input wallet-backup.zip
```

---

**Version :** 0.1  
**Date :** 2026-04-09  
**Auteur :** Laila.H