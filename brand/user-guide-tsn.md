# Guide Utilisateur Trust Stack Network (TSN)

> 🌐 *Post-quantum. Décentralisé. Construit par une équipe IA.*  
> Ce guide t’aide à déployer un nœud, miner, et interagir avec la première blockchain post-quantique prête pour la production.

---

## 🧱 1. Pourquoi TSN ? (En 30 secondes)

| Problème actuel | Solution TSN |
|----------------|--------------|
| Les clés ECDSA/Schnorr seront cassées par un ordinateur quantique (Shor, ~2030–2040) | 🔒 ML-DSA-65 (FIPS204) + Plonky2 STARKs post-quantiques |
| Les preuves ZK classiques (Groth16) dépendent de courbes vulnérables | 🛡️ Commitments & nullifiers calculés avec Poseidon2 — résistant aux attaques quantiques |
| Les blockchains « post-quantiques » sont souvent théoriques | 🚀 TSN est opérationnel, testé sur mainnet, avec preuve de sécurité réductible |

> 💡 *Oui, on sait que c’est rare : une blockchain post-quantique qui fonctionne — et qui est open source.*

---

## 🖥️ 2. Déployer un nœud complet (Rust)

### Prérequis
- Rust ≥ 1.78 (`rustup show`)
- 8 Go RAM minimum (16 Go recommandés pour le mining)
- 500 Go SSD (disque NVMe idéal)
- Linux/macOS (Windows via WSL2 supporté)

### Étapes

```bash
# 1. Cloner le repo
git clone https://github.com/trust-stack-network/tsn.git
cd tsn

# 2. Compiler (cargo check OK ✅)
cargo build --release

# 3. Générer la clé de nœud (ML-DSA-65)
./target/release/tsn keys generate-node --output ~/.tsn/node_key.pem

# 4. Démarrer le nœud (avec RPC activé)
./target/release/tsn node run \
  --network mainnet \
  --rpc-port 8545 \
  --p2p-port 9000 \
  --db-path ~/.tsn/db
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"tsn_syncStatus","params":[],"id":1}'
# Lancer le miner
./target/release/tsn-miner \
  --pool tsn.pool.truststack.network:3333 \
  --wallet YOUR_TSN_ADDRESS \
  --threads 8 \
  --algo poseidon2
./target/release/tsn wallet send \
  --to tsn1qzw... \
  --amount 100 \
  --from ~/.tsn/wallet.pem