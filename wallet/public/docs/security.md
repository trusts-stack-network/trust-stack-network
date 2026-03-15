# 🔒 Guide Sécurité TSN

Guide complet des bonnes pratiques de sécurité pour Trust Stack Network.

## 🛡️ Sécurité Post-Quantique

### Pourquoi TSN est-il déjà sécurisé ?

TSN a été conçu **dès le départ** pour résister aux ordinateurs quantiques — contrairement aux autres blockchains qui devront migrer.

| Composant | Cryptographie classique vulnérable | TSN post-quantique |
|-----------|-----------------------------------|-------------------|
| **Signatures** | ECDSA (Bitcoin), EdDSA (Ethereum) | **ML-DSA-65 (FIPS 204)** |
| **Signatures backup** | RSA | **SLH-DSA (FIPS 205)** |
| **Hash functions** | SHA-256 (sécurisé) | **Poseidon2** (ZK-optimisé) |
| **ZK Proofs** | Groth16 (courbes elliptiques) | **Plonky3 STARKs** (hash-based) |
| **Chiffrement** | AES-GCM | **ChaCha20-Poly1305** |

### Vérification de l'intégrité crypto

TSN vérifie automatiquement l'intégrité des clés de vérification ZK :

```bash
# Les checksums sont vérifiés au démarrage
./target/release/tsn node
# ✓ Using committed verification keys (checksums verified)
```

**Checksums attendus** (circuits/keys/) :
- `spend_vkey.json`: `a1ff15d0968e066b6d8285993580f57065d67fb7ce5625ed7966fd13a8952e27`
- `output_vkey.json`: `c97a5eb20c85009a2abd2f85b1bece88c054e913a24423e1973e0629537ff038`

---

## 🔑 Sécurité des Wallets

### Génération sécurisée

```bash
# Génération d'un wallet avec entropie cryptographique forte
./target/release/tsn new-wallet --output my-secure-wallet.json

# IMPORTANT: Sauvegardez immédiatement le fichier JSON !
cp my-secure-wallet.json ~/backup/wallet-$(date +%Y%m%d).json.backup
```

### Protection du fichier wallet

```bash
# Permissions restrictives (lecture seule pour le propriétaire)
chmod 400 my-wallet.json

# Chiffrement du wallet (optionnel)
gpg --symmetric my-wallet.json
rm my-wallet.json  # Supprimer la version non chiffrée
```

### Viewing Keys — surveillance sans exposition

TSN support les **viewing keys** pour surveiller un wallet sans exposer les clés de dépense :

```bash
# Exporter la viewing key (lecture seule)
./target/release/tsn export-viewing-key --wallet my-wallet.json

# Créer un wallet watch-only avec la viewing key
./target/release/tsn import-viewing-key --viewing-key vk1abc... --output watch-only.json
```

**Cas d'usage** :
- Surveillance de solde sur un serveur non sécurisé
- Comptabilité d'entreprise
- Audit sans accès aux fonds

---

## 🏗️ Sécurité des Nodes

### Vérification complète des preuves ZK

Par défaut, TSN utilise **assume-valid** pour accélérer la sync. Pour une sécurité maximale :

```bash
# Vérifier TOUTES les preuves ZK depuis le bloc genesis
./target/release/tsn node --full-verify

# ⚠️  Plus lent mais garantie cryptographique complète
```

### Isolation réseau

```bash
# Node mineur isolé (pas d'API publique)
./target/release/tsn node --role miner --port 18333 --mine my-wallet.json

# Node relay public avec reverse proxy
./target/release/tsn node --role relay --port 8333 --public-url https://node.example.com
```

### Configuration firewall

```bash
# Ouvrir seulement le port P2P TSN
sudo ufw allow 8333/tcp    # Port principal TSN
sudo ufw allow 9333/tcp    # Port testnet TSN
sudo ufw deny 8333/tcp from any to any port 22  # Bloquer SSH via port TSN
```

### Surveillance et logs

```bash
# Logs de sécurité détaillés
RUST_LOG=tsn=debug ./target/release/tsn node

# Métriques en temps réel
curl http://localhost:8333/metrics | grep -E "(peers|height|mempool)"
```

---

## 🔍 Vérification et Audit

### Vérification de l'état de la blockchain

```bash
# Vérifier l'intégrité de la chaîne locale
./target/release/tsn verify-chain

# Comparer avec plusieurs peers
curl http://peer1.example.com:8333/chain/info
curl http://peer2.example.com:8333/chain/info
curl http://localhost:8333/chain/info
```

### Audit des nullifiers

Les nullifiers empêchent le double-spend. Vérification manuelle :

```bash
# Vérifier qu'un nullifier n'a pas été dépensé
curl -X POST http://localhost:8333/nullifiers/check \
  -H "Content-Type: application/json" \
  -d '{"nullifiers": ["null1abc...", "null2def..."]}'
```

### Validation de transaction avant broadcast

```bash
# Simuler une transaction sans la broadcaster
./target/release/tsn send --wallet my-wallet.json \
  --to tsnaddr1abc... --amount 10.5 --dry-run
```

---

## ⚡ Anti-Attaques Réseau

### Protection contre les attaques Eclipse

TSN inclut des protections automatiques :

| Protection | Description |
|------------|-------------|
| **Seed nodes diversifiés** | 4 seed nodes dans différents data centers |
| **Kademlia DHT** | Découverte de peers décentralisée |
| **Rotation des connexions** | Renouvellement automatique des peers |
| **Détection de fork** | Limite de réorganisation (100 blocs max) |

### Configuration anti-Sybil

```bash
# Limiter les connexions entrantes
./target/release/tsn node --max-inbound-peers 8

# Utiliser des peers de confiance uniquement
./target/release/tsn node --no-seeds \
  --peer peer1.mycompany.com:8333 \
  --peer peer2.mycompany.com:8333
```

### Rate limiting intégré

TSN limite automatiquement :
- **Requêtes API** : 100 req/min par IP
- **Transactions mempool** : 10 tx/min par peer
- **Téléchargements blocks** : 1 GB/hour par peer

---

## 🚨 Détection d'Intrusions

### Alertes automatiques

```bash
# Surveiller les tentatives de double-spend
tail -f ~/.tsn/logs/security.log | grep "DOUBLE_SPEND_ATTEMPT"

# Alertes sur les forks suspects
tail -f ~/.tsn/logs/chain.log | grep "REORG_DETECTED"
```

### Métriques de sécurité

```bash
# Vérifier la santé du réseau
curl http://localhost:8333/network/health

# Exemple de réponse
{
  "peers_connected": 12,
  "chain_height": 185434,
  "last_block_time": "2026-03-15T14:23:12Z",
  "mempool_size": 7,
  "sync_status": "synced",
  "reorg_alerts": 0
}
```

---

## 🛠️ Récupération d'Urgence

### Sauvegarde du wallet

```bash
# Script de sauvegarde automatique
#!/bin/bash
WALLET_FILE="my-wallet.json"
BACKUP_DIR="~/crypto-backups/tsn/"
DATE=$(date +%Y%m%d-%H%M)

mkdir -p "$BACKUP_DIR"
cp "$WALLET_FILE" "$BACKUP_DIR/wallet-$DATE.json"
gpg --symmetric "$BACKUP_DIR/wallet-$DATE.json"
rm "$BACKUP_DIR/wallet-$DATE.json"  # Garder seulement la version chiffrée

echo "Wallet sauvegardé : $BACKUP_DIR/wallet-$DATE.json.gpg"
```

### Récupération depuis un backup

```bash
# Déchiffrer et restaurer
gpg --decrypt wallet-20260315-1423.json.gpg > my-wallet.json
chmod 400 my-wallet.json

# Vérifier l'intégrité
./target/release/tsn balance --wallet my-wallet.json
```

### Recovery en cas de corruption de node

```bash
# Resync complète depuis des peers
rm -rf ~/.tsn/data/
./target/release/tsn node --fast-sync

# Alternative : resync lente mais plus sécurisée
./target/release/tsn node --full-verify
```

---

## ✅ Checklist Sécurité

### Avant le déploiement

- [ ] **Wallet backup** chiffré et testé
- [ ] **Permissions fichiers** restrictives (400)
- [ ] **Firewall** configuré (ports 8333/9333 seulement)
- [ ] **Monitoring** logs et métriques actif
- [ ] **Checksums** clés de vérification validés

### Maintenance régulière

- [ ] **Updates TSN** vers dernière version stable
- [ ] **Rotation backup** wallets (mensuelle)
- [ ] **Audit peers** connectés (vérifier réputation)
- [ ] **Surveillance reorg** (alertes > 5 blocs)
- [ ] **Test recovery** procedures (trimestriel)

### En cas d'incident

- [ ] **Isoler le node** (couper réseau)
- [ ] **Sauvegarder l'état** avant investigation
- [ ] **Analyser les logs** pour comprendre l'attaque
- [ ] **Resync depuis backup** vérifié
- [ ] **Signaler** l'incident à l'équipe TSN

---

## 🔗 Ressources complémentaires

- **Audit de code** : Le code TSN sera open-source à la mainnet
- **Bug bounty** : Programme de récompenses prévu pour le testnet public
- **Standards crypto** : [FIPS 204](https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/post-quantum-cryptography-standards) (ML-DSA), [FIPS 205](https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/post-quantum-cryptography-standards) (SLH-DSA)
- **Support sécurité** : security@tsnchain.com

---

*Guide de sécurité TSN v0.4.0 • Dernière mise à jour : Mars 2026*
*⚠️ La sécurité est une responsabilité partagée — suivez toujours les bonnes pratiques*