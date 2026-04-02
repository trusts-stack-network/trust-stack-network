# 💼 Guide Wallet TSN

Guide complet pour gérer vos wallets Trust Stack Network, sécuriser vos TSN et effectuer des transactions.

## 🎯 Types de wallets

### 🔹 CLI Wallet (Recommandé)

**Pour** : Utilisateurs techniques, sécurité maximale
**Sécurité** : Clés privées locales, signatures post-quantiques

```bash
# Créer un nouveau wallet
./target/release/tsn new-wallet --output my-wallet.json

# Wallet avec mot de passe
./target/release/tsn new-wallet --output secure-wallet.json --password
```

### 🌐 Web Wallet (En développement)

**Pour** : Débutants, usage quotidien
**Interface** : React/TypeScript dans `/wallet/`
**Status** : Alpha (Q2 2026)

---

## 🚀 Première utilisation

### 1. Créer votre premier wallet

```bash
# Wallet simple (pour tests)
./target/release/tsn new-wallet --output test-wallet.json

# Wallet sécurisé avec mot de passe
./target/release/tsn new-wallet --output main-wallet.json --password

# Vérifier la création
cat main-wallet.json
```

**Structure du wallet** :
```json
{
  "address": "tsn1abcd1234...",
  "private_key": "encrypted_with_chacha20poly1305",
  "public_key": "ml_dsa_65_public_key",
  "version": "0.4.0",
  "created": "2026-03-15T10:30:00Z"
}
```

### 2. Obtenir votre première adresse

```bash
# Afficher l'adresse publique
./target/release/tsn address --wallet main-wallet.json

# Avec QR code (si qr-code activé)
./target/release/tsn address --wallet main-wallet.json --qr
```

**Format adresse TSN** :
- Préfixe : `tsn1` (mainnet), `tst1` (testnet)
- Longueur : 62 caractères
- Encoding : Bech32m (post-quantique compatible)

### 3. Obtenir des TSN de test

```bash
# Faucet testnet (50 TSN gratuits)
./target/release/tsn faucet --wallet main-wallet.json

# Vérifier réception
./target/release/tsn balance --wallet main-wallet.json
```

---

## 💰 Gestion des fonds

### Vérifier le solde

```bash
# Solde simple
./target/release/tsn balance --wallet main-wallet.json

# Solde détaillé avec historique
./target/release/tsn balance --wallet main-wallet.json --verbose

# Via node spécifique
./target/release/tsn balance --wallet main-wallet.json --node http://node.tsnchain.com:8333
```

**Output détaillé** :
```
Wallet: tsn1abcd1234...
Balance: 250.5 TSN
Pending: 10.0 TSN (2 transactions)
Total: 260.5 TSN

Recent transactions:
  + 50.0 TSN - Block mining reward (block #1234)
  - 5.5 TSN  - Sent to tsn1efgh5678... (fee: 0.1 TSN)
  + 200.0 TSN - Mining rewards (blocks #1200-1233)
```

### Envoyer des TSN

```bash
# Transaction simple
./target/release/tsn send \
  --wallet my-wallet.json \
  --to tsn1recipient... \
  --amount 25.5

# Avec commentaire
./target/release/tsn send \
  --wallet my-wallet.json \
  --to tsn1recipient... \
  --amount 25.5 \
  --memo "Paiement facture #123"

# Transaction avec frais custom
./target/release/tsn send \
  --wallet my-wallet.json \
  --to tsn1recipient... \
  --amount 25.5 \
  --fee 0.05
```

**Frais de transaction** :
- Défaut : 0.1 TSN
- Minimum : 0.01 TSN
- Priority : 0.2 TSN (confirmation rapide)

### Historique des transactions

```bash
# 10 dernières transactions
./target/release/tsn history --wallet my-wallet.json

# Historique complet
./target/release/tsn history --wallet my-wallet.json --all

# Export CSV
./target/release/tsn history --wallet my-wallet.json --export history.csv
```

---

## 🔐 Sécurité avancée

### Protection par mot de passe

```bash
# Ajouter un mot de passe à un wallet existant
./target/release/tsn encrypt-wallet --wallet unprotected.json --output protected.json

# Changer le mot de passe
./target/release/tsn change-password --wallet protected.json
```

### Backup et restauration

```bash
# Backup sécurisé (seed phrase)
./target/release/tsn backup --wallet my-wallet.json --output backup-seed.txt

# Restaurer depuis seed
./target/release/tsn restore --seed backup-seed.txt --output restored-wallet.json

# Backup JSON complet
cp my-wallet.json /secure/location/wallet-backup-2026-03-15.json
```

**Seed phrase format** :
```
TSN_SEED_V1
abandon ability able about above absent absorb abstract absurd abuse access
accident accord account accurate achieve acid acoustic acquire across act action
24_words_total_bip39_compatible_but_ml_dsa_derivation
CHECKSUM: sha256_of_above_words
```

### Multi-signature (Roadmap Q3 2026)

```bash
# Créer wallet 2-of-3 multisig
./target/release/tsn new-multisig \
  --threshold 2 \
  --participants 3 \
  --output multisig-wallet.json

# Signer une transaction multisig
./target/release/tsn multisig-sign \
  --wallet my-partial-wallet.json \
  --transaction unsigned-tx.json
```

---

## 🌐 Interface Web Wallet

### Installation locale

```bash
# Démarrer le serveur wallet
cd /opt/tsn/wallet
npm install
npm run dev

# Interface accessible sur http://localhost:5173
```

### Fonctionnalités disponibles

**✅ Disponible (v0.4.0)** :
- Affichage du solde en temps réel
- Historique des transactions
- QR codes pour recevoir
- Connexion sécurisée via WebSocket

**🚧 En développement (Q2 2026)** :
- Envoi de transactions depuis l'interface
- Multi-wallet management
- Integration hardware wallet (Ledger)
- Wallet connect protocole

### Configuration

Fichier `wallet/src/config.ts` :
```typescript
export const WALLET_CONFIG = {
  // Node TSN à utiliser
  nodeUrl: 'http://localhost:8333',

  // WebSocket pour updates temps réel
  wsUrl: 'ws://localhost:8333/ws',

  // Thème interface
  theme: 'dark', // 'light' | 'dark' | 'auto'

  // Sécurité
  autoLockMinutes: 15,
  biometricAuth: true
}
```

---

## 📱 Intégrations mobiles

### Wallet mobile (Roadmap 2026)

**Plateformes** :
- iOS (Swift + TSN native SDK)
- Android (Kotlin + TSN JNI)

**Fonctionnalités prévues** :
- Scan QR codes TSN
- Notifications push pour transactions
- Backup cloud chiffré (iCloud/Google Drive)
- Support hardware security module (TEE)

### Export vers autres wallets

```bash
# Export vers format standard
./target/release/tsn export --wallet my-wallet.json --format json --output export.json

# Export clé publique uniquement
./target/release/tsn export --wallet my-wallet.json --public-only --output pubkey.json
```

---

## 🔗 Intégration développeur

### API wallet programmatique

```bash
# Démarrer wallet en mode daemon
./target/release/tsn wallet-daemon --wallet my-wallet.json --port 8334
```

**Endpoints disponibles** :
```bash
# Solde
curl http://localhost:8334/balance

# Nouvel adresse
curl -X POST http://localhost:8334/new-address

# Envoyer transaction
curl -X POST http://localhost:8334/send \
  -H "Content-Type: application/json" \
  -d '{"to": "tsn1...", "amount": "25.5", "memo": "test"}'
```

### SDK intégration

**Rust** :
```rust
use tsn_wallet::Wallet;

// Charger wallet
let wallet = Wallet::load("my-wallet.json")?;

// Balance
let balance = wallet.balance().await?;

// Envoyer
let tx = wallet.send("tsn1recipient...", 25.5).await?;
```

**TypeScript/JavaScript** :
```typescript
import { TSNWallet } from '@tsn/wallet-sdk'

const wallet = await TSNWallet.load('my-wallet.json')
const balance = await wallet.getBalance()
await wallet.send('tsn1recipient...', 25.5)
```

---

## 🛠️ Outils avancés

### Wallet analytics

```bash
# Analyse des patterns de transactions
./target/release/tsn analyze --wallet my-wallet.json --days 30

# Export pour Excel/Sheets
./target/release/tsn analyze --wallet my-wallet.json --export analytics.xlsx
```

### Optimisation performances

```bash
# Compacter l'historique (> 1000 tx)
./target/release/tsn compact --wallet my-wallet.json

# Sync rapide après longue absence
./target/release/tsn sync --wallet my-wallet.json --fast

# Vérification intégrité
./target/release/tsn verify --wallet my-wallet.json
```

### Wallet watch-only

```bash
# Créer wallet observation (sans clé privée)
./target/release/tsn watch-only --address tsn1abcd... --output watch.json

# Surveiller sans pouvoir dépenser
./target/release/tsn balance --wallet watch.json
```

---

## 🚨 Troubleshooting

### Problèmes courants

**Wallet corrompu** :
```bash
# Tenter réparation
./target/release/tsn repair --wallet corrupted.json --output repaired.json

# Restaurer depuis backup
./target/release/tsn restore --seed backup-seed.txt --output new-wallet.json
```

**Transactions bloquées** :
```bash
# Vérifier statut transaction
./target/release/tsn tx-status --hash 0xabc123...

# Remplacer transaction (fee plus élevé)
./target/release/tsn replace-tx --wallet my-wallet.json --hash 0xabc123... --fee 0.2
```

**Sync lente** :
```bash
# Changer de node
./target/release/tsn balance --wallet my-wallet.json --node http://fast-node.com:8333

# Mode offline (consultation uniquement)
./target/release/tsn balance --wallet my-wallet.json --offline
```

**Mot de passe oublié** :
```bash
# Si seed phrase disponible
./target/release/tsn restore --seed backup-seed.txt --output recovered.json

# Bruteforce (wallets test seulement)
./target/release/tsn bruteforce --wallet protected.json --wordlist common-passwords.txt
```

---

## 🏆 Bonnes pratiques

### Sécurité quotidienne

- ✅ **Toujours** utiliser un mot de passe fort
- ✅ **Backup** de la seed phrase hors ligne
- ✅ **Vérifier** les adresses de destination avant envoi
- ✅ **Tester** avec petites sommes en premier
- ❌ **Jamais** partager votre clé privée ou seed
- ❌ **Éviter** les wallets sur machines publiques

### Organisation multi-wallets

```bash
# Wallet principal (stockage long terme)
./target/release/tsn new-wallet --output hodl-wallet.json --password

# Wallet dépenses (usage quotidien)
./target/release/tsn new-wallet --output spending-wallet.json --password

# Wallet mining (récompenses automatiques)
./target/release/tsn new-wallet --output miner-wallet.json
```

### Planification fiscale

```bash
# Export transactions annuel
./target/release/tsn history --wallet my-wallet.json \
  --from 2026-01-01 --to 2026-12-31 \
  --export taxes-2026.csv

# Calcul plus/moins values
./target/release/tsn tax-report --wallet my-wallet.json --year 2026
```

---

**💎 Votre wallet TSN est votre passeport vers l'économie post-quantique. Protégez-le comme vos bijoux de famille !**

---

*Guide Wallet TSN v0.4.0 • Mis à jour Mars 2026*