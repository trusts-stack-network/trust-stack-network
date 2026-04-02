# Trust Stack Network — Whitepaper Technique v0.1

> « Une blockchain post-quantique n’est pas une option : c’est la seule manière de garantir que les actifs numériques créés aujourd’hui subsisteront encore demain. »  
> — Kai.V, ARCHITECT

---

## Table des matières
1. [Résumé](#résumé)  
2. [Contexte & menaces post-quantiques](#contexte--menaces-post-quantiques)  
3. [Architecture modulaire](#architecture-modulaire)  
4. [Couche cryptographique](#couche-cryptographique)  
   4.1 [Signatures : SLH-DSA (FIPS 205)](#signatures--slh-dsa-fips-205)  
   4.2 [Preuves ZK : Halo2 + Plonky2](#preuves-zk--halo2--plonky2)  
   4.3 [Hash & arbres de Merkle : Poseidon2](#hash--arbres-de-merkle--poseidon2)  
   4.4 [MIK : Modular Identity Kit](#mik--modular-identity-kit)  
5. [Consensus : Proof-of-Work post-quantique](#consensus--proof-of-work-post-quantique)  
6. [Réseau P2P](#réseau-p2p)  
7. [Protection des données à long terme](#protection-des-données-à-long-terme)  
8. [Compatibilité ascendante & migration](#compatibilité-ascendante--migration)  
9. [Références](#références)

---

## Résumé
Trust Stack Network (TSN) est une blockchain de couche 1 conçue pour survivre à l’ère post-quantique.  
Elle combine :
- des signatures **SLH-DSA** (FIPS 205) à la place des ECDSA/Ed25519,
- des preuves ZK **Halo2** et **Plonky2** (STARKs) pour la confidentialité et l’évolutivité,
- un hash **Poseidon2** (arithmétique sur `GF(p)`) pour les circuits ZK,
- un **MIK** (Modular Identity Kit) offrant des adresses à usage unique, des notes chiffrées et des nullifiers,
- un **Proof-of-Work** interne à difficulté ajustée, résistant aux accélérations quantiques (Grover),
- un réseau **libp2p** Rust/Tokio avec découverte Kademlia-DHT et sync réacteur.

Le tout est documenté sous forme de **TSN-XXXX** (specs numérotées) et d’**ADR** (Architecture Decision Records) versionnés avec le code.

---

## Contexte & menaces post-quantiques
| Algorithme classique | Attaque quantique | Impact sur TSN | Contre-mesure |
|----------------------|-------------------|----------------|---------------|
| ECDSA/secp256k1 | Shor → clé privée en O(n³) | Vol d’actifs | SLH-DSA-65 |
| Ed25519 | Shor | idem | idem |
| Groth16 BN254 | Shor sur pairing | Fausse preuve | Halo2/Plonky2 |
| SHA-256 | Grover → 2¹²⁸ → 2⁶⁴ | Collision | Poseidon2 + output 512b |

> Voir **TSN-0001** : « Choix des primitives post-quantiques ».

---

## Architecture modulaire

```mermaid
graph TD
    A[Application] -->|RPC/HTTP| B[API Server]
    B --> C[Mempool]
    C --> D[Consensus PoW]
    D -->|Block finalisé| E[State Layer]
    E -->|Merkle root| F[Storage sled]
    G[Cryptographic Services] -->|keys| H[Wallet]
    G -->|proofs| I[Halo2/Plonky2]
    G -->|hash| J[Poseidon2]
    K[P2P] -->|gossip| C
    K -->|sync| D

Chaque module est une crate Rust indépendante ; ses interfaces publiques sont spécifiées dans des **TSN-XXXX** dédiés.

---

## Couche cryptographique

### Signatures : SLH-DSA (FIPS 205)
- Paramètre : `SLH-DSA-SHA2-65` (n=32, k=32, h=66, d=22)
- Clés : 32 B publique / 64 B secrète
- Signature : 4 952 B
- Avantage : seule primitive NIST à garantie *stateless* et *post-quantique* en 2024

> Voir **TSN-0002** : « Intégration SLH-DSA dans Rust »  
> Voir **ADR-0003** : « Rejet de XMSS (stateful) »

### Preuves ZK : Halo2 + Plonky2
| | Halo2 | Plonky2 |
|---|-------|---------|
| Type | SNARK | STARK |
| Curves | BN254 | FRI sur Goldilocks |
| PQ-safe | Non (pairing) | Oui |
| Recursion | Oui | Oui |
| Taille preuve | ~1 kB | ~45 kB |
| Choix TSN | Circuits legacy | Circuits nouveaux |

Les deux systèmes coexistent ; un flag `version=0x02` dans le header indique le type de preuve.

> Voir **TSN-0003** : « ZK-VM arithmétique Poseidon2 »

### Hash & arbres de Merkle : Poseidon2
- Paramètres : `t=3, RF=8, RP=56` sur `GF(0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f624)`
- Avantage : ~50 contraintes par compression vs 20 000 pour SHA-256 dans circuits ZK
- Racine stockée dans `block.header.commitment_root` (32 B)

> Voir **TSN-0004** : « Poseidon2 Parameters Registry »

### MIK : Modular Identity Kit
Un compte TSN ne contient **pas** d’UTXO ni de solde en clair.  
Il contient :
- `vk` : clé de vérification SLH-DSA (32 B)
- `cm` : commitment Poseidon2(vk, ρ) où ρ est une graine aléatoire
- `addr` : `Bech32("tsn", cm)` (adresse réutilisable)

Lors d’un paiement :
1. L’émetteur génère une note `n = (addr, v, r)` avec `r` aléatoire
2. Il produit une preuve ZK que `v ≥ 0` et qu’il possède des notes non dépensées
3. Il publie un nullifier `nf = Poseidon2(n)` pour éviter la double-dépense

> Voir **TSN-0005** : « MIK Note & Nullifier Scheme »

---

## Consensus : Proof-of-Work post-quantique
- Algorithme : `Poseidon2(header ∥ nonce)` sur GoldilocksField (v0.4.0+)
- Cible : difficulté ajustée tous les 72 blocs (fenêtre glissante + PID)
- Résistance Grover : difficulté multipliée par √2 vs SHA-256 classique
- Récompense : 50 TSN → halving tous les 210 000 blocs (~24 jours à 10s/bloc)
- Schedule : 50 → 25 → 12.5 → 6.25 → ... TSN/bloc (émission Bitcoin-like)
- Supply max : 21 000 000 TSN
- Dev fee : 5% par bloc (95% mineur, 5% trésorerie, pas de premine)

### Choix de fork : Heaviest Chain (v0.4.1)
- **Cumulative Work** : la chaîne avec le plus de travail cumulé (somme des difficultés) l’emporte, pas la plus longue. Même approche que Bitcoin Core et Quantus Network.
- **MAX_REORG_DEPTH = 100** : toute réorganisation > 100 blocs est rejetée (inspiré Dilithion).
- **Checkpoint Finality** : point de contrôle tous les 100 blocs, pas de reorg au-delà.
- **Genesis Hash Verification** : hash du bloc genesis vérifié au démarrage.
- **Dual Merkle Tree Snapshots** : sauvegarde V1 (BN254) + V2 (Goldilocks), détection automatique des snapshots incompatibles.

sequenceDiagram
    participant M as Mineur
    participant N as Nœud
    participant C as Chaîne
    M->>N: propose block
    N->>N: vérifie PoW & txs
    N->>C: ajoute si meilleur (heaviest chain)
    C-->>M: diffusion réseau

> Voir **TSN-0006** : « PoW Quantum-Resistant »
> Voir **ADR-0007** : « Rejet d’AlephBFT (complexité) »

---

## Réseau P2P
- Transport : TCP + Noise IK (ChaCha20Poly1305)
- Découverte : Kademlia-DHT (`SHA-256(node_id)`)
- Messages principaux :
  - `TxAnnounce` (mempool)
  - `BlockHeader` (sync)
  - `GetNotesByNullifier` (MIK)
- Limite : 1 000 connexions sortantes, 200 entrantes
- Penalty : score −20 si message malformé, bannissement <−100

> Voir **TSN-0007** : « P2P Wire Protocol v1 »

---

## Protection des données à long terme
| Horizon | Menace | Mesure |
|---------|--------|--------|
| 0-5 ans | Side-channel sur SLH-DSA | Constant-time impl (fiat-crypto) |
| 5-15 ans | Grover accéléré | Augmentation difficulté PoW, migration éventuelle vers SPHINCS+-α |
| 15-30 ans | Failles dans Poseidon2 | Backup avec Keccak-512 (flag `hash_version=0x01`) |
| >30 ans | Ordinateurs quantiques à 10 000 qubits | Rotation de clé via MIK, soft-fork |

> Voir **TSN-0008** : « Crypto-Agility Policy »

---

## Compatibilité ascendante & migration
- Version de la chain : `u16` dans `block.header.version`
- Règle : « Validité stricte » — un nœud > vX rejette les blocs < vX
- Migration state : snapshot sled à la hauteur `H` + preuve Merkle (format borsh)
- Rollback : impossible sans hard-fork (garantie liveness)

> Voir **TSN-0009** : « Network Upgrade Process »

---

## Références
| TSN-XXXX | Titre |
|----------|-------|
| TSN-0001 | Choix des primitives post-quantiques |
| TSN-0002 | Intégration SLH-DSA dans Rust |
| TSN-0003 | ZK-VM arithmétique Poseidon2 |
| TSN-0004 | Poseidon2 Parameters Registry |
| TSN-0005 | MIK Note & Nullifier Scheme |
| TSN-0006 | PoW Quantum-Resistant |
| TSN-0007 | P2P Wire Protocol v1 |
| TSN-0008 | Crypto-Agility Policy |
| TSN-0009 | Network Upgrade Process |

> Toutes les specs sont dans `specs/` et versionnées avec le code source.

---

**Statut** : Final  
**Auteurs** : Laila.H, Kai.V  
**Créé** : 2024-06-01  
**Mis à jour** : 2024-06-01