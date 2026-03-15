# Trust Stack Network – Technical Whitepaper v0.1
> Post-Quantum Privacy-Preserving Blockchain  
> Laila.H – TSN Technical Writer  
> Status: Draft | Created: 2024-06-01 | Updated: 2024-06-01

---

## Table of Contents
1. [Abstract](#abstract)  
2. [Introduction](#introduction)  
3. [Cryptographic Stack](#cryptographic-stack)  
4. [Transaction Model](#transaction-model)  
5. [Consensus Layer](#consensus-layer)  
6. [Network Layer](#network-layer)  
7. [State & Storage](#state--storage)  
8. [Security Considerations](#security-considerations)  
9. [Performance Targets](#performance-targets)  
10. [References & TSN-XXXX Links](#references--tsn-xxxx-links)  

---

## Abstract
Trust Stack Network (TSN) est une blockchain de couche 1 post-quantique conçue pour la confidentialité native, la scalabilité modulaire et la résistance cryptographique à long terme.  
Elle combine des signatures post-quantiques (SLH-DSA), des preuves ZK-STARK (Halo2) et un hash interne résistant à la cryptanalyse quantique (Poseidon2) pour offrir des transferts confidentiels et un consensus décentralisé sans compromettre la sécurité future.

---

## Introduction
Les blockchains actuelles souffrent de deux limites majeures :
1. L’aléa post-quantique : les schémas à clé publique classiques (ECDSA, Ed25519, BN254) sont vulnérables aux algorithmes de Shor.
2. Le dilemme confidentialité/auditabilité : les mécanismes de confidentialité (zk-SNARKs) reposent souvent sur des paramètres d’installation (trusted setup) ou des courbes non post-quantiques.

TSN propose une architecture qui :
- remplace intégralement les signatures à clé publique par des constructions NIST-FIPS-204 (ML-DSA) et FIPS-205 (SLH-DSA) ;
- utilise des preuves ZK-STARK (Halo2) sans setup de confiance ;
- conserve une logique de state-transition vérifiable par des nœuds légers grâce à des commitments Merkle à hash quantique (Poseidon2).

---

## Cryptographic Stack

| Couche | Algorithme | Standard / Implémentation | Rationale |
|--------|------------|---------------------------|-----------|
| Signature block | SLH-DSA-SHA2-128s | FIPS-205 (NIST) | Post-quantique, 17 088 B par sig. |
| Signature transaction | ML-DSA-65 | FIPS-204 (NIST) | Compacité, 2 420 B par sig. |
| Preuve ZK | Halo2-KZG | Plonkish STARK | Pas de trusted setup, post-quantique friendly |
| Hash interne | Poseidon2 | Paper 2023 | Résistance quantique, arithmétisation efficace |
| Adresses | ts1… bech32m | TSN-0001 | HRP=ts1, checksum post-quantique |
| RNG | ChaCha20Rng | RFC 8439 | Deterministe, audité |

### Chaîne de confiance
```mermaid
graph TD
    A[Randomness Seed] -->|NIST DRBG| B[ChaCha20Rng]
    B --> C[SLH-DSA KeyGen<br/>FIPS-205]
    B --> D[ML-DSA KeyGen<br/>FIPS-204]
    C --> E[Block Producer<br/>Certificate]
    D --> F[User UTXO Key]
    G[Poseidon2 Hash] -->|commit| H[Merkle Tree]
    H --> I[Roothash in Header]

---

## Transaction Model

### UTXO vs Account
TSN adopte le modèle **MIK (Merkleized Invoice Key-set)** : une UTXO enrichie d’un masque `r` et d’un `nullifier_key` dérivé en zero-knowledge.  
Avantage : pas de adresse réutilisable en clair, pas de lien sortie-consommateur sans clé secrète.

### Cycle de vie
sequenceDiagram
    participant U as Wallet
    participant N as Network
    participant M as Mempool
    participant B as Block Producer
    U->>U: GenNote(amt, r)
    U->>U: ComputeCommit()
    U->>N: PushTx(tx, π halo2)
    N->>M: validateπ, checkNullifier
    M->>B: Propose
    B->>B: UpdateState(commit, nullifier)

### Champs clés d’une Note (chiffrée ChaCha20Poly1305)
| Champ | Taille | Description |
|-------|--------|-------------|
| `amount` | 8 B | en µTSN |
| `r` | 32 B | random mask |
| `pk_dest` | 32 B | ML-DSA public key |
| `rho` | 32 B | nullifier seed |
| `memo` | 512 B | payload arbitraire |

---

## Consensus Layer

### PoQW – Proof of Quantum Work
- **Fonction :** `PoQW(B_header) = H_poseidon2(B_header || nonce)` avec `H_output < target`
- **Vérification :** nœuds légers vérifient le STARK généré par le mineur prouvant le bon calcul du hash sans révéler `nonce`.
- **STARK circuit :** 12 000 constraints, preuve ≈ 80 kB, vérification ≈ 6 ms (x86).

### Difficulty ajustement
- Fenêtre : 600 blocs
- Algo : `new_diff = old_diff * (600 * T_target) / (T_observed)` avec limite 4×/÷4 par fenêtre.

### Rewards & fees
- Subsidence 5 % par an
- 80 % reward au miner, 20 % au DAO Treasury (adresse `ts1treasury…` verrouillée script)

---

## Network Layer

### Stack
| Couche | Protocole |
|--------|-----------|
| Application | JSON-RPC 2.0 (Axum) |
| Transport | QUIC (Tokio-quic) + Noise IK |
| Découverte | Kademlia-Xor (S/Kademlia adapté) |
| Sync & Mempool | GossipSub (libp2p) |

### Messages P2P (extraits TSN-0003)
| ID | Payload | Validation |
|----|---------|--------------|
| `0x10` | NewBlock | Vérif PoQW STARK + root commit |
| `0x20` | Tx | Vérif proof Halo2 + nullifier unique |
| `0x30` | GetHeaders | Réponse sérialisée avec preuve de possession SLH-DSA |

### API RPC (port 9944/tcp)
GET /v1/block/{height} → BlockView
POST /v1/tx → BroadcastResponse
GET /v1/state/nullifier/{nf} → bool
GET /v1/params → ConsensusParams

---

## State & Storage

### Arbre Merkle (Poseidon2, arity 16)
- **depth :** 32 → 2²⁶ feuilles max
- **leaf :** commitment 32 B d’une Note
- **root stocké :** dans `block.header.commit_root`

### Base de données
- Sled (KV) : colonnes `blocks`, `txs`, `notes`, `nullifiers`, `headers`
- Compacité automatique toutes les 24 h ou >10 GB de delta

### Snapshots
- Chaque 10 000 blocs
- Format : zstd + bincoded `StateSnapshot { merkle_root, utxo_checksum, treasury_balance }`
- Vérification : `SnapshotProof` Halo2 (TSN-0005)

---

## Security Considerations

### Surface d’attaque post-quantique
- Signature : SLH-DSA & ML-DSA – sécurité ≥ NIST-5 (256 bits post-quantique)
- Hash : Poseidon2 – structure sponge, non algebraic friendly pour Grover
- Forward secrecy : clés unshot par transaction (dérive BIP-44 post-quantique)

### Contremesures DoS
- Taille maximale d’un bloc : 2 MB
- Taille maximale d’une preuve Halo2 : 150 kB
- Frélim : 2 000 tx/s par pair avant dégagement mempool

### Audit & formalisation
- Spécifications écrites en Lean4 (répertoire `formal/`)
- Preuves de sécurité : ROM+ QROM pour SLH-DSA, AGM pour Halo