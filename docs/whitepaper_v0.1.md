# Trust Stack Network — Whitepaper Technique v0.1

**Révision** : 0.1.0  
**Date** : 2024-06-XX  
**Auteurs** : Laila.H, Kai.V, dev-crypto-tsn  
**Statut** : Draft  

## Table des matières
1. [Vue d’ensemble](#vue-densemble)  
2. [Architecture modulaire](#architecture-modulaire)  
3. [Couche cryptographique post-quantique](#couche-cryptographique-post-quantique)  
4. [Consensus Nakamoto avec preuves MIK](#consensus-nakamoto-avec-preuves-mik)  
5. [Réseau P2P & synchronisation](#réseau-p2p--synchronisation)  
6. [Protection de la vie privée](#protection-de-la-vie-privée)  
7. [Menaces post-quantiques & contre-mesures](#menaces-post-quantiques--contre-mesures)  
8. [Roadmap & versions futures](#roadmap--versions-futures)  
9. [Références](#références)

---

## Vue d’ensemble

Trust Stack Network (TSN) est une blockchain de couche 1 conçue pour survivre à l’ère post-quantique.  
Elle combine :

- **SLH-DSA (FIPS 204)** pour les signatures de blocs et de transactions.  
- **Halo2 + KZG (Plonky2)** pour les preuves ZK quantum-safe.  
- **Poseidon2** comme primitive de hachage arithmétique.  
- **MIK (Merkle Interval Keeps)** pour remplacer la preuve de travail par une preuve de stockage/d’intervalle.  
- **ChaCha20-Poly1305** pour le chiffrement des payloads réseau.

Objectifs : décentralisation, confidentialité optionnelle, faible latence (< 3 s), 1 000 tps sur 200 validateurs.

---

## Architecture modulaire

```mermaid
graph TD
    A[Application] -->|RPC| B[API Layer Axum]
    B --> C[Consensus MIK]
    B --> D[Mempool]
    C --> E[Block Builder]
    D --> E
    E --> F[Crypto Service]
    F -->|SLH-DSA| G[Keys]
    F -->|Plonky2| H[Proofs]
    F -->|Poseidon2| I[Hash]
    E --> J[Storage Sled]
    C --> K[P2P Sync]

Chaque module est librement remplaçable (cf. ADR-0003 « Boundaries & Crates »).

---

## Couche cryptographique post-quantique

### 1. Signatures
- **Algorithme** : SLH-SHA2-65s (paramètres « e »)  
- **Contexte** : `b"TSN-v0.1-PQ"` (domain-separation)  
- **Randomiser** : RFC 9381 § 4.2 (sig-rnd)  
- **Taille clef publique** : 32 B  
- **Taille signature** : 2 460 B

### 2. Primitives de hachage
| Primitive     | Usage                     | Sécurité (bits PQ) |
|---------------|---------------------------|--------------------|
| Poseidon2     | Commitments, Merkle, ZK | 128                |
| SHA-3-256     | Block headers             | 256                |
| BLAKE3        | Networking checksum       | 256                |

### 3. Preuves ZK
- **Halo2 + KZG** sur BLS12-381 (Plonky2 fork)  
- **Recursion** : 2 niveaux max (agrégation de 128 tx)  
- **Taille proof** : 192 kB (compressée)  
- **Temps génération** : 1.4 s (Apple M3)

---

## Consensus Nakamoto avec preuves MIK

### 1. Rappel MIK
MIK = Merkle Interval Keep  
Un « keep » est un tuple `(C, i, j)` où :
- `C` : racine Poseidon2 d’un arbre binaire de hauteur 30  
- `i, j` : intervalle `[i, j]` de 64 bits

Pour produire un bloc :
1. Le mineur prouve possession d’un keep valide sur `[H-Δ, H]`  
2. Il résout un mini-puzzle VDF (verif_delay = 2 s)  
3. Il émet le bloc avec preuve SLH-DSA

### 2. Difficulty adjustment
next_diff = prev_diff * (target_time / actual_time).sqrt()
Fenêtre : 120 blocs, cible : 3 s (ADR-0007)

### 3. Fork-choice
- Règle : « MIK-heaviest » = plus grand `Σ keep.weight`  
- Pas de slashing ; reorg max 30 blocs (cf. TSN-0002)

---

## Réseau P2P & synchronisation

### Transport
- QUIC v1 + TLS 1.3 (draft-34)  
- Identité éphémère : clef X25519 (post-quantique transition)  

### Messages principaux
| Type        | Payload max | Fréquence typ. |
|-------------|-------------|---------------|
| Ping        | 64 B        | 30 s          |
| BlockHeader | 1 kB        | 3 s           |
| BlockBody   | 1 MB        | 3 s           |
| TX          | 2 kB        | aléatoire     |

### Synchronisation rapide
- Snap-sync : télécharge 512 blocs parallèles + preuve MIK agrégée  
- Vérification : 300 ms/bloc (Ryzen 9)

---

## Protection de la vie privée

### 1. Notes & Commitments
- Note = `(pk, v, ρ, r)`  
- Commit : `Com = Poseidon2(pk∥v∥ρ∥r)`  
- Nullifier : `nf = Poseidon2(ρ∥sk)` empêche la double-depense

### 2. Pool anonyme
- Mélange de 16 notes par défaut (ring-size)  
- Pas de trusted-setup (Halo2)  
- Taille tx privée : 4.2 kB

### 3. Auditabilité réglementaire
- Vue en clair possible via clef de vue `vk` (diffie-hellman) – cf. TSN-0005

---

## Menaces post-quantiques & contre-mesures

| Menace                | Impact     | Contre-mesure TSN |
|-----------------------|------------|--------------------|
| Shor sur ECDSA        | Signature fausseées | SLH-DSA (EU-CMA) |
| Grover sur SHA-256    | 128 bits   | Poseidon2 (256 bits) |
| Attaque de migration  | Key-harvest | Flag `PQ_MIGRATE_TX` interdit les clefs ECDSA |
| Quantum-networking    | MITM       | Authenticité via SLH-DSA sur chaque handshake QUIC |

---

## Roadmap & versions futures

- **v0.2** : migration complète SLH-DSA-44 (plus petit)  
- **v0.3** : rollup ZK natif (Halo2 recursion 3 niveaux)  
- **v0.4** : support hardware wallets Ledger PQ  
- **v1.0** : mainnet stable, audit NCC + TrailOfBits

---

## Références

1. TSN-0001 – Poseidon2 Parameter Selection  
2. TSN-0002 – Fork-choice & Reorg Limits  
3. TSN-0003 – SLH-DSA Context & Randomiser  
4. ADR-0003 – Modular Crates Boundaries  
5. FIPS 204 (draft) – Stateless Hash-Based Digital Signature Standard  
6. Plonky2 – Polygon Labs (commit 3f5c1a9)  
7. RFC 9381 – SIG-RND for SLH-DSA  
