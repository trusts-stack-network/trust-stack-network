# Trust Stack Network v0.1 — Whitepaper Technique

> “Post-quantum, ZK-native, évolutif : la blockchain de la confiance distribuée”

---

## Table des matières
1. [Vue d’ensemble](#vue-densemble)  
2. [Architecture modulaire](#architecture-modulaire)  
3. [Couche cryptographique post-quantique](#couche-cryptographique-post-quantique)  
4. [Consensus Proof-of-Work adaptatif](#consensus-proof-of-work-adaptatif)  
5. [Réseau pair-à-pair](#réseau-pair-à-pair)  
6. [Couche d’exécution et MIK-VM](#couche-dexécution-et-mik-vm)  
7. [Protection de vie privée](#protection-de-vie-privée)  
8. [Évolutivité et sharding](#évolutivité-et-sharding)  
9. [Références](#références)  

---

## Vue d’ensemble

Trust Stack Network (TSN) est une blockchain de couche 1 post-quantique conçue pour offrir sécurité, confidentialité et scalabilité native.  
Elle combine :

- **SLH-DSA (FIPS 204)** : signature numérique résistante aux attaques quantiques.  
- **Halo2** : preuves ZK récursives sans setup de confiance.  
- **Poseidon2** : hash arithmétique optimisé pour les circuits ZK.  
- **MIK-VM** : machine virtuelle instruction-set zero-knowledge.  
- **PoW adaptatif** : consensus réglé en temps réel, ASIC-résistant.  

Objectifs :  
- Sécurité post-quantique dès le génèse.  
- Confidentialité opt-in par défaut.  
- Latence < 1 s, débit > 5 k tx/s sur shard unique.  

---

## Architecture modulaire

```mermaid
graph TD
    A[Application] --> B[RPC/REST]
    B --> C[MIK-VM]
    C --> D[Halo2 ZK]
    D --> E[Poseidon2 Hash]
    E --> F[SLH-DSA Sig]
    F --> G[Ledger Sled]
    G --> H[P2P Layer]
    H --> I[PoW Consensus]

Modules clés :  
| Module | Crate | Responsabilité | Spec |
|--------|-------|----------------|--------|
| `tsn_crypto` | `src/crypto` | Clés, signatures, commitments | TSN-0001 |
| `tsn_consensus` | `src/consensus` | PoW + difficulté | TSN-0002 |
| `tsn_network` | `src/network` | Découverte, mempool, sync | TSN-0003 |
| `tsn_vm` | `src/vm` | MIK-VM & circuits | TSN-0004 |
| `tsn_storage` | `src/storage` | Sled persistance | TSN-0005 |

---

## Couche cryptographique post-quantique

### 1. Signatures : SLH-DSA-65 (FIPS 204)

- `PublicKey = 32 B`, `SecretKey = 64 B`, `Sig = 2 459 B`.  
- Aucun état de session → parallélisation totale.  
- Randomiser le message avec ChaCha20Rng (évite les collisions multi-utilisateurs).  

### 2. Commits & Merkle

pub struct Commitment([u8; 32]); // Output Poseidon2

- Arbre de hauteur 32 → 4 G feuilles.  
- Feuille = `hash(addr ∥ amount ∥ blinding)`.  
- Root stocké dans `BlockHeader::commitment_root`.  

### 3. Nullifiers & Vie privée

Voir [TSN-0006](specs/TSN-0006-nullifier-privacy.md) pour le schéma dépense-anonyme.

---

## Consensus Proof-of-Work adaptatif

### Algorithme : SHA-3-512 (Keccak) sur header

struct BlockHeader {
    prev: Hash,
    height: u64,
    timestamp: u64,
    target: u32,
    commitment_root: Hash,
    sig: SLHSignature,
}

### Ajustement de difficulté (ADR-0003)

- Fenêtre glissante de 60 blocs.  
- Cible : 1 bloc / 5 s.  
- Formule :  
  next_target = prev_target * (ΔT_ideal / ΔT_real)

### Règles de validité

1. `timestamp > median(last 11) && < now + 2 h`.  
2. `hash(header) ≤ target`.  
3. Signature SLH-DSA valide sur hash.  

---

## Réseau pair-à-pair

sequenceDiagram
    participant N1 as Node-1
    participant N2 as Node-2
    N1->>N2: Ping(nonce, height)
    N2->>N1: Pong(nonce, height)
    N1->>N2: GetBlocks(from,height)
    N2->>N1: Blocks([Block])

- Transport : QUIC + Noise IK.  
- Découverte : Kademlia-like (Node-ID = hash(pubkey)).  
- Mempool : CRDT set, max 50 k tx.  
- Sync : Fast-Sync + Header-First + State-Sync (zk-proof).  

---

## Couche d’exécution et MIK-VM

### Instruction-set minimal

| Opcode | Description | Circuit |
|--------|-------------|---------|
| `TRANSFER` | envoi UTXO | Halo2 |
| `CALL` | appel contrat | Halo2 |
| `RET` | retourne valeur | Halo2 |

### Compilation vers circuit

1. ASM MIK → AST.  
2. AST → contraintes Halo2 (custom gates).  
3. Proof généré côté client, vérifié en 3 ms (Intel i7).  

### Gaz & fees

- Prix fixe par instruction (table TSN-0004).  
- Fees brûlées → rendre le token déflationnaire.  

---

## Protection de vie privée

1. **UTXO anonyme** : commitments cachés, nullifiers uniques.  
2. **View-key** : partage opt-in de clé de lecture.  
3. **Pool unifié** : toutes les tx passent par le même contrat shielded → évite les “anonymity set” fractionnés.  
4. **Rapport d’audit** : cf. [ADR-0007](specs/ADR-0007-privacy-tradeoffs.md).

---

## Évolutivité et sharding

### Phase 0 (actuelle)

- Shard unique : ~5 k tx/s.  
- State ~50 GB/an.  

### Phase 1 (v0.2)

- 64 shards, assignation par `account[0..6 bits]`.  
- Cross-shard : zk-rollup interne, confirmation 12 s.  
- Sécurité : histogramme de rand. beacon + VDF.  

### Phase 2 (v0.3)

- Data-availability sampling (DAS) via Reed-Solomon.  
- Recursive proofs : 1 proof = N shards.  

---

## Références

- FIPS 204 : *Sloth-Half-Domain Signature Standard*, NIST, 2024.  
- Bowe et al. : *Halo : Recursive Proof Composition*, 2019.  
- Grassi et al. : *Poseidon2 : A Faster Hash Function*, 2023.  
- TSN Improvement Proposals : [specs/](specs/)  
- Code source : [src/](src/)

---

> Statut : Final pour v0.1  
> Auteurs : Laila.H, Kai.V, J. Smith  
> Dernière mise à jour : 2024-06-XX