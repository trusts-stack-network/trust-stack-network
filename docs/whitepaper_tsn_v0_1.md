# Trust Stack Network — Whitepaper Technique v0.1  
*Post-Quantum Privacy-Preserving Blockchain*

---

## Table des matières
1. [Résumé](#résumé)  
2. [Vue d’ensemble](#vue-densemble)  
3. [Architecture modulaire](#architecture-modulaire)  
4. [Couche cryptographique](#couche-cryptographique)  
5. [Consensus](#consensus)  
6. [Réseau P2P](#réseau-p2p)  
7. [Couche d’exécution](#couche-dexécution)  
8. [Économie des frais](#économie-des-frais)  
9. [Menaces & contre-mesures](#menaces--contre-mesures)  
10. [Feuille de route](#feuille-de-route)  
11. [Références internes](#références-internes)

---

## Résumé
Trust Stack Network (TSN) est une blockchain de couche 1 résistante aux attaques post-quantiques, conçue pour préserver la vie privée des utilisateurs tout en restant vérifiable par des nœuds complets.  
Elle combine :
- Des signatures et adresses post-quantiques (SLH-DSA, FIPS-204),
- Des preuves ZK « quantique-sûres » (Halo2 + Plonky2),
- Un hash interne Poseidon2 (arithmétique sur `GF(p)` BN254),
- Un consensus PoW à fenêtres MIK (Merkle Interval Knowledge),
- Un protocole P2P Tokio/QUIC avec discovery libp2p.

---

## Vue d’ensemble

```mermaid
graph TD
    subgraph "Couche applicative"
        Wallet("Wallet TS/Wallet Rust")-->|RPC|API("Axum HTTP API")
        Explorer("Block Explorer")-->|gRPC|API
    end
    subgraph "Couche consensus"
        API-->|BlockCandidate|Pow("PoW MIK")
        Pow-->|ValidBlock|BC("Blockchain")
    end
    subgraph "Couche crypto"
        BC-->|State|NullifierSet("Nullifier Set")
        BC-->|Notes|NoteCommitTree("Note Commitment Tree")
        NullifierSet-->|Poseidon2|HashOps("Poseidon2 Ops")
        NoteCommitTree-->|Merkle|MTree("Sparse Merkle Tree")
    end
    subgraph "Réseau"
        Sync("Sync Engine")<-->|blocks+txs|P2P("P2P QUIC")
        Mempool("Mempool")-->|pending|P2P
    end

---

## Architecture modulaire

| Module | Répertoire | Responsabilité | Spec associée |
|--------|------------|----------------|---------------|
| `core` | `src/core/` | Blocs, transactions, état UTXO-ZK | [TSN-0001](specs/tsn-0001.md) |
| `crypto` | `src/crypto/` | Clés, sig, hash, preuves | [TSN-0002](specs/tsn-0002.md) |
| `consensus` | `src/consensus/` | PoW MIK, difficulté | [TSN-0003](specs/tsn-0003.md) |
| `network` | `src/network/` | P2P, mempool, sync | [TSN-0004](specs/tsn-0004.md) |
| `storage` | `src/storage/` | Persistence sled | [TSN-0005](specs/tsn-0005.md) |
| `wallet` | `src/wallet/` | Génération TX, note scanning | [TSN-0006](specs/tsn-0006.md) |

---

## Couche cryptographique

### 1. Clés et adresses
- **Clé privée** → 32 octets d’entropie ChaCha20RNG  
- **Clé publique** → `pk := SLH-DSA.PublicKey` (FIPS-204, 64 B)  
- **Address** → `PKEnc(pk) || pk_hash` où `pk_hash = Poseidon2(pk)[..20]`  
  → Empêche l’énumération de clés sur un ordinateur quantique (ADR-0003).

### 2. Signatures
- Tx spend authentification : SLH-DSA-65 (niveau 3 post-quantique).  
- Consensus : même schéma pour éviter deux implémentations critiques.

### 3. Commitments & Nullifiers
note = (v: u64, ρ: F, r: F)
cm   = Poseidon2(v, ρ, r)
nf   = Poseidon2(pk, ρ)
- `cm` stocké dans l’arbre de hauteur 32 (≈ 4 G feuilles max).  
- `nf` inséré dans un ensemble éphemère « Nullifier Set » (sled `HashSet`).  
  → Double-spend détecté via existence du nullifier.

### 4. Preuves ZK
| Protocole | Usage | Taille preuve | Vérification | Quantum-safe |
|-----------|-------|---------------|------------|--------------|
| Plonky2 | Spend privé | 40 kB | 6 ms Oui | ✅ |
| Groth16 | Legacy bridge | 0.2 kB | 2 ms Non | ❌ |

Chaque `SpendDescription` contient :
π_plonky2, cm_old, cm_new, nf, epk, memo_enc

### 5. Arbre de commitments
 SparseMerkleTree<Poseidon2, 32>
- Feuille `index = Poseidon2(cm)[..4]` (32 bits)  
- Mises à jour incrémentales via `sled` + cache LRU 64 k nœuds.

---

## Consensus

### Fenêtre MIK (Merkle Interval Knowledge)
Objectif : preuve de travail **sans** divulgation des transactions aux mineurs.  
Principe :
1. Le mineur reçoit un `BlockHeader` contenant :
   - `merkle_root_note` (commitments),
   - `merkle_root_null` (nullifiers),
   - `difficulty_target`.
2. Il calcule :
   pre_hash = Blake3(header || nonce)
   work     = LeadingZeros(pre_hash)
3. Validité :
   work ≥ target ∧ pre_hash % MIK_WINDOW == 0
   où `MIK_WINDOW = 2^20` (≈ 1 M partages possibles).  
   → Le minage reste probabiliste, mais le réseau peut valider sans voir le contenu.

### Ajustement de difficulté
new_target = old_target * (600_000 / delta_time_ms)
- Fenêtre 90 blocs, borné `0.5 ≤ factor ≤ 2.0`.

---

## Réseau P2P

| Protocole | Transport | Port par défaut | Spec |
|-----------|-----------|-----------------|------|
| QUIC | Tokio-quinn | 9933 | [TSN-0004](specs/tsn-0004.md) |
| Discovery | libp2p-mdns + kademlia DHT | 9934 | idem |
| RPC | Protobuf + borsh | — | idem |

### Messages critiques
Handshake { magic: 0x54534e01, version: 0, challenge: [u8;32] }
Pong { challenge_response, height, best_hash }
GetBlocks { start_height, count }
Block { header, body, zproofs }
Transaction { spends, outputs, binding_sig }

### Sync
1. Fast-sync : télécharger en parallèle par tranche de 512 blocs.  
2. Validate : vérifier preuves Plonky2 + nullifiers uniques.  
3. Commit : écrire dans sled via `batch` ≤ 10 k inserts.  
→ Tempo cible ≤ 1 h pour 1 M blocs (SSD NVMe, 8 cœurs).

---

## Couche d’exécution

### Modèle comptable
- UTXO-ZK : les notes sont des UTXO cachés.  
- Pas de compte « solde » publique.  
- Les miners perçoivent :
  reward = base(60 TSN) + Σfees
  émis dans une `CoinbaseNote` déchiffrable seulement par `miner_pk`.

### Frais
fee = 1000 + 50*num_inputs + 30*num_outputs [sats]
- Les frais sont transparents (hors bande) pour éviter l’attaque « fee-sniping ».  
- Passage en `FeeMarket` dynamique prévu v0.2 (voir [TSN-0010