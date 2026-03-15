# TSN Protocol v0.1 - Whitepaper Technique

**Post-Quantum Secure Ledger with Recursive ZK-Proofs**

*Date: 2024*  
*Version: 0.1.0-draft*  
*Classification: Technical Specification*

---

## Table des matières

1. [Résumé Exécutif](#1-résumé-exécutif)
2. [Architecture Globale](#2-architecture-globale)
3. [Couche Cryptographique](#3-couche-cryptographique)
   - 3.1 [SLH-DSA (SPHINCS+)](#31-slh-dsa-sphincs)
   - 3.2 [Halo2 Proving System](#32-halo2-proving-system)
   - 3.3 [Poseidon2 Hash Function](#33-poseidon2-hash-function)
   - 3.4 [MIK - Multi-Identity Key Management](#34-mik---multi-identity-key-management)
4. [Consensus Protocol](#4-consensus-protocol)
5. [Couche Réseau P2P](#5-couche-réseau-p2p)
6. [Format des Transactions](#6-format-des-transactions)
7. [Circuit Halo2 pour TSN](#7-circuit-halo2-pour-tsn)
8. [Considérations de Sécurité](#8-considérations-de-sécurité)
9. [Références](#9-références)

---

## 1. Résumé Exécutif

TSN (Trustless Secure Network) v0.1 est un registre distribué résistant aux attaques quantiques, combinant des signatures post-quantiques SLH-DSA (SPHINCS+) avec des preuves à divulgation nulle de connaissance récursives via Halo2. L'architecture intègre une fonction de hachage arithmétisée Poseidon2 optimisée pour les circuits ZK et un système de gestion d'identités hiérarchiques MIK (Multi-Instance Key).

**Caractéristiques clés :**
- Sécurité post-quantique (NIST Level 1-5)
- Preuves récursives sans trusted setup (Halo2)
- Finalité rapide (< 3s) via consensus BFT optimisé
- Bande passante réduite grâce à la compression ZK

---

## 2. Architecture Globale

```mermaid
graph TB
    subgraph "Application Layer"
        APP[Client TSN]
    end
    
    subgraph "Cryptographic Core"
        SLH[SLH-DSA<br/>FIPS 205]
        MIK[MIK Manager<br/>HKDF-SLH]
        HALO[Halo2 Prover<br/>Recursive]
    end
    
    subgraph "Consensus Layer"
        HOT[HotStuff-BFT<br/>Optimisé]
        POS[Poseidon2<br/>Merkle Trees]
    end
    
    subgraph "Network Layer"
        P2P[Libp2p<br/>Noise + TLS 1.3]
        GOS[GossipSub<br/>Flood Publishing]
    end
    
    APP -->|Sign TX| SLH
    SLH -->|PubKey| MIK
    MIK -->|Derived Keys| HALO
    HALO -->|ZK-Proof| HOT
    HOT -->|Block Hash| POS
    POS -->|Root| P2P
    P2P -->|Broadcast| GOS

---

## 3. Couche Cryptographique

### 3.1 SLH-DSA (SPHINCS+)

**Spécification :** NIST FIPS 205 (Août 2024)

TSN utilise SLH-DSA-SHA2-128s pour les signatures de transaction et SLH-DSA-SHAKE-256s pour les signatures de blocs (haute valeur).

**Paramètres :**
| Paramètre | Valeur | Sécurité | Taille Signature |
|-----------|--------|----------|------------------|
| n | 16 | 128-bit | 7.8 KB |
| h | 63 | - | - |
| d | 7 | - | - |
| a | 12 | - | - |
| k | 14 | - | - |

**Implémentation :**
- WOTS+ pour signatures à usage unique
- FORS (Forest of Random Subsets) pour l'état stateless
- SHA2-256/SHAKE256 comme PRF et H

// Pseudo-code de signature TSN
fn sign_tx(sk: SlhDsaPrivateKey, tx: Transaction) -> Signature {
    let ctx = b"TSN-v0.1-context";
    slh_dsa_sign(sk, tx.hash(), ctx, Randomness::Deterministic)
}

### 3.2 Halo2 Proving System

**Spécification :** Zcash Halo2 (IPA-based, KZG variant supporté)

TSN utilise Halo2 pour prouver la validité des transitions d'état sans révéler les entrées.

**Configuration Circuit :**
- **Curve :** Pasta curves (Pallas/Vesta) ou BLS12-381 (avec KZG)
- **Lookup tables :** 2^20 rows max
- **Constraints degree :** 5
- **Recursion :** Accumulation scheme (Nova-compatible)

**Preuve Recursive :**
Chaque bloc contient une preuve $\pi_n$ qui vérifie la preuve $\pi_{n-1}$ plus les nouvelles transactions.

$$\pi_n = \text{Prove}(C_{TSN}, (st_n, tx_n, \pi_{n-1}))$$

Où $C_{TSN}$ est le circuit décrit dans la section 7.

### 3.3 Poseidon2 Hash Function

**Spécification :** Poseidon2 (2023) - amélioration de Poseidon avec moins de contraintes R1CS.

**Paramètres TSN :**
- **Field :** $\mathbb{F}_p$ (Pallas