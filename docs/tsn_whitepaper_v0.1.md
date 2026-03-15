# TSN v0.1 - Technical Whitepaper
## Trustless Secure Network Architecture

**Version:** 0.1.0-alpha  
**Date:** 2024  
**Status:** Draft Specification  
**Classification:** Technical Documentation / Research

---

## Table des matières

1. [Résumé Exécutif](#1-résumé-exécutif)
2. [Architecture Système](#2-architecture-système)
3. [Primitives Cryptographiques](#3-primitives-cryptographiques)
   - 3.1 [SLH-DSA (SPHINCS+)](#31-slh-dsa-sphincs)
   - 3.2 [Poseidon2 Hash Function](#32-poseidon2-hash-function)
   - 3.3 [Halo2 ZK Framework](#33-halo2-zk-framework)
4. [MIK - Modular Integrity Kernel](#4-mik---modular-integrity-kernel)
5. [Mécanisme de Consensus](#5-mécanisme-de-consensus)
6. [Couche P2P](#6-couche-p2p)
7. [Flux de Protocole](#7-flux-de-protocole)
8. [Analyse de Sécurité](#8-analyse-de-sécurité)
9. [Références](#9-références)

---

## 1. Résumé Exécutif

TSN (Trustless Secure Network) est une infrastructure distribuée post-quantique combinant des primitives cryptographiques à sécurité prouvée avec des preuves à divulgation nulle de connaissance (ZK). L'architecture intègre :

- **SLH-DSA** (NIST FIPS 205) pour la signature post-quantique stateless
- **Halo2** pour les preuves recursives et composition de circuits
- **Poseidon2** pour le hachage optimisé en arithmétique ZK
- **MIK** pour la gestion d'état authentifiée par Merkle
- Un consensus BFT asynchrone résistant aux attaques quantiques
- Une couche P2P avec routage anonymisé

---

## 2. Architecture Système

```mermaid
graph TB
    subgraph "Couche Application"
        APP[Smart Contracts / State Transitions]
    end
    
    subgraph "Couche ZK / Preuve"
        HALO[Halo2 Prover/Verifier]
        MIK[MIK State Manager]
    end
    
    subgraph "Couche Cryptographique"
        SLH[SLH-DSA Signer]
        POS[Poseidon2 Hasher]
        PQ_Crypto[Post-Quantum Primitives]
    end
    
    subgraph "Couche Consensus"
        CONS[BFT Consensus Engine]
        ST[State Replication]
    end
    
    subgraph "Couche Réseau"
        P2P[P2P Transport]
        DISC[Peer Discovery]
        ENCR[Noise Framework + PQ KEM]
    end
    
    APP --> HALO
    HALO --> MIK
    MIK --> POS
    HALO --> SLH
    SLH --> CONS
    CONS --> P2P
    MIK --> CONS
    P2P --> ENCR

### 2.1 Stack Technique

| Composant | Implémentation | Spécification |
|-----------|---------------|---------------|
| Signature | SLH-DSA-SHAKE-256s | NIST FIPS 205 |
| Hash ZK | Poseidon2 | Cryptology ePrint 2023/323 |
| Preuve ZK | Halo2 | Zcash Protocol Spec |
| Consensus | MIK-BFT | TSN-CONS-001 |
| Transport | QUIC + Noise IK | IETF RFC 9000 / Noise Protocol |

---

## 3. Primitives Cryptographiques

### 3.1 SLH-DSA (SPHINCS+)

SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) fournit la résistance post-quantique via des fonctions de hachage cryptographiques standard, sans dépendance de la structure algébrique.

#### Paramètres TSN

# Configuration SLH-DSA-SHAKE-256s (Small, Sécurité 128 bits NIST Level 1)
PARAMETERS = {
    "n": 16,          # Longueur de sécurité (bytes)
    "h": 63,          # Hauteur de l'hypertree
    "d": 7,           # Nombre de couches
    "a": 12,          # Taille des arbres XMSS
    "k": 14,          # Nombre de chaînes FORS
    "w": 16,          # Paramètre Winternitz
    
    # Dérivés
    "h_prime": 9,     # h // d
    "m": 30,          # Longueur du message digest (FORS)
    "len": 35         # Nombre de blocs Winternitz
}

#### Structure de la Signature

Signature SLH-DSA (7,856 bytes pour SHAKE-256s):
├── Randomness (n bytes)
├── FORS Signature (k(1+a)n bytes)
│   ├── k indices de sélection
│   └── k preuves d'authentification (a+1 nœuds chacune)
└── Hypertree Signature (d × XMSS)
    └── d × (len + h/d) × n bytes

#### Intégration TSN

Les clés sont dérivées via un HD-wallet post-quantique (BIP32-PQ) :

Master Seed (256 bits)
    └── CKD-PQ(index):
        ├── SLH-DSA SK 
        ├── SLH-DSA PK
        └── Chaîne de hachage BLAKE2b pour dérivation déterministe

### 3.2 Poseidon2 Hash Function

Poseidon2 est une primitive de hachage conçue spécifiquement pour les circuits ZK (faible arithmétique de contraintes R1CS/Plonkish).

#### Paramètres Arithmétiques

- **Corps fini :** GF(p) où p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001 (BN254 scalar field)
- **Taux (t) :** 3 (2 éléments de capacité, 1 de taux)
- **Nombre de tours :** 8 full rounds + 56 partial rounds (rounds à mi-chemin