# TSN Technical Whitepaper v0.1
## Trustless Secure Network Architecture

**Version:** 0.1.0-draft  
**Date:** 2024-01-15  
**Status:** Draft Specification  
**Authors:** TSN Protocol Team  

---

## Table of Contents

1. [Abstract](#abstract)
2. [Introduction](#introduction)
3. [Architecture Overview](#architecture-overview)
4. [Cryptographic Primitives](#cryptographic-primitives)
   - 4.1 [SLH-DSA (SPHINCS+)](#slh-dsa-sphincs)
   - 4.2 [Poseidon2 Hash Function](#poseidon2-hash-function)
   - 4.3 [Halo2 Proof System](#halo2-proof-system)
5. [Identity Layer: MIK](#identity-layer-mik)
6. [Consensus Protocol](#consensus-protocol)
7. [Networking Layer](#networking-layer)
8. [Security Considerations](#security-considerations)
9. [References](#references)

---

## Abstract

TSN (Trustless Secure Network) est une infrastructure blockchain post-quantique intégrant des primitives cryptographiques résistantes aux ordinateurs quantiques avec des preuves à divulgation nulle de connaissance (ZKP) récursives. Ce document spécifie l'architecture v0.1 combinant SLH-DSA pour la signature post-quantique, Halo2 pour les preuves récursives, et Poseidon2 comme fonction de hachage arithmétisée.

---

## Introduction

Les réseaux distribués actuels font face à deux menaces majeures :
1. **Suprématie quantique** : L'algorithme de Shor menace ECDSA et RSA
2. **Scalabilité** : Les preuves ZK existantes souffrent de temps de vérification élevés

TSN v0.1 propose une architecture hybride :
- **Post-quantique** : SLH-DSA (NIST FIPS 205) pour toutes les signatures
- **ZK-Rollup natif** : Halo2 sans trusted setup
- **Hachage algébrique** : Poseidon2 optimisé pour les circuits R1CS/PLONK

---

## Architecture Overview

### Stack Technique

```mermaid
graph TB
    A[Application Layer] --> B[ZK-Rollup Layer<br/>Halo2 Circuits]
    B --> C[Consensus Layer<br/>BFT + MIK]
    C --> D[Cryptographic Layer<br/>SLH-DSA + Poseidon2]
    D --> E[P2P Network Layer<br/>Noise Protocol]
    
    subgraph "Post-Quantum Security"
    D
    end
    
    subgraph "Zero-Knowledge"
    B
    end

### Flux de Transaction

sequenceDiagram
    participant U as User
    participant W as Wallet/MIK
    participant V as Validator
    participant C as Halo2 Circuit
    participant N as P2P Network
    
    U->>W: Sign(Tx, SK_SLH)
    W->>C: Generate Witness
    C->>C: Poseidon2(Tx_hash)
    C->>C: Create Proof π
    W->>V: Submit(Tx, π, PK_SLH)
    V->>V: Verify SLH-DSA Sig
    V->>C: Verify π
    V->>N: Broadcast Proposal
    N->>V: Consensus Round

---

## Cryptographic Primitives

### SLH-DSA (SPHINCS+)

TSN utilise **SLH-DSA-SHA2-128s** comme schéma de signature par défaut, conforme à NIST FIPS 205.

#### Paramètres

| Paramètre | Valeur | Description |
|-----------|--------|-------------|
| `n` | 16 | Security parameter (128-bit security) |
| `h` | 63 | Hypertree height |
| `d` | 7 | Hypertree layers |
| `a` | 12 | FORS trees |
| `k` | 14 | FORS leafs |
| `w` | 16 | Winternitz parameter |

#### Intégration

Les adresses TSN sont dérivées des clés publiques SLH-DSA via :

address = Poseidon2(PK_SLH || version_byte || checksum)

**Tailles :**
- Clé privée : 64 octets (seed)
- Clé publique : 32 octets
- Signature : 7 856 octets (compactée avec compression de Winternitz)

### Poseidon2 Hash Function

Remplacement de SHA-256/Keccak par Poseidon2 pour toutes les opérations arithmétiques.

#### Paramètres TSN-P2

# Prime field: BLS12-381 scalar field
p = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

# Permutation configuration
t = 3          # State size (2 inputs + 1 capacity)
R_F = 8        # Full rounds
R_P = 56       # Partial rounds (optimized for t=3)

#### Sponge Construction

graph LR
    I[Input Blocks] --> S[Sponge<br/>t=3]
    S -->|Absorb| P[Permutation<br/>R_F=8, R_P=56]
    P -->|Squeeze| O[Output<br/>256-bit]
    
    style P fill:#f9f,stroke:#333,stroke-width:2px

### Halo2 Proof System

Utilisation de Halo2 pour :
1. **Rollup validation** : Agrégation des signatures SLH-DSA
2. **State transitions** : Preuves de transition d'état valides
3. **Recursive composition** : Preuve de preuve pour scalabilité infinie

#### Circuit Architecture

graph TD
    A[Transaction Circuit] --> D[Recursive Verifier]
    B[State Circuit] --> D
    C[Signature Circuit<br/>SLH-DSA verification] --> D
    D --> E[Aggregation Circuit]
    E --> F[Final Proof<br/>~200 bytes]

**Contraintes clés :**
- Lookup tables pour Poseidon2 (optimisation 40% vs hash direct)
- Custom gates pour vérification WOTS+ (Winternitz)
- Recursive depth max : 32 niveaux

---

## Identity Layer: MIK

### Merkle Identity Key (MIK)

Système de dérivation hiérarchique post-quantique.

#### Structure

MIK-Tree (