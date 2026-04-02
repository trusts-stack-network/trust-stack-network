# TSN v0.1 Technical Whitepaper
## Temporal State Network - Zero-Knowledge Post-Quantum Architecture

**Version:** 0.1.0-alpha  
**Date:** 2024-01-15  
**Status:** Draft  
**Classification:** Technical Specification

---

## Table des matières

1. [Résumé exécutif](#1-résumé-exécutif)
2. [Architecture système](#2-architecture-système)
3. [Primitives cryptographiques](#3-primitives-cryptographiques)
4. [Consensus distribué](#4-consensus-distribué)
5. [Réseau P2P](#5-réseau-p2p)
6. [Gestion d'état et MIK](#6-gestion-détat-et-mik)
7. [Sécurité et preuves](#7-sécurité-et-preuves)
8. [Références](#8-références)

---

## 1. Résumé exécutif

Le **Temporal State Network (TSN)** est une infrastructure blockchain de couche 1 intégrant nativement :
- **Résistance post-quantique** via SLH-DSA (SPHINCS+)
- **Preuves à divulgation nulle de connaissance** via Halo2
- **Hachage arithmétisé** via Poseidon2
- **Consensus BFT** optimisé pour les circuits ZK
- **Schéma d'intégrité d'état** MIK (Merkle Integrity Key)

L'architecture garantit l'immuabilité temporelle des états avec vérification succincte des transitions d'état.

---

## 2. Architecture système

### 2.1 Vue d'ensemble

TSN utilise une séparation d'architecture entre :
- **Execution Layer (EL)** : Calcul des transitions d'état avec preuves Halo2
- **Consensus Layer (CL)** : Finalisation des blocs via consensus BFT
- **Networking Layer (NL)** : Transport P2P chiffré post-quantique

```mermaid
graph TB
    subgraph "Client TSN"
        A[Application] --> B[TSN SDK]
        B --> C[Prover Halo2]
        B --> D[Signer SLH-DSA]
    end
    
    subgraph "Nœud Validateur"
        E[P2P Interface] --> F[Consensus Engine]
        F --> G[State Manager]
        G --> H[MIK Storage]
        C -->|ZK Proof| I[Verifier Circuit]
        D -->|Signatures PQC| F
    end
    
    subgraph "Couche cryptographique"
        H --> J[Poseidon2 Hasher]
        I --> J
        F --> K[SLH-DSA Verifier]
    end
    
    style C fill:#f9f,stroke:#333,stroke-width:2px
    style D fill:#bbf,stroke:#333,stroke-width:2px

### 2.2 Flux de transaction

sequenceDiagram
    participant U as Utilisateur
    participant P as Prover Halo2
    participant S as SLH-DSA Sign
    participant N as Nœud P2P
    participant C as Consensus
    participant V as Verifier
    
    U->>P: Générer preuve transition état
    P->>P: Arithmétisation PLONKish
    P->>P: Commitment KZG
    P-->>U: π (preuve ZK)
    
    U->>S: Signer tx + π
    S-->>U: σ (signature SLH-DSA)
    
    U->>N: Diffuser (tx, π, σ)
    N->>N: Vérification Poseidon2
    
    N->>C: Proposer bloc
    C->>V: Vérifier preuve Halo2
    C->>V: Vérifier SLH-DSA
    V-->>C: Valid/Invalid
    C->>C: Consensus BFT
    C-->>N: Finalisation

---

## 3. Primitives cryptographiques

### 3.1 SLH-DSA (SPHINCS+)

Implémentation conforme à **FIPS 205** :
- Paramètres : `128s`, `128f`, `192s`, `192f`, `256s`, `256f`
- Fonction de hachage : SHA-256 ou SHAKE256
- Structure : Hypertree XMSS multi-couches
- Taille