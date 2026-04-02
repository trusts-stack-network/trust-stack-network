# TSN Protocol v0.1 Technical Whitepaper
## Trustless Secure Network - Post-Quantum Ledger Architecture

**Version:** 0.1.0-alpha  
**Date:** 2024-11  
**Status:** Draft Specification  
**Classification:** Technical Reference

---

## Table des matières

1. [Résumé exécutif](#1-résumé-exécutif)
2. [Architecture système](#2-architecture-système)
3. [Couche cryptographique](#3-couche-cryptographique)
   - 3.1 [SLH-DSA (FIPS 205)](#31-slh-dsa-fips-205)
   - 3.2 [Poseidon2 Hash Function](#32-poseidon2-hash-function)
4. [Couche Zero-Knowledge](#4-couche-zero-knowledge)
   - 4.1 [Halo2 Proof System](#41-halo2-proof-system)
   - 4.2 [Recursive Composition](#42-recursive-composition)
5. [Protocole de consensus MIK](#5-protocole-de-consensus-mik)
   - 5.1 [Spécification du protocole](#51-spécification-du-protocole)
   - 5.2 [État et transitions](#52-état-et-transitions)
6. [Couche réseau P2P](#6-couche-réseau-p2p)
7. [Pipeline de transaction](#7-pipeline-de-transaction)
8. [Modèle de sécurité](#8-modèle-de-sécurité)
9. [Performances](#9-performances)
10. [Références](#10-références)

---

## 1. Résumé exécutif

TSN (Trustless Secure Network) est une infrastructure de ledger distribué résistante aux attaques quantiques, combinant primitives cryptographiques post-quantiques (SLH-DSA), preuves à divulgation nulle de connaissance récursives (Halo2), et consensus byzantin tolérant aux fautes optimisé pour l'état (MIK).

**Propriétés fondamentales:**
- **Sécurité post-quantique:** Signatures stateful SLH-DSA conformes NIST FIPS 205
- **Scalabilité horizontale:** Preuves récursives Halo2 sans trusted setup
- **Finalité rapide:** Consensus MIK à finalité instantanée (≤3s)
- **Confidentialité optionnelle:** Circuits ZK pour transactions privées
- **Interopérabilité:** Compatibilité EVM via preuves de validité

---

## 2. Architecture système

L'architecture TSN adopte une séparation stricte des couches :

```mermaid
flowchart TB
    subgraph Application["Couche Application"]
        SC[Smart Contracts]
        ZKApp[ZK Applications]
    end
    
    subgraph Execution["Couche Exécution (Halo2)"]
        PC[Proof Circuits]
        RV[Recursive Verifier]
        Poseidon[Poseidon2 Hasher]
    end
    
    subgraph Consensus["Couche Consensus (MIK)"]
        BFT[MIK BFT Engine]
        SMR[State Machine Replication]
        SLH[SLH-DSA Signatures]
    end
    
    subgraph Network["Couche Réseau (P2P)"]
        Gossip[Gossipsub v1.2]
        Noise[Noise Protocol]
        Discovery[mDNS/DHT]
    end
    
    Application -->|Transactions| Execution
    Execution -->|Batch Proofs| Consensus
    Consensus -->|Committed Blocks| Network
    Network -->|Block Propagation| Consensus

**Principes architecturaux:**
1. **Sé