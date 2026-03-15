# TSN (Trustless Secure Network) v0.1 - Technical Whitepaper

**Version:** 0.1.0-alpha  
**Date:** 2024-01-15  
**Status:** Draft  
**Classification:** Technical Specification  

## Abstract

TSN est une infrastructure blockchain post-quantique de couche 1, intégrant des primitives cryptographiques résistantes aux ordinateurs quantiques (SLH-DSA), des preuves à divulgation nulle de connaissance récursives (Halo2) et une fonction de hachage algébrique optimisée (Poseidon2). Ce document spécifie l'architecture système, le protocole de consensus hybride, la couche de gestion d'identité modulaire (MIK) et la stack réseau P2P.

## Table des matières

1. [Introduction](#1-introduction)
2. [Primitives Cryptographiques](#2-primitives-cryptographiques)
   - 2.1 [SLH-DSA (SPHINCS+)](#21-slh-dsa-sphincs)
   - 2.2 [Poseidon2](#22-poseidon2)
   - 2.3 [Halo2 ZK Proving System](#23-halo2-zk-proving-system)
3. [Architecture Système](#3-architecture-système)
   - 3.1 [Vue d'ensemble](#31-vue-densemble)
   - 3.2 [Structure des transactions](#32-structure-des-transactions)
   - 3.3 [Modèle d'état](#33-modèle-détat)
4. [MIK - Modular Identity & Key Management](#4-mik---modular-identity--key-management)
5. [Protocole de Consensus](#5-protocole-de-consensus)
6. [Couche P2P](#6-couche-p2p)
7. [Sécurité et Analyse](#7-sécurité-et-analyse)
8. [Références](#8-références)

---

## 1. Introduction

TSN résout le problème de la migration post-quantique des blockchains existantes en implémentant nativement des signatures hash-based stateless (SLH-DSA) tout en maintenant la confidentialité sélective via des zk-SNARKs récursifs. L'architecture est conçue pour résister à l'algorithme de Shor et à l'algorithme de Grover.

### Objectifs de conception

- **Post-Quantum Security**: Résistance aux attaques quantiques via SLH-DSA-128f (NIST FIPS 205)
- **Scalabilité**: Traitement parallèle des transactions via preuves récursives Halo2
- **Interopérabilité**: Format de transaction compatible avec les standards existants (EVM-like)
- **Privacy**: Transactions confidentielles via circuits zk intégrés

---

## 2. Primitives Cryptographiques

### 2.1 SLH-DSA (SPHINCS+)

Implémentation conforme à [FIPS 205](https://csrc.nist.gov/projects/post-quantum-cryptography) avec les paramètres suivants :

| Paramètre | Valeur | Description |
|-----------|--------|-------------|
| `n` | 16 | Security parameter (128-bit security) |
| `h` | 66 | Height of the hypertree |
| `d` | 22 | Number of layers |
| `a` | 6 | Winternitz parameter |
| `k` | 33 | Number of FORS trees |

**Tailles :**
- Clé publique : 32 octets
- Clé privée : 64 octets  
- Signature : 7,856 octets (optimisée via compression WOTS+)

```mermaid
graph TD
    A[Message] -->|SHAKE256| B[M']
    B --> C[FORS Signature]
    C --> D[Hypertree Signature]
    D --> E[Final Signature<br/>~7.8KB]
    F[SK.seed + PK.seed] --> C
    F --> D

### 2.2 Poseidon2

Fonction de hachage à préimage résistante optimisée pour les circuits ZK. Paramètres TSN :

- **Field**: BLS12-381 scalar field (`p = 0x73eda753...`)
- **S-box**: x⁵ (inversion dans le champ premier)
- **Rounds**: 8 full rounds + 57 partial rounds (t = 3)
- **Capacité**: 2 éléments de field
- **Rate**: 1 élément de field

// Pseudo-code de la permutation
fn poseidon2_permutation(state: [Fp; 3]) -> [Fp; 3] {
    // Full S-box layers
    for r in 0..4 {
        state = s_box_full(state);
        state = mds_matrix_mul(state);
        state = add_constants(state, RC[r]);
    }
    // Partial rounds
    for r in 4..60 {
        state[0] = state[0].pow(5); // S-box partiel
        state = mds_matrix_mul(state);
        state = add_constants(state, RC[r]);
    }
    // Final full rounds
    for r in 60..64 {
        state = s_box_full(state);
        state = mds_matrix_mul(state);
    }
    state
}

### 2.3 Halo2 ZK Proving System

Utilisation du protocole IPA (Inner Product Argument) sur les courbes de cycles Pallas/Vesta (cycle de 2-courbes).

**Caractéristiques :**
- **Courbes**: Pallas (Vesta scalar field) / Vesta (Pallas scalar field)
- **Polynomial Commitment**: IPA (pas de trusted setup requise)
- **Lookup arguments**: Tables de lookup pour opérations arith