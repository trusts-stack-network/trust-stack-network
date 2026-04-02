# TSN Whitepaper v0.1
## Threshold Secure Network - Architecture Technique Post-Quantique

**Version:** 0.1.0-alpha  
**Date:** 2024-01-15  
**Statut:** Brouillon Technique  
**Classification:** Public / Open Specification  

---

## Table des matières

1. [Résumé Exécutif](#1-résumé-exécutif)
2. [Introduction et Objectifs](#2-introduction-et-objectifs)
3. [Architecture Globale](#3-architecture-globale)
4. [Couche Cryptographique](#4-couche-cryptographique)
   - 4.1 [SLH-DSA (FIPS 205)](#41-slh-dsa-fips-205)
   - 4.2 [Poseidon2 Hash Function](#42-poseidon2-hash-function)
5. [Couche Preuve à Connaissance Nulle](#5-couche-preuve-à-connaissance-nulle)
   - 5.1 [Halo2 Recursive Proof System](#51-halo2-recursive-proof-system)
6. [Système d'Identité MIK](#6-système-didentité-mik)
7. [Mécanisme de Consensus](#7-mécanisme-de-consensus)
8. [Couche Réseau P2P](#8-couche-réseau-p2p)
9. [Sécurité et Analyse des Menaces](#9-sécurité-et-analyse-des-menaces)
10. [Paramètres de Déploiement](#10-paramètres-de-déploiement)
11. [Références](#11-références)

---

##