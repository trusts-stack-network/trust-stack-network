---
tsn: 001
title: Migration ML-DSA-65 vers SLH-DSA-SHA2-192s
status: Draft
type: Standards Track
category: Crypto
author: Security Research Team <security@example.org>
created: 2024-01-15
updated: 2024-01-15
requires: FIPS 204, FIPS 205
---

# TSN-001: Migration ML-DSA-65 vers SLH-DSA-SHA2-192s

## Table des matières
- [Abstract](#abstract)
- [Motivation](#motivation)
- [Spécification](#spécification)
  - [Paramètres cryptographiques](#paramètres-cryptographiques)
  - [Formats de données](#formats-de-données)
  - [Algorithmes](#algorithmes)
- [Plan de migration](#plan-de-migration)
- [Vecteurs de test](#vecteurs-de-test)
- [Rationale](#rationale)
- [Compatibilité descendante](#compatibilité-descendante)
- [Considérations de sécurité](#considérations-de-sécurité)
- [Références](#références)
- [Annexe A: Comparaison des tailles](#annexe-a-comparaison-des-tailles)

## Abstract

Cette spécification définit la procédure de migration des signatures numériques post-quantiques depuis ML-DSA-65 (CRYSTALS-Dilithium, FIPS 204) vers SLH-DSA-SHA2-192s (SPHINCS+, FIPS 205). Elle établit les paramètres cryptographiques, les formats d'encodage des clés et signatures, ainsi qu'un plan de transition en quatre phases permettant la coexistence hybride suivie du retrait sécurisé de ML-DSA.

## Motivation

ML-DSA repose sur la sécurité des réseaux euclidiens (lattices), offrant des signatures compactes et rapides. Cependant, SLH-DSA présente des avantages fondamentaux pour les infrastructures à haute sécurité :

1. **Hypothèses cryptographiques conservatrices** : SLH-DSA repose uniquement sur la résistance des fonctions de hachage cryptographiques (SHA2/SHAKE), sans dépendre de structures algébriques complexes
2. **Résistance aux attaques par canaux auxiliaires** : Algorithmes stateless sans dépendance à l'état interne secret durant la signature
3. **Conformité réglementaire** : Recommandation explicite dans certains secteurs (défense, finance) pour les systèmes à longue durée de vie (>20 ans)

La migration vise à assurer la continuité de service tout en élevant le niveau de sécurité quantique de NIST Level 3 vers une sécurité basée uniquement sur les fonctions de hachage.

## Spécification

### Paramètres cryptographiques

La migration cible **SLH-DSA-SHA2-192s** (small, fast signature generation) comme paramètre par défaut, avec **SLH-DSA-SHA2-192f** (fast verification) comme alternative.

| Paramètre | ML-DSA-65 (Legacy) | SLH-DSA-SHA2-192s (Cible) | SLH-DSA-SHA2-192f (Alternative) |
|-----------|-------------------|---------------------------|-------------------------------|
| NIST Level | 3 | 3 | 3 |
| Fonction de hachage | SHAKE-256 | SHA2-256 | SHA2-256 |
| `n` (paramètre de sécurité) | 256 | 24 | 24 |
| `