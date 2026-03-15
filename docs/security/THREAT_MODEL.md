# Modèle de Menaces - Trust Stack Network (TSN)

**Version:** 1.0
**Date:** 2024
**Classification:** Interne

---

## 1. Introduction

Ce document décrit le modèle de menaces pour Trust Stack Network (TSN), une blockchain post-quantique. Il identifie les acteurs malveillants, les surfaces d'attaque, et les mitigations en place.

---

## 2. Acteurs Malveillants (Threat Actors)

### 2.1 Attaquant Opportuniste
- **Capacités:** Accès à du matériel standard
- **Motivation:** Profit financier
- **Surface d'attaque:** RPC public, mempool

### 2.2 Attaquant Organisé
- **Capacités:** Infrastructure dédiée, botnets
- **Motivation:** Sabotage, manipulation de marché
- **Surface d'attaque:** Réseau P2P, consensus

### 2.3 Attaquant Étatique
- **Capacités:** Ordinateurs quantiques (futur), ressources illimitées
- **Motivation:** Censure, surveillance
- **Surface d'attaque:** Cryptographie, gouvernance

### 2.4 Attaquant Interne
- **Capacités:** Accès au code source, infrastructure
- **Motivation:** Profit, revanche
- **Surface d'attaque:** CI/CD, clés de déploiement

---

## 3. Surfaces d'Attaque

### 3.1 Couche Réseau
| Composant | Risque | Mitigation |
|-----------|--------|------------|
| P2P Discovery | DoS, Eclipse | Rate limiting, peer diversity |
| Mempool | Spam, DoS | Fees, size limits |
| RPC/HTTP | Injection, DoS | Input validation, auth |

### 3.2 Couche Consensus
| Composant | Risque | Mitigation |
|-----------|--------|------------|
| PoW Mining | 51% attack | Difficulty adjustment |
| Block Validation | Invalid blocks | Multi-layer validation |
| Fork Choice | Long-range attacks | Finality gadget |

### 3.3 Couche Cryptographique
| Composant | Risque | Mitigation |
|-----------|--------|------------|
| Signatures | Forgery | ML-DSA-65 (post-quantique) |
| Hashes | Collisions | Poseidon2 |
| Preuves ZK | Soundness failures | Plonky2 STARKs |
| Clés | Extraction | HSM, air-gapped |

### 3.4 Couche Application
| Composant | Risque | Mitigation |
|-----------|--------|------------|
| Wallet | Key theft | Encryption, 2FA |
| Smart Contracts | Logic bugs | Formal verification |
| Oracle | Data manipulation | Multiple sources |

---

## 4. Menaces Spécifiques (STRIDE)

### 4.1 Spoofing (Falsification d'identité)
**Menace:** Falsification de signatures de transactions

**Scénario:**
- Attaquant tente de forger une signature ML-DSA-65
- Objectif: dépenser des fonds sans autorisation

**Mitigation:**
- ML-DSA-65 est prouvé sûr sous MLWE/MSIS
- Vérification stricte des signatures
- Pas de fallback vers algorithmes faibles

**Tests:** `tests/crypto_audit_signature.rs`

---

### 4.2 Tampering (Altération)
**Menace:** Modification de l'état de la blockchain

**Scénario:**
- Attaquant tente de modifier un bloc historique
- Objectif: réécrire l'historique des transactions

**Mitigation:**
- Chaîne de hashes immuable
- Preuves de Merkle pour chaque bloc
- Détection de modifications via consensus

**Tests:** `tests/crypto_audit_merkle.rs`

---

### 4.3 Repudiation (Répudiation)
**Menace:** Nier avoir effectué une transaction

**Scénario:**
- Utilisateur nie avoir signé une transaction
- Objectif: annuler un paiement

**Mitigation:**
- Signatures non-répudiables
- Logs immuables
- Timestamps vérifiables

---

### 4.4 Information Disclosure (Divulgation)
**Menace:** Exposition de données sensibles

**Scénario:**
- Attaquant extrait des informations des notes chiffrées
- Objectif: déanonymiser les transactions

**Mitigation:**
- Chiffrement ChaCha20Poly1305
- Commitments Pedersen
- Zero-knowledge proofs

---

### 4.5 Denial of Service (DoS)
**Menace:** Rendre le réseau indisponible

**Scénarios:**
1. **Mempool spam:** Envoi de transactions invalides
2. **Block flooding:** Minage de blocs vides
3. **Proof flooding:** Envoi de preuves malformées

**Mitigations:**
- Rate limiting sur les connexions P2P
- Validation rapide avant traitement
- Timeouts sur les opérations coûteuses
- Limites de taille sur les messages

**Tests:**
- `fuzz/signature_fuzzer.rs`
- `fuzz/proof_fuzzer.rs`
- `tests/crypto_audit_proof.rs`

---

### 4.6 Elevation of Privilege (Élévation de privilèges)
**Menace:** Obtenir des privilèges non autorisés

**Scénario:**
- Attaquant exploite une vulnérabilité dans le consensus
- Objectif: contrôler la production de blocs

**Mitigation:**
- Séparation des privilèges
- Validation multi-couches
- Audit de sécurité régulier

---

## 5. Attaques Post-Quantiques

### 5.1 Attaque de Shor
**Cible:** ECDSA, RSA, Diffie-Hellman
**Impact:** Tous les algorithmes à courbes elliptiques cassés
**Mitigation TSN:** Utilisation de ML-DSA-65 (pas de courbes elliptiques)

### 5.2 Attaque de Grover
**Cible:** Fonctions de hachage (SHA-256)
**Impact:** Complexité réduite de O(N) à O(√N)
**Mitigation TSN:** Poseidon2 avec paramètres augmentés

### 5.3 Attaque sur les preuves ZK
**Cible:** Groth16 (basé sur BN254)
**Impact:** Possibilité de forger des preuves
**Mitigation TSN:** Migration vers Plonky2 (STARKs post-quantiques)

---

## 6. Checklist de Sécurité Pré-Release

### 6.1 Cryptographie
- [ ] Tous les algorithmes post-quantiques validés
- [ ] Aucun unwrap/expect dans le code crypto
- [ ] Tests de régression pour chaque vulnérabilité
- [ ] Fuzzers exécutés sans crash

### 6.2 Réseau
- [ ] Rate limiting configuré
- [ ] Validation des inputs complète
- [ ] Timeouts sur toutes les opérations bloquantes
- [ ] Logs de sécurité activés

### 6.3 Consensus
- [ ] Tests de scénarios adversariaux
- [ ] Validation des blocs exhaustive
- [ ] Gestion des forks testée
- [ ] Résistance aux attaques 51% documentée

### 6.4 Documentation
- [ ] Ce threat model à jour
- [ ] SECURITY.md publié
- [ ] Procédure de disclosure définie
- [ ] Guide de réponse aux incidents

---

## 7. Références

- STRIDE: https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
- NIST Post-Quantum Cryptography: https://csrc.nist.gov/projects/post-quantum-cryptography
- OWASP Threat Modeling: https://owasp.org/www-community/Application_Threat_Modeling
