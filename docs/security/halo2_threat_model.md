# Modèle de Menaces Halo2 - Trust Stack Network

## Vue d'ensemble

Ce document décrit le modèle de menaces pour le système de preuves Halo2 de TSN, incluant les circuits ZK, le validateur de preuves, et les mécanismes de protection.

## Architecture Halo2 TSN

### Composants Principaux

1. **halo2_proofs.rs** - Implémentation des circuits et preuves Halo2
2. **halo2_validator.rs** - Validation sécurisée des preuves
3. **halo2_shielded_proofs.rs** - Preuves pour transactions shielded
4. **halo2_circuit.rs** - Définition des circuits

### Flux de Données

```
Transaction Shielded → Circuit Halo2 → Preuve ZK → Validation → Inclusion Bloc
```

## Modèle d'Adversaire

### Capacités de l'Adversaire

| Niveau | Capacités | Exemples |
|--------|-----------|----------|
| Opportuniste | Réseau public, observation | Timing attacks, fingerprinting |
| Actif | Injection de messages, DoS | Preuves malformées, flood |
| Avancé | Connaissance cryptographique | Preuves fausses sophistiquées |
| Insider | Accès interne, clés compromises | Fausse preuve avec vk légitime |

### Objectifs de l'Adversaire

1. **Falsification de preuve** - Créer une preuve valide sans connaître le witness
2. **Double-spend** - Réutiliser une preuve pour deux transactions
3. **DoS** - Crasher le validateur avec des entrées malformées
4. **Extraction d'information** - Déduire des données privées des preuves
5. **Malleabilité** - Modifier une preuve sans invalider la vérification

## Analyse STRIDE

### Spoofing (Usurpation d'identité)

**Menace:** Usurpation d'un circuit Halo2 légitime

**Scénario:**
- Attaquant crée un faux verifying key
- Usurpe l'identité d'un circuit approuvé

**Mitigation:**
- Hash du verifying key stocké on-chain
- Vérification systématique du vk_hash
- Registre de circuits approuvés

**Statut:** ✅ Mitigé

### Tampering (Altération)

**Menace:** Modification d'une preuve après génération

**Scénario:**
- Attaquant intercepte une preuve valide
- Modifie les entrées publiques
- Soumet la preuve modifiée

**Mitigation:**
- Binding cryptographique preuve → entrées publiques
- Vérification de cohérence des commitments
- Non-malleabilité du schéma de preuve

**Statut:** ✅ Mitigé

### Repudiation (Répudiation)

**Menace:** Nier avoir effectué une transaction

**Scénace:**
- Utilisateur nie avoir créé une transaction shielded
- Pas de traçabilité publique

**Mitigation:**
- Nullifiers publiques et uniques
- Preuves liées aux nullifiers
- Audit trail cryptographique

**Statut:** ✅ Mitigé

### Information Disclosure (Divulgation d'information)

**Menace:** Extraction d'informations privées des preuves

**Scénario:**
- Analyse des preuves pour déduire les montants
- Corrélation des nullifiers
- Timing analysis

**Mitigation:**
- Zero-knowledge property du circuit
- Padding constant-time
- Randomisation des preuves

**Statut:** ✅ Mitigé

### Denial of Service (Déni de service)

**Menace:** Crash ou ralentissement du validateur

**Scénarios:**
- Preuve de taille excessive (10GB+)
- Nombre d'entrées publiques énorme
- Points de courbe invalides
- Boucles infinies dans la vérification

**Mitigations:**
- Limites strictes de taille (preuve < 10MB, entrées < 1000)
- Timeouts de vérification
- Circuit breaker sur erreurs répétées
- Validation structurelle avant vérification cryptographique

**Statut:** ✅ Mitigé

### Elevation of Privilege (Élévation de privilèges)

**Menace:** Contournement des règles de consensus

**Scénario:**
- Preuve valide mais pour montant supérieur aux inputs
- Contournement des vérifications de solde

**Mitigation:**
- Vérification des contraintes arithmétiques
- Range checks sur tous les montants
- Vérification des Merkle roots

**Statut:** ✅ Mitigé

## Surfaces d'Attaque

### 1. Interface de Validation

**Entrées:**
- Preuve binaire (bytes)
- Entrées publiques (Vec<Vec<u8>>)
- Verifying key hash ([u8; 32])

**Risques:**
- Deserialization panic
- Buffer overflow
- Integer overflow sur les tailles

**Tests:** `halo2_proof_validation_test.rs`, `halo2_property_tests.rs`

### 2. Circuit Halo2

**Composants:**
- Contraintes arithmétiques
- Lookup tables
- Permutation arguments

**Risques:**
- Underconstrained circuit
- Malicious witness
- Side-channel via lookup tables

**Tests:** `halo2_circuit_test.rs`

### 3. Verifying Key

**Risques:**
- VK malformé
- VK compromis
- VK substitution

**Mitigation:**
- Hash verification
- On-chain registry
- Multi-sig pour VK updates

## Checklist de Sécurité Pré-Déploiement

### Validation des Preuves

- [ ] Taille de preuve limitée (min: 32 bytes, max: 10MB)
- [ ] Nombre d'entrées publiques limité (max: 1000)
- [ ] Taille individuelle des entrées limitée (max: 1MB)
- [ ] Taille totale des entrées limitée (max: 100MB)
- [ ] Patterns malveillants rejetés (PWN!, etc.)
- [ ] Points de courbe invalides rejetés
- [ ] Timeout de vérification configuré

### Circuit Security

- [ ] Circuit audité pour underconstrained constraints
- [ ] Lookup tables vérifiées
- [ ] Random oracle model validé
- [ ] Fiat-Shamir transform sécurisé

### Opérationnel

- [ ] Circuit breaker activé
- [ ] Rate limiting configuré
- [ ] Monitoring des erreurs de validation
- [ ] Alertes sur taux d'échec anormal

## Références

- [Halo2 Book](https://zcash.github.io/halo2/)
- [PLONK Paper](https://eprint.iacr.org/2019/953)
- [Halo Paper](https://eprint.iacr.org/2019/1021)
- TSN Security Guidelines

## Historique des Révisions

| Version | Date | Auteur | Changements |
|---------|------|--------|-------------|
| 1.0 | 2024-01-15 | Security Team | Création initiale |
| 1.1 | 2024-02-20 | Security Team | Ajout DoS scenarios |
