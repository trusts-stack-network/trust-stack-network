# Threat Model: TSN Faucet Module

## Overview

Le module faucet distribue 50 TSN par wallet par jour. C'est une surface d'attaque critique car il crée de la valeur (tokens) à partir de rien.

**Document Version:** 1.0  
**Last Updated:** 2024  
**Owner:** Security & QA Team

---

## Assets

| Asset | Value | Protection Level |
|-------|-------|------------------|
| Faucet balance | TSN tokens | Critical |
| Claim rate limit state | DoS prevention | High |
| Nullifier set | Replay protection | Critical |
| Plonky2 verification key | Proof validation | Critical |
| Merkle root | Commitment integrity | Critical |

---

## Threat Actors

### 1. Opportunist (Low Sophistication)
- **Capabilities:** Scripts basiques, multiples wallets
- **Motivation:** Tokens gratuits
- **Attack:** Création massive de wallets, claims automatisés

### 2. Organized Abuser (Medium Sophistication)
- **Capabilities:** Botnets, CAPTCHA solving, proxy rotation
- **Motivation:** Revente des tokens
- **Attack:** Sybil attacks, géo-distribution des requêtes

### 3. Advanced Attacker (High Sophistication)
- **Capabilities:** Reverse engineering, cryptanalyse
- **Motivation:** Exploitation technique, briser les garanties de sécurité
- **Attack:** Falsification de preuves Plonky2, timing attacks, race conditions

### 4. Insider Threat
- **Capabilities:** Accès au code source, infrastructure
- **Motivation:** Sabotage, vol
- **Attack:** Backdoors, manipulation des paramètres

---

## STRIDE Analysis

### Spoofing (S)

| Threat | Risk | Mitigation | Status |
|--------|------|------------|--------|
| Usurpation d'identité wallet | High | pk_hash binding cryptographique | ✅ Implémenté |
| Falsification de preuve Plonky2 | Critical | Vérification complète du circuit | ✅ Implémenté |
| Replay de claims valides | High | Nullifier unique par claim | ✅ Implémenté |

### Tampering (T)

| Threat | Risk | Mitigation | Status |
|--------|------|------------|--------|
| Modification du montant de claim | Critical | Montant constant (50 TSN), non configurable par l'utilisateur | ✅ Implémenté |
| Modification du timestamp | Medium | Validation côté serveur, tolérance limitée | ✅ Implémenté |
| Manipulation Merkle root | Critical | Vérification contre root canonique | ✅ Implémenté |
| Race condition double-spend | High | Atomicité des opérations de claim | ⚠️ À vérifier |

### Repudiation (R)

| Threat | Risk | Mitigation | Status |
|--------|------|------------|--------|
| Négation d'un claim | Low | Logging immuable, nullifier enregistré | ✅ Implémenté |
| Négation d'abus | Medium | Métriques détaillées, alerting | ✅ Implémenté |

### Information Disclosure (I)

| Threat | Risk | Mitigation | Status |
|--------|------|------------|--------|
| Timing attack sur pk_hash | Medium | Comparaisons constant-time via `subtle` crate | ✅ Implémenté |
| Timing attack sur nullifier check | Medium | Recherche constant-time dans le set | ⚠️ À vérifier |
| Fuite du solde faucet | Low | Information publique par design | ✅ Accepté |
| Fuite des wallets ayant claim | Low | Données on-chain publiques | ✅ Accepté |

### Denial of Service (D)

| Threat | Risk | Mitigation | Status |
|--------|------|------------|--------|
| Exhaustion mémoire (grosses preuves) | High | Limites de taille strictes (64KB max) | ✅ Implémenté |
| CPU exhaustion (vérification preuve) | High | Rate limiting global, timeouts | ✅ Implémenté |
| Remplissage du nullifier set | Medium | Coût de claim, purge périodique | ⚠️ À surveiller |
| Slowloris sur endpoint faucet | Medium | Timeouts de connexion, limites de requêtes | ✅ Implémenté |

### Elevation of Privilege (E)

| Threat | Risk | Mitigation | Status |
|--------|------|------------|--------|
| Bypass rate limiting | Critical | Atomicité, validation côté serveur uniquement | ✅ Implémenté |
| Bypass vérification preuve | Critical | Circuit Plonky2 fixe, VK hardcodé | ✅ Implémenté |
| Modification paramètres faucet | Critical | Pas de configuration runtime des paramètres critiques | ✅ Implémenté |

---

## Attack Scenarios

### Scenario 1: Preuve Plonky2 Falsifiée

**Description:** Un attaquant génère une preuve Plonky2 invalide qui passe la validation.

**Impact:** Création illimitée de tokens.

**Étapes d'attaque:**
1. Analyse du circuit Plonky2 utilisé
2. Tentative de génération de preuve sans witness valide
3. Soumission au faucet

**Mitigations:**
- Circuit Plonky2 audité et fixe
- Verification key hardcodée
- Tests de régression pour preuves invalides

**Test de sécurité:** `test_plonky2_proof_verification_rejects_invalid`

---

### Scenario 2: Timing Attack sur pk_hash

**Description:** Un attaquant mesure le temps de réponse pour déduire des informations sur les pk_hash valides.

**Impact:** Énumération des wallets éligibles, préparation d'attaques ciblées.

**Étapes d'attaque:**
1. Mesure du temps de réponse pour différents pk_hash
2. Détection de patterns (early exit vs full validation)
3. Exploitation de la différence

**Mitigations:**
- Utilisation de `subtle::ConstantTimeEq` pour toutes les comparaisons
- Temps de réponse constant quel que soit le résultat
- Padding des réponses pour uniformiser la taille

**Test de sécurité:** `test_pk_hash_comparison_is_constant_time`

---

### Scenario 3: Race Condition Double-Claim

**Description:** Deux requêtes simultanées pour le même wallet passent toutes les deux.

**Impact:** Double paiement, perte de fonds faucet.

**Étapes d'attaque:**
1. Envoi simultané de deux claims depuis le même wallet
2. Timing précis pour interleaving des threads
3. Les deux validations passent avant l'enregistrement

**Mitigations:**
- Atomicité des opérations de claim
- Verrouillage par wallet pendant le traitement
- Vérification finale avant émission du token

**Test de sécurité:** `test_concurrent_claims_are_atomic`

---

### Scenario 4: Sybil Attack Massive

**Description:** Un attaquant crée des milliers de wallets pour maximiser les claims.

**Impact:** Épuisement rapide du faucet.

**Étapes d'attaque:**
1. Génération automatisée de wallets
2. Distribution géographique des requêtes
3. Rotation d'IP pour éviter le rate limiting

**Mitigations:**
- Rate limiting par IP (en plus du wallet)
- Détection de patterns anormaux
- CAPTCHA pour claims suspects
- Cooldown exponentiel pour IPs suspectes

**Test de sécurité:** `test_rate_limiting_enforced`

---

### Scenario 5: Memory Exhaustion

**Description:** Un attaquant envoie des preuves énormes pour causer un OOM.

**Impact:** Crash du nœud, indisponibilité du service.

**Étapes d'attaque:**
1. Création d'une preuve de plusieurs GB
2. Soumission au endpoint faucet
3. Allocation mémoire excessive

**Mitigations:**
- Limite de taille stricte avant parsing (64KB)
- Streaming des données si possible
- Limites de mémoire par connexion

**Test de sécurité:** `test_large_input_handling`

---

## Security Checklist

### Avant chaque release:

- [ ] Tous les tests de sécurité passent
- [ ] Fuzzers exécutés sans crash pendant >24h
- [ ] Pas de `unwrap()` ou `expect()` dans le hot path réseau
- [ ] Comparaisons cryptographiques en temps constant
- [ ] Validations d'entrée complètes (taille, format, plage)
- [ ] Arithmetic vérifiée (pas de underflow/overflow)
- [ ] Tests de concurrence passent (miri si possible)
- [ ] Documentation des changements de sécurité

---

## Vulnerability Registry

| ID | Description | Severity | Status | Discovered | Mitigated |
|----|-------------|----------|--------|------------|-----------|
| FAU-001 | Timing attack potentiel sur pk_hash | Medium | ✅ Fixed | Audit interne | v1.0 |
| FAU-002 | Limite de taille manquante sur preuves | High | ✅ Fixed | Fuzzing | v1.0 |
| FAU-003 | Race condition théorique double-claim | Medium | ⚠️ Monitoring | Review code | - |

---

## References

- [Plonky2 Documentation](https://github.com/0xPolygonZero/plonky2)
- [Subtle Crate - Constant-Time Operations](https://docs.rs/subtle)
- [STRIDE Threat Model](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
