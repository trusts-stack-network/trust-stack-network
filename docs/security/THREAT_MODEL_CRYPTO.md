# Modèle de Menaces - Module Cryptographique TSN

## Vue d'Ensemble
Ce document définit le modèle de menaces pour le module cryptographique de Trust Stack Network, incluant les hypothèses de sécurité, les capacités de l'adversaire, et les mitigations en place.

## Hypothèses de Menace

### Modèle d'Adversaire
- **Capacités**: L'adversaire peut:
  - Observer tous les messages réseau
  - Mesurer les temps d'exécution avec précision microseconde
  - Soumettre des inputs malveillants via l'API
  - Accéder au code source (modèle white-box)

- **Limitations**: L'adversaire ne peut pas:
  - Accéder aux clés privées stockées en mémoire sécurisée
  - Modifier le code en production
  - Forcer des reboots arbitraires

### Surfaces d'Attaque

#### 1. Timing Attacks
**Vecteur**: Comparaison non-constant-time dans verify_signature()
**Impact**: Récupération de clé privée via analyse temporelle
**État**: VULNÉRABLE - Voir test `test_signature_timing_attack_resistance`
**Mitigation: Implémenter `constant_time_eq()` pour toutes les comparaisons cryptographiques

#### 2. Side-Channel Attacks
**Vecteur**: Cache-timing sur les opérations de hash
**Impact**: Inférence d'information sur les inputs secrets
**État**: PARTIELLEMENT PROTÉGÉ - Voir test `test_cache_timing_resistance`
**Mitigation**: Utiliser des opérations constant-time, ajouter du bruit

#### 3. Fault Injection
**Vecteur**: Inputs malformés dans les parsers
**Impact**: Panic, DoS, potentiellement exécution arbitraire
**État**: PARTIELLEMENT PROTÉGÉ - Fuzzing en place
**Mitigation**: Validation stricte des inputs, tests de robustesse

## Vulnérabilités Actives

### CRITIQUE-001: Timing Attack sur Signature
**Fichier**: `src/crypto/signature.rs:127`
**Description**: La comparaison de signature utilise `==` au lieu de `constant_time_eq`
**CVSS**: 7.5 (High)
**Status**: Non patché
**Test**: `tests/crypto/timing_attacks_test.rs`

### HIGH-001: Validation de Clé Publique
**Fichier**: `src/crypto/keys.rs:89`
**Description**: Aucune validation que le point est sur la courbe
**Impact**: Attaque de clé invalide pouvant mener à des signatures forgées
**Status**: Non patché
**Test**: `tests/crypto/invalid_key_test.rs`

### MEDIUM-001: Entropie PRNG
**Fichier**: `src/crypto/pq/dilithium.rs`
**Description**: Utilisation de `thread_rng()` au lieu de `OsRng` pour la génération de clés
**Impact**: Potentielle prédictibilité des clés
**Status**: Non patché

## Recommandations

### Immédiates (1 semaine)
1. Remplacer toutes les comparaisons cryptographiques par `constant_time_eq`
2. Ajouter la validation de points de courbe pour les clés publiques
3. Passer à `OsRng` pour toute génération de clés cryptographiques

### À court terme (1 mois)
1. Implémenter des compteurs de protection contre les timing attacks
2. Ajouter du bruit artificiel dans les opérations sensibles
3. Documenter tous les algorithmes non-constant-time

### À long terme (3 mois)
1. Audit externe du module crypto par des experts en side-channels
2. Certification FIPS 140-3 du module de signature
3. Implémentation d'un HSM logiciel pour la protection des clés