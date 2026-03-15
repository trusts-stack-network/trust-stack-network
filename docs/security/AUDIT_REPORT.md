# Rapport d'Audit Sécurité - src/crypto/

## Résumé exécutif
Date: 2024
Auditeur: Security Research Team
Scope: Chiffrement symétrique, dérivation de clé, authentification

## Vulnérabilités critiques

### 1. Timing Attack sur vérification MAC (CRITIQUE)
**Fichier**: `src/crypto/auth.rs:45`
**Problème**: Utilisation de `==` pour comparer les tags MAC
**Impact**: Falsification de MAC par mesure de temps (attaque par oracle de timing)
**Preuve**: Voir `tests/timing_attack_tests.rs::test_mac_timing_leak`

### 2. Comparaison de secrets non-constant-time (CRITIQUE)
**Fichier**: `src/crypto/utils.rs:12`
**Problème**: Comparaison byte-à-byte court-circuitée
**Impact**: Attaque par canal auxiliaire sur la clé

### 3. Génération de nonce prévisible (HAUTE)
**Fichier**: `src/crypto/cipher.rs:30`
**Problème**: `rand::thread_rng()` utilisé pour nonces
**Impact**: Réutilisation de nonce possible → compromission du flux chiffré

### 4. Pas d'effacement mémoire (MOYENNE)
**Fichier**: Tous les fichiers
**Problème**: Clés restent en mémoire après drop
**Impact**: Dump mémoire récupère les clés

### 5. Dérivation de clé faible (HAUTE)
**Fichier**: `src/crypto/kdf.rs`
**Problème**: PBKDF2 avec 1000 iterations seulement
**Impact**: Brute-force efficace sur GPUs

## Recommandations immédiates

1. Remplacer toutes les comparaisons par `subtle::ConstantTimeEq`
2. Implémenter `Zeroize` sur toutes les structures contenant des clés
3. Utiliser `OsRng` pour la génération cryptographique
4. Augmenter les iterations PBKDF2 à 600k minimum ou migrer vers Argon2id
5. Ajouter des tests de régression pour chaque vulnérabilité identifiée