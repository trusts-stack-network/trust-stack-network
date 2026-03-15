# Audit des unwraps/panics dans le codebase TSN

**Date:** 2024  
**Scope:** src/core, src/consensus, src/crypto, src/network  
**Severity:** HIGH - Risques de crash en production

---

## Résumé exécutif

Ce document recense les **unwraps/expects/panics non justifiés** dans le code critique de TSN. Chaque entrée est évaluée selon :
- **Impact:** Crash potentiel en production
- **Exploitabilité:** Peut un attaquant déclencher ce panic ?
- **Mitigation:** Comment remplacer par une gestion d'erreur propre

---

## 🔴 CRITIQUE - unwraps dans le hot path réseau/consensus

### 1. `src/consensus/validation.rs:64`
```rust
let current_time = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()  // ← PANIC si horloge < 1970
    .as_secs();
```
- **Impact:** Nœud crash si horloge système erronée
- **Exploitabilité:** INDIRECT - requiert compromission horloge système
- **Mitigation:** Remplacer par `unwrap_or(0)` ou gestion d'erreur explicite
- **Test:** `tests/panic_audit_test.rs::test_timestamp_validation_graceful`

### 2. `src/network/api.rs:67`
```rust
.expect("Failed to build rate limiter config")
```
- **Impact:** Panic au démarrage si config invalide
- **Exploitabilité:** DIRECT - fichier de config malformé = DoS
- **Mitigation:** Propager l'erreur avec `?` au lieu de panic

---

## 🟠 HAUTE - unwraps dans la crypto

### 3. `src/crypto/keys.rs:20`
```rust
ml_dsa_65::try_keygen().expect("RNG failure");
```
- **Impact:** Panic si RNG système échoue
- **Exploitabilité:** FAIBLE - RNG failure = condition système critique
- **Mitigation:** Retourner `Result` au lieu de panic

### 4. `src/crypto/secure.rs:30`
```rust
getrandom::getrandom(&mut bytes).expect("RNG failure");
```
- **Impact:** Même risque que #3
- **Mitigation:** Propager l'erreur via `Result`

### 5. `src/crypto/poseidon.rs:41,47,90`
```rust
Poseidon::<Fr>::new_circom(n_inputs).expect("Poseidon init failed");
poseidon.hash(&all_inputs).expect("Poseidon hash failed")
matrix[i][j] = sum.inverse().expect("Cauchy matrix construction");
```
- **Impact:** Panic sur entrées invalides
- **Exploitabilité:** DIRECT - entrées contrôlables par l'attaquant
- **Mitigation:** Tous ces expects doivent devenir des `Result`

### 6. `src/crypto/secure_impl.rs:70`
```rust
.expect("Argon2 failed")
```
- **Impact:** Panic sur dérivation de clé
- **Exploitabilité:** DIRECT - paramètres Argon2 malformés
- **Mitigation:** Retourner `Result`

---

## 🟡 MOYENNE - unwraps dans les métriques/logging

### 7. `src/metrics/mod.rs:204`
```rust
.expect("Impossible d'initialiser les métriques consensus")
```
- **Impact:** Panic au démarrage
- **Exploitabilité:** INDIRECT
- **Mitigation:** Log d'erreur + continuation sans métriques

---

## ✅ ACCEPTABLE - unwraps dans les tests

Les unwraps dans `src/storage/db.rs`, `src/storage/mik_storage.rs` et `src/network/tests/` sont **acceptables** car ils sont dans :
- Des fonctions de test (`#[test]`)
- Du code d'initialisation de test
- Des assertions de test

Ces unwraps ne sont pas exécutés en production.

---

## Recommandations

### Priorité 1 (Immédiat)
1. Corriger `validation.rs:64` - SystemTime unwrap
2. Corriger `poseidon.rs` - tous les expects crypto
3. Corriger `api.rs:67` - config rate limiter

### Priorité 2 (Cette semaine)
4. Corriger `keys.rs`, `secure.rs`, `secure_impl.rs` - RNG failures
5. Corriger `metrics/mod.rs:204` - init métriques

### Priorité 3 (Prochain sprint)
6. Ajouter `clippy::unwrap_used` lint dans CI
7. Fuzzer tous les parsers avec entrées externes

---

## Tests de régression

Voir `tests/panic_audit_test.rs` pour les tests qui vérifient :
- Aucun panic sur entrées malformées
- Gestion gracieuse des erreurs système
- Comportement défini sur conditions limites
