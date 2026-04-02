# Corrections des Unwraps/Expects Critiques

**Date:** Mars 2026  
**Auteur:** Marcus.R (Security & QA Engineer)  
**Statut:** EN COURS  
**Sévérité:** CRITIQUE

## Résumé Exécutif

Ce document suit les corrections des unwraps/expects critiques identifiés dans le codebase TSN. Ces corrections sont essentielles pour garantir la stabilité du nœud en production et prévenir les attaques DoS.

## Unwraps/Expects Identifiés et Corrigés

### 1. src/consensus/validation.rs:64

**Code problématique:**
```rust
let current_time = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs();
```

**Risque:** Si l'horloge système est avant l'epoch Unix (1970), le code panique.

**Correction proposée:**
```rust
let current_time = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or(Duration::from_secs(0))
    .as_secs();
```

**Statut:** ⏳ EN ATTENTE DE CORRECTION

---

### 2. src/crypto/poseidon.rs:41

**Code problématique:**
```rust
let poseidon = Poseidon::<Fr>::new_circom(n_inputs)
    .expect("Poseidon init failed");
```

**Risque:** Panique si le nombre d'inputs est invalide.

**Correction proposée:**
```rust
let poseidon = Poseidon::<Fr>::new_circom(n_inputs)
    .map_err(|e| ValidationError::PoseidonInitFailed(e))?;
```

**Statut:** ⏳ EN ATTENTE DE CORRECTION

---

### 3. src/crypto/poseidon.rs:47

**Code problématique:**
```rust
let hash = poseidon.hash(&all_inputs)
    .expect("Poseidon hash failed");
```

**Risque:** Panique si le hash échoue.

**Correction proposée:**
```rust
let hash = poseidon.hash(&all_inputs)
    .map_err(|e| ValidationError::PoseidonHashFailed(e))?;
```

**Statut:** ⏳ EN ATTENTE DE CORRECTION

---

### 4. src/crypto/poseidon.rs:90

**Code problématique:**
```rust
let inv = sum.inverse()
    .expect("Cauchy matrix construction");
```

**Risque:** Panique si l'inverse n'existe pas (sum = 0).

**Correction proposée:**
```rust
let inv = sum.inverse()
    .ok_or(ValidationError::CauchyMatrixConstructionFailed)?;
```

**Statut:** ⏳ EN ATTENTE DE CORRECTION

---

### 5. src/crypto/keys.rs:20

**Code problématique:**
```rust
let (pk, sk) = ml_dsa_65::try_keygen()
    .expect("RNG failure");
```

**Risque:** Panique si le RNG échoue.

**Correction proposée:**
```rust
let (pk, sk) = ml_dsa_65::try_keygen()
    .map_err(|e| KeyError::RngFailed(e))?;
```

**Statut:** ⏳ EN ATTENTE DE CORRECTION

---

### 6. src/network/api.rs:67

**Code problématique:**
```rust
let rate_limiter = RateLimiter::new(config)
    .expect("Failed to build rate limiter config");
```

**Risque:** Panique si la config est invalide.

**Correction proposée:**
```rust
let rate_limiter = RateLimiter::new(config)
    .unwrap_or_else(|_| create_default_rate_limiter());
```

**Statut:** ⏳ EN ATTENTE DE CORRECTION

---

## Tests de Régression

Les tests suivants ont été créés pour vérifier les corrections:

1. `tests/panic_regression_test.rs` - Tests unitaires pour chaque unwrap corrigé
2. `fuzz/fuzz_targets/critical_unwrap_fuzzer.rs` - Fuzzer dédié aux unwraps critiques

## Checklist de Validation

- [ ] Correction appliquée à src/consensus/validation.rs:64
- [ ] Correction appliquée à src/crypto/poseidon.rs:41
- [ ] Correction appliquée à src/crypto/poseidon.rs:47
- [ ] Correction appliquée à src/crypto/poseidon.rs:90
- [ ] Correction appliquée à src/crypto/keys.rs:20
- [ ] Correction appliquée à src/network/api.rs:67
- [ ] Tests de régression passent
- [ ] Fuzzer critical_unwrap passe sans panic
- [ ] cargo check passe sans erreurs
- [ ] cargo test passe sans erreurs

## Notes de Sécurité

1. **Ne jamais utiliser unwrap() ou expect() dans le code réseau**
2. **Toujours préférer Result<T, E> pour les opérations qui peuvent échouer**
3. **Utiliser unwrap_or(), unwrap_or_else(), ou ? pour la propagation d'erreurs**
4. **Documenter les invariants qui justifient un unwrap avec SAFETY comments**

## Références

- [PANIC_AUDIT.md](./PANIC_AUDIT.md) - Audit complet des panics
- [UNWRAP_AUDIT.md](./UNWRAP_AUDIT.md) - Audit des unwraps
- [THREAT_MODEL.md](./THREAT_MODEL.md) - Modèle de menaces TSN
