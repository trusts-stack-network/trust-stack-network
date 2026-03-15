# Guide de Sécurité pour les Développeurs TSN

## Règles Critiques

### 1. Interdiction des `unwrap()` et `expect()` dans le code réseau/consensus

**❌ INTERDIT:**
```rust
// Dans handlers réseau, consensus, ou validation
let value = result.unwrap();
let value = result.expect("should never fail");
```

**✅ OBLIGATOIRE:**
```rust
// Utiliser ? pour propager les erreurs
let value = result?;

// Ou gérer explicitement
match result {
    Ok(v) => v,
    Err(e) => {
        tracing::error!("Operation failed: {}", e);
        return Err(e.into());
    }
}
```

### 2. Vérification des bornes systématique

**❌ INTERDIT:**
```rust
let first = vec[0]; // Panic si vide
let slice = &data[start..end]; // Panic si out of bounds
```

**✅ OBLIGATOIRE:**
```rust
let first = vec.first()?; // Option
let first = vec.get(0).ok_or(Error::Empty)?; // Result

// Vérifier les bornes
if end > data.len() {
    return Err(Error::OutOfBounds);
}
let slice = &data[start..end];
```

### 3. Arithmétique vérifiée

**❌ INTERDIT:**
```rust
let sum = a + b; // Peut overflow
let product = a * b;
```

**✅ OBLIGATOIRE:**
```rust
let sum = a.checked_add(b).ok_or(Error::Overflow)?;
let product = a.checked_mul(b).ok_or(Error::Overflow)?;
```

### 4. Parsing sécurisé

**❌ INTERDIT:**
```rust
let num: u64 = s.parse().unwrap();
```

**✅ OBLIGATOIRE:**
```rust
let num: u64 = s.parse().map_err(|e| Error::ParseError(e))?;
```

## Checklist de Review

Avant chaque commit dans les modules critiques:

- [ ] Aucun `unwrap()`/`expect()` non justifié
- [ ] Tous les indexations utilisent `get()` ou sont vérifiés
- [ ] Arithmétique avec `checked_*` dans les hot paths
- [ ] Parsing avec gestion d'erreurs explicite
- [ ] Tests de résilience ajoutés

## Modules Critiques

Les modules suivants nécessitent une attention particulière:

1. **src/crypto/** - Toute panic = compromission possible
2. **src/consensus/** - Panic = fork potentiel
3. **src/network/** - Panic = DoS vector
4. **src/core/validation.rs** - Panic = bloc invalide accepté

## Outils de Vérification

```bash
# Audit des unwraps/expects
grep -rn "\.unwrap()" src/crypto src/consensus src/network
grep -rn "\.expect(" src/crypto src/consensus src/network

# Vérification avec clippy
cargo clippy -- -W clippy::unwrap_used -W clippy::expect_used

# Tests de résilience
cargo test --test panic_regression_test
cargo test --test error_handling_integration
```

## Exemple de Code Sécurisé

```rust
/// Valide une transaction sans jamais paniquer
pub fn validate_transaction(tx: &Transaction) -> Result<ValidationResult, ValidationError> {
    // Vérifier la taille
    if tx.encoded_len() > MAX_TX_SIZE {
        return Err(ValidationError::Oversized);
    }
    
    // Vérifier les inputs
    if tx.inputs.is_empty() {
        return Err(ValidationError::NoInputs);
    }
    
    // Vérifier les montants avec arithmétique sécurisée
    let total_input = tx.inputs
        .iter()
        .try_fold(0u64, |acc, input| {
            acc.checked_add(input.amount)
                .ok_or(ValidationError::AmountOverflow)
        })?;
    
    // Vérifier les signatures
    for (i, input) in tx.inputs.iter().enumerate() {
        let sig = tx.signatures.get(i)
            .ok_or(ValidationError::MissingSignature(i))?;
        
        if !verify_signature(sig, &input.pubkey, &tx.hash)? {
            return Err(ValidationError::InvalidSignature(i));
        }
    }
    
    Ok(ValidationResult::Valid)
}
```

## Contact

Questions de sécurité: security@tsn.network
