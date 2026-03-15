# Rapport d'Audit : Unwraps/Panics dans le Codebase TSN

**Date:** Audit de sécurité - Phase 1  
**Auditeur:** Marcus.R (Security & QA Engineer)  
**Scope:** Modules core, consensus, crypto, network, storage  
**Statut:** 🔴 CRITIQUE - Corrections requises avant production

---

## Résumé Exécutif

L'analyse du codebase a révélé **plusieurs unwraps/expects critiques** dans les chemins de code production qui peuvent provoquer des panics et des arrêts de nœud. Ces vulnérabilités sont particulièrement dangereuses car elles peuvent être déclenchées par des pairs malveillants via le réseau.

### Classification des Risques

| Sévérité | Compte | Description |
|----------|--------|-------------|
| 🔴 **CRITIQUE** | 3 | Panic déclenchable par réseau (DoS) |
| 🟠 **HAUTE** | 2 | Panic sur opérations cryptographiques |
| 🟡 **MOYENNE** | 1 | Panic sur opérations temporelles |

---

## Vulnérabilités Critiques Identifiées

### 1. [CRITIQUE] RwLock Poisoning dans `sync.rs` et `api.rs`

**Fichiers concernés:**
- `src/network/sync.rs` (lignes 36, 91, 108, 141)
- `src/network/api.rs` (lignes 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90)

**Code problématique:**
```rust
let chain = state.blockchain.read().unwrap();
let mut chain = state.blockchain.write().unwrap();
```

**Impact:**
- Un thread qui panique alors qu'il détient un verrou en écriture "empoisonne" le verrou
- Tous les threads suivants qui tentent d'acquérir le verrou paniquent également
- Résultat : crash en cascade de tout le nœud

**Attaque potentielle:**
1. Un attaquant envoie un message réseau malformé qui provoque un panic dans un handler
2. Le handler détient le verrou blockchain en écriture au moment du panic
3. Le verrou est empoisonné
4. Tous les autres handlers qui tentent d'accéder à la blockchain paniquent
5. Le nœud devient complètement inopérant (DoS total)

**Mitigation:**
Remplacer `.unwrap()` par `.unwrap_or_else(|_| RwLock::new(...))` ou gérer proprement le poison:
```rust
let chain = state.blockchain.read().unwrap_or_else(|poisoned| poisoned.into_inner());
```

---

### 2. [HAUTE] RNG Failure dans `keys.rs`

**Fichier:** `src/crypto/keys.rs` (ligne 25)

**Code problématique:**
```rust
let (public_key, secret_key) = ml_dsa_65::try_keygen().expect("RNG failure");
```

**Impact:**
- Panic si la génération de clés échoue (RNG indisponible, erreur système)
- Interruption complète du wallet/minage

**Mitigation:**
Retourner un `Result` et propager l'erreur:
```rust
pub fn generate() -> Result<Self, KeyError> {
    let (public_key, secret_key) = ml_dsa_65::try_keygen()
        .map_err(|_| KeyError::RngFailure)?;
    Ok(Self { public_key, secret_key })
}
```

---

### 3. [MOYENNE] SystemTime avant UNIX_EPOCH dans `pow.rs`

**Fichier:** `src/consensus/pow.rs` (lignes 47-48, 169-170)

**Code problématique:**
```rust
.duration_since(std::time::UNIX_EPOCH)
.unwrap()
```

**Impact:**
- Panic si l'horloge système est réglée avant 1970 (rare mais possible)
- Interruption du minage

**Mitigation:**
Utiliser `unwrap_or(0)` ou gérer l'erreur:
```rust
.duration_since(std::time::UNIX_EPOCH)
.unwrap_or(Duration::from_secs(0))
.as_secs()
```

---

## Recommandations

### Priorité Immédiate (avant release)

1. **Corriger tous les unwraps sur RwLock** dans les modules réseau
2. **Remplacer expect("RNG failure")** par un Result propre
3. **Ajouter des tests de régression** pour chaque correction

### Bonnes Pratiques à Adopter

1. **Interdiction stricte** de `.unwrap()` et `.expect()` dans le code production
2. **Utilisation obligatoire** de `Result` avec propagation d'erreurs
3. **Fuzzing systématique** des parsers réseau avec cargo-fuzz
4. **Tests property-based** avec proptest pour les invariants

---

## Tests de Régression

Des tests spécifiques doivent être créés pour:
1. Vérifier la résilience aux messages réseau malformés
2. Tester le comportement lorsqu'un verrou est empoisonné
3. Valider la gestion des erreurs RNG

Voir `tests/security/unwrap_regression_tests.rs` pour l'implémentation.

---

## Conclusion

Les unwraps/expects identifiés représentent des **vulnérabilités DoS exploitables**. La correction prioritaire des RwLock dans les modules réseau est **impérative** avant toute mise en production.

**Statut:** 🔴 **BLOCANT** - Merge interdit sans corrections

---

*Document généré dans le cadre de l'audit de sécurité TSN*  
*Classification: INTERNAL USE ONLY*
