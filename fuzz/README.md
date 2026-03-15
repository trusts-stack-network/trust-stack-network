# TSN Fuzzing Suite - Chasse aux Panics

**Auteur**: Marcus.R (Security & QA Engineer)  
**Objectif**: Détecter les vulnérabilités critiques dans les désérialiseurs TSN

## 🎯 Vue d'ensemble

Cette suite de fuzzers ultra-agressifs est conçue pour détecter les **panics non gérés** dans les désérialiseurs de transactions et blocs TSN. Chaque panic détecté indique une **vulnérabilité critique** qui pourrait être exploitée par un attaquant pour crasher des nœuds du réseau.

### 🚨 Règle absolue
**Aucun désérialiseur ne doit jamais paniquer**, même avec des données complètement corrompues ou malveillantes. Tout panic = vulnérabilité à corriger immédiatement.

## 🔧 Fuzzers implémentés

### 1. `panic_hunter_deserialize.rs`
**Fuzzer principal ultra-agressif**

- **Stack overflow** : Structures imbriquées infiniment
- **Integer overflow** : Valeurs proches de MAX/MIN
- **Memory exhaustion** : Allocations massives
- **Corrupted lengths** : Longueurs incohérentes
- **Malformed signatures** : Signatures crypto corrompues
- **Timing attacks** : Mesure des variations temporelles
- **Hybrid V1/V2** : Mélange des versions de protocole
- **Boundary conditions** : Valeurs limites des types
- **Recursion bombs** : Références circulaires
- **Null pointer deref** : Conditions de déréférencement null

### 2. `deserialize_property_fuzzer.rs`
**Property-based testing pour invariants**

- **Idempotence** : `deserialize(serialize(x)) == x`
- **Déterminisme** : Résultats reproductibles
- **Robustesse** : Résistance aux données corrompues
- **Business invariants** : Respect des règles métier
- **Security properties** : Propriétés de sécurité

### 3. `network_deserialize_fuzzer.rs`
**Fuzzer spécialisé réseau**

- **Malformed messages** : Messages réseau corrompus
- **Oversized payloads** : Attaques DoS par taille
- **Protocol confusion** : Mélange de protocoles
- **Message fragmentation** : Messages partiels
- **Timing attacks** : Fuites temporelles réseau
- **Memory exhaustion** : Épuisement mémoire via réseau

## 🚀 Utilisation

### Installation des dépendances
```bash
# Installer cargo-fuzz
cargo install cargo-fuzz

# Installer GNU parallel (optionnel, pour parallélisation)
sudo apt-get install parallel  # Ubuntu/Debian
brew install parallel          # macOS
```

### Lancement rapide
```bash
# Lancer tous les fuzzers pendant 5 minutes
cd fuzz/
chmod +x run_panic_hunters.sh
./run_panic_hunters.sh
```

### Lancement personnalisé
```bash
# Fuzzing plus long (30 minutes par fuzzer)
FUZZ_TIME=1800 ./run_panic_hunters.sh

# Plus de jobs parallèles
PARALLEL_JOBS=8 ./run_panic_hunters.sh

# Fuzzer individuel
cargo fuzz run panic_hunter_deserialize --release -- -max_len=1048576
```

### Analyse des résultats
```bash
# Voir les logs détaillés
ls fuzz_logs/
cat fuzz_logs/panic_hunter_deserialize.log

# Examiner les artefacts de crash
ls fuzz_results/
hexdump -C fuzz_results/panic_hunter_deserialize_artifacts/crash-*
```

## 📊 Interprétation des résultats

### ✅ Résultat normal
```
✅ panic_hunter_deserialize: Terminé normalement (timeout)
✅ Aucune vulnérabilité critique détectée
```

### 🚨 Vulnérabilité détectée
```
🚨 panic_hunter_deserialize: PANIC DÉTECTÉ - VULNÉRABILITÉ CRITIQUE!
   Voir les détails dans: fuzz_logs/panic_hunter_deserialize.log
   Artefacts sauvés dans: fuzz_results/panic_hunter_deserialize_artifacts/
```

**Action requise** : Analyser immédiatement le panic et corriger la vulnérabilité.

## 🔍 Types de vulnérabilités ciblées

### Panics critiques
- `unwrap()` sur `None` ou `Err`
- `expect()` avec condition non respectée
- Index out of bounds
- Integer overflow/underflow non géré
- Stack overflow par récursion

### Attaques DoS
- Allocation mémoire excessive
- Parsing infiniment lent
- Boucles infinies
- Structures récursives

### Vulnérabilités crypto
- Signatures malformées acceptées
- Timing attacks sur vérification
- Clés publiques invalides
- Preuves ZK corrompues

### Attaques réseau
- Messages oversized
- Fragmentation malveillante
- Confusion de protocole
- Injection de données

## 🛠️ Développement de nouveaux fuzzers

### Structure d'un fuzzer
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    data: Vec<u8>,
    // ... paramètres d'attaque
}

fuzz_target!(|input: FuzzInput| {
    // Protection anti-panic globale
    let result = std::panic::catch_unwind(|| {
        // Code de test
    });
    
    if let Err(panic_info) = result {
        panic!("VULNERABILITY DETECTED: {}", extract_panic_message(panic_info));
    }
});
```

### Bonnes pratiques
1. **Toujours** wrapper dans `catch_unwind()`
2. **Mesurer** les temps d'exécution (détection DoS)
3. **Limiter** les allocations mémoire du fuzzer
4. **Documenter** chaque type d'attaque testé
5. **Utiliser** `arbitrary::Arbitrary` pour la génération de données

## 📋 Checklist de sécurité

Avant chaque release, vérifier que :

- [ ] Tous les fuzzers passent sans panic (5+ minutes chacun)
- [ ] Aucun timeout de parsing > 100ms pour des inputs < 1MB
- [ ] Aucune allocation > 100MB pour des inputs < 10MB
- [ ] Variance temporelle < 50ms entre inputs similaires
- [ ] Tous les invariants métier respectés
- [ ] Pas de regression sur les vulnérabilités connues

## 🔗 Intégration CI/CD

```yaml
# .github/workflows/fuzz.yml
name: Security Fuzzing
on: [push, pull_request]

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz
      - name: Run panic hunters
        run: |
          cd fuzz
          FUZZ_TIME=60 ./run_panic_hunters.sh
```

## 📚 Références

- [libFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)
- [cargo-fuzz Book](https://rust-fuzz.github.io/book/)
- [Arbitrary Crate](https://docs.rs/arbitrary/)
- [TSN Security Model](../docs/security/SECURITY.md)

---

**⚠️ IMPORTANT** : Ce fuzzing ne remplace pas un audit de sécurité complet. Il s'agit d'un outil de détection automatisée des vulnérabilités les plus critiques.