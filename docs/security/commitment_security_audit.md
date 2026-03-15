# Audit de sécurité: Module commitment.rs

## Date: 2024-01-XX
## Auditeur: Marcus.R (Security & QA Engineer)
## Statut: EN COURS - VULNÉRABILITÉS CRITIQUES IDENTIFIÉES

## Résumé exécutif

Le module `commitment.rs` présente plusieurs vulnérabilités critiques qui compromettent les propriétés de sécurité fondamentales des commitments cryptographiques. Une refonte majeure est nécessaire avant toute mise en production.

## Vulnérabilités identifiées

### 1. CRITIQUE - Timing Attack sur la comparaison
**Localisation**: `verify()` utilise l'opérateur `==` non constant-time

**Impact**: Un attaquant peut déduire le contenu du commitment en mesurant le temps de vérification

**Preuve de concept**:

**Mitigation**: Implémenter `ConstantTimeEq` de la crate `subtle`

### 2. HIGH - Absence de sel unique (Collision attacks)
**Localisation**: `new()` n'utilise pas de sel

**Impact**: Deux mêmes valeurs produisent le même commitment → violations de la propriété de hiding

**Scénario d'attaque**:
1. Alice envoie un commitment pour "BID_100"
2. Bob peut deviner qu'Alice a fait une enchère de 100
3. Bob peut créer un commitment identique sans connaître le secret

**Mitigation**: Toujours utiliser un sel cryptographiquement aléatoire

### 3. MEDIUM - DoS par overflow de taille
**Localisation**: Aucune vérification de la taille d'entrée

**Impact**: Un attaquant peut créer des commitments avec des entrées de plusieurs GB

**Mitigation**: Limiter `MAX_INPUT_SIZE` à 1MB

### 4. LOW - Zeroize incomplet
**Localisation**: Le `Drop` n'appelle pas automatiquement `zeroize`

**Impact**: Les secrets peuvent rester en mémoire après libération

## Tests de régression

Les tests suivants DOIVENT passer après correction:

1. `test_commitment_timing_attack_resistance` - Vérifie la résistance aux timing attacks
2. `test_commitment_binding_property` - Vérifie la propriété de binding
3. `test_commitment_hiding_property` - Vérifie la propriété de hiding
4. `test_commitment_collision_resistance` - Vérifie la résistance aux collisions

## Recommandations

### Immédiates (AVANT RELEASE)
1. Remplacer `PartialEq` par `ConstantTimeEq`
2. Ajouter un paramètre de sel obligatoire
3. Limiter la taille d'entrée à 1MB maximum
4. Ajouter des tests de fuzzing intensifs

### Futures
1. Considérer l'utilisation de Pedersen commitments pour des propriétés plus fortes
2. Ajouter un domain separator par type d'usage
3. Implémenter des commitments vectoriels pour des ensembles de données

## Menaces documentées

### Adversaire Type I - Observer passif
- **Capacités**: Peut observer tous les commitments sur le réseau
- **Objectif**: Corréler commitments avec des valeurs connues
- **Mitigation**: Sels uniques par commitment

### Adversaire Type II - Actif limité
- **Capacités**: Peut créer des commitments et mesurer les temps de vérification
- **Objectif**: Extraire des informations sur des commitments secrets
- **Mitigation**: Comparaison constant-time

### Adversaire Type III - Malicieux
- **Capacités**: Contrôle des entrées, peut créer des collisions
- **Objectif**: Violer les propriétés de binding/hiding
- **Mitigation**: Hash domain-separated avec sel

## Statut des corrections

- [ ] Timing attack corrigé
- [ ] Sel obligatoire implémenté
- [ ] Limites de taille ajoutées
- [ ] Tests de fuzzing écrits
- [ ] Documentation de menace complétée
- [ ] Audit par pair review effectué

## Références
- [RFC-8439: ChaCha20-Poly1305](https://tools.ietf.org/html/rfc8439)
- [subtle crate documentation](https://docs.rs/subtle/)
- [zeroize crate documentation](https://docs.rs/zeroize/)