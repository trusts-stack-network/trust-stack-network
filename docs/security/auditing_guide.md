# Guide d'Audit Manuel - Code Crypto Rust

## Commandes d'audit

### 1. Analyse statique

### 2. Tests de timing (requires valgrind/perf)

### 3. Fuzzing continu

## Patterns dangereux à détecter

### DANGER: Comparison directe

### DANGER: Branche sur secret

### DANGER: Nonce manuel

## Vérification des dépendances

## Revue de PR - Questions à poser
1. Cette fonction prend-elle des données externes? → Fuzz target ajouté?
2. Y a-t-il une nouvelle comparaison de secrets? → Test CT ajouté?
3. Nouvelle primitive crypto? → Property tests ajoutés?
4. Clés en mémoire? → Zeroize implémenté?