# Modèle de Menaces - Module Cryptographique

## Scope
Module `src/crypto/` : chiffrement symétrique, MAC, dérivation de clés, gestion de secrets.

## Acteurs et Assets
- **Assets**: Clés privées, mots de passe, données chiffrées, nonces/IVs
- **Attaquants**: 
  - Local (accès mémoire, cache, timing)
  - Réseau (manipulation ciphertexts)
  - Physique (cold boot, DMA)

## Vecteurs d'Attaque Identifiés

### 1. Timing Attacks (HIGH)
- **Description**: Mesure du temps d'exécution pour dériver des secrets
- **Cibles**: Comparaison de HMACs, boucles sur secrets, lookup tables
- **Mitigations**: Opérations constant-time (`subtle`), pas de branchement sur secrets

### 2. Memory Side-Channels (HIGH)
- **Description**: Exposition des clés en mémoire (swap, core dumps, heap inspection)
- **Mitigations**: `zeroize`, allocation verrouillée (memsec), minimisation temps de vie

### 3. Padding Oracle (CRITICAL)
- **Description**: Déchiffrement CBC avec validation de padding information leak
- **Mitigations**: Utiliser AEAD (AES-GCM/ChaCha20-Poly1305), pas de padding manuel

### 4. Nonce Reuse (CRITICAL)
- **Description**: Réutilisation de IV avec CTR/GCM mode
- **Mitigations**: Génération aléatoire 96-bit (GCM) ou compteur atomique

### 5. RNG Predictability (CRITICAL)
- **Description**: Mauvaise source d'entropie pour génération clés
- **Mitigations**: `getrandom` / `rand::rngs::OsRng` uniquement

### 6. Cache Timing via Lookup Tables (MEDIUM)
- **Description**: Tables S-box indexées par secret (AES software impl)
- **Mitigations**: Implémentations constant-time ou hardware AES-NI

## Hypothèses de Sécurité
- Le système d'exploitation protège l'espace mémoire des processus
- `getrandom` fournit de l'entropie système véritable
- L'attaquant ne peut pas lire les registres CPU pendant l'exécution (mais peut mesurer le temps)

## Checklist d'Audit
- [ ] Aucune comparaison de secrets avec `==`
- [ ] Pas de `if secret[index] == value`
- [ ] Zeroization explicite des clés
- [ ] Vérification des bounds avant opérations crypto
- [ ] RNG seeding non manuel (pas de `FromEntropy` prévisible)