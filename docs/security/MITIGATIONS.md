# Guide des Mitigations Cryptographiques

## 1. Constant-Time Operations

### Principe
Les opérations sur données sensibles (clés, plaintexts internes) doivent s'exécuter en temps constant indépendamment des valeurs.

### Implémentation Rust


### Vérification

Utiliser `dudect` (Distinguishing Attack using Differential Testing) :


## 2. RSA Blinding

Protection contre timing attacks sur déchiffrement RSA.


## 3. ECDSA Nonce Reuse Prevention


## 4. Memory Zeroization
