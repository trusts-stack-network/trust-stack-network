# Audit sécurité – Module crypto de TSN
Date: 2024-12-19  
Auditeur: Marcus.R  
Version cible: commit HEAD (`src/crypto/`)

## 1. Surface d’attaque principale
- Clés privées ML-DSA-65 (FIPS-204) : génération, stockage en mémoire, zeroisation
- Signatures produites/consommées via RPC (JSON) → entrées adversariales
- Hashes Poseidon2 : collisions, paramètres de domaine
- Commitments/nullifiers : double-spend, recompute attacks
- Merkle proofs : leaf, index, root forgery
- RNG ChaCha20Rng : sécurité et reseed côté WASM (wallet)

## 2. Menaces identifiées

| ID  | Menace | Impact | Probabilité | Gravité | Statut |
|-----|--------|--------|-------------|---------|--------|
| T1  | Signature malleability ML-DSA | High | Medium | High | Open |
| T2  | Timing leak comparaison clés publiques | Medium | Low | Medium | Open |
| T3  | Panic sur slice malformé côté proof decode | High | High | High | Open |
| T4  | Overflow index Merkle tree | Medium | Medium | Medium | Open |
| T5  | Zeroisation mémoire clé privée non garantie | High | Low | High | Open |

## 3. Recommandations immédiates

1. Implémenter fonction `compare_public_key_ct(a: &MlDsaPublicKey, b: &MlDsaPublicKey) -> bool` en constant-time (crate `subtle`)
2. Faire `cargo-fuzz` cibler tous les `TryFrom<Vec<u8>>` de messages réseau
3. Remplacer tous les `.unwrap()` dans les parsers par `Result` propagent l’erreur
4. Ajouter vérification que `index < 2^depth` dans `merkle_tree.rs`
5. Utiliser `zeroize` crate + `#[derive(ZeroizeOnDrop)]` sur toute structure contenant une clé privée
6. Documenter vecteurs de test connus pour Poseidon2 (paramètres, domaine, round constants)

## 4. Tests de régression requis
- Signature malleability: vérifier qu’une signature modifiée échoue
- Overflow: `2^32` feuilles → doit échouer proprement
- Chaîne de 1 million de messages RPC malformés → pas de panic, pas de DoS
- Constant-time: pas de différence mesurable > 5 ns entre comparaisons

## 5. Références
- FIPS 204 (Draft) – ML-DSA
- RFC 8439 – ChaCha20-Poly1305
- Poseidon2 paper – ePrint 2023/323
- STRIDE – Microsoft Security Development Lifecycle