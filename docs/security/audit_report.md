# Rapport d'Audit Sécurité - src/crypto/

## Résumé Exécutif
Date: 2024-01-15
Auditeur: Security Research Team
Scope: Cryptographie symétrique et dérivation de clés

## Findings

### [CRITICAL] F-001: Nonce Generation Non-Atomic
**Fichier**: `src/crypto/aead.rs:45`
**Description**: La génération de nonce utilise `rand::thread_rng()` sans verrou atomique, risque de collision sous forte charge.
**Preuve**: Voir `tests/regression_tests.rs::test_nonce_collision_resistance`
**Correction**: Utiliser `AtomicU64` + random 128-bit

### [HIGH] F-002: MAC Comparison Variable-Time
**Fichier**: `src/crypto/aead.rs:89`
**Description**: Comparaison de tag via `==` standard (optimisé par LLVM)
**Impact**: Timing attack possible sur les 16 premiers octets
**Correction**: `subtle::ConstantTimeEq` requis

### [HIGH] F-003: Secret Key Material in Swap
**Fichier**: `src/crypto/kdf.rs`
**Description**: Clés dérivées stockées en `Vec<u8>` sans `mlock`
**Impact**: Extraction via swap/partition de swap
**Correction**: Utiliser `secrets::SecretBox` ou `memsec::mlock`

### [MEDIUM] F-004: Insufficient KDF Iterations
**Fichier**: `src/crypto/kdf.rs:23`
**Description**: Argon2 paramétré avec m=8KB, trop faible pour résistance GPU
**Correction**: m >= 64MB, t >= 3

### [LOW] F-005: RNG Seed Reuse in Tests
**Fichier**: `tests/` (multiples)
**Description**: Tests utilisent seed fixe, masque potentiellement des bugs
**Correction**: Proptest avec seeds aléatoires + replay

## Recommandations

1. **Hardening Constant-Time**: Vérifier assembly généré pour comparaisons
2. **Fuzzing Continu**: Intégrer `cargo-fuzz` dans CI/CD
3. **Formal Verification**: Considérer `saw` ou `cryptol` pour primitives critiques
4. **Documentation**: Ajouter warnings de sécurité sur tous les exports publiques