# Audit Sécurité - Findings

## CRITICAL-001: Nonce Reuse Vulnerability
**Fichier**: `src/crypto/aead.rs:45`
**Problème**: Counter non atomique, race condition possible en concurrence
**Impact**: Break confidentiality (XOR keystream recovery)
**Fix**: `AtomicU64` + `Ordering::SeqCst`

## HIGH-001: Timing Leak in MAC Verification  
**Fichier**: `src/crypto/utils.rs:12`
**Problème**: Utilisation de `==` sur slice pour MAC comparison
**Impact**: Padding oracle / MAC forgery via timing analysis
**Fix**: `subtle::constant_time_eq`

## HIGH-002: Insufficient Key Derivation
**Fichier**: `src/crypto/kdf.rs`
**Problème**: PBKDF2 avec 1000 itérations (OWASP recommande 600k+)
**Impact**: Brute force rapide sur GPUs
**Fix**: Migration vers Argon2id

## MEDIUM-001: Lack of Memory Zeroization
**Fichier**: `src/crypto/keys.rs`
**Problème**: Clés privées restent en mémoire après drop
**Impact**: Memory dump exposure
**Fix**: Implémenter `ZeroizeOnDrop`

## MEDIUM-002: Panic on Malformed Input
**Fichier**: `src/crypto/parser.rs:78`
**Problème**: `unwrap()` sur résultat parsing DER
**Impact**: DoS via panic
**Fix**: Propagation d'erreur avec `?`