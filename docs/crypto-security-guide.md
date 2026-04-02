# Guide de Sécurité Cryptographique TSN

## Vue d'ensemble

Ce guide présente les bonnes pratiques cryptographiques pour le développement sur Trust Stack Network (TSN). Il couvre les implémentations sécurisées, les vulnérabilités courantes, et les modules de démonstration éducatifs.

## 🛡️ Modules de Production (Sécurisés)

### Cryptographie Post-Quantique

```rust
// ✅ CORRECT : Signature ML-DSA-65 (FIPS 204)
use fips204::ml_dsa_65;

let (pk, sk) = ml_dsa_65::try_keygen_with_rng(&mut OsRng)?;
let signature = ml_dsa_65::try_sign_with_rng(&mut OsRng, &sk, &message, &context)?;
let is_valid = ml_dsa_65::try_verify(&pk, &message, &signature, &context)?;
```

### Hachage Sécurisé

```rust
// ✅ CORRECT : Poseidon2 pour les preuves ZK
use light_poseidon::Poseidon;

let mut poseidon = Poseidon::new();
poseidon.hash(&inputs)?;

// ✅ CORRECT : SHA-256 pour usage général
use sha2::{Sha256, Digest};

let mut hasher = Sha256::new();
hasher.update(data);
let hash = hasher.finalize();
```

### Chiffrement Authentifié

```rust
// ✅ CORRECT : ChaCha20-Poly1305 (AEAD)
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};

let key = ChaCha20Poly1305::generate_key(&mut OsRng);
let cipher = ChaCha20Poly1305::new(&key);
let nonce = Nonce::from_slice(b"unique nonce"); // 12 bytes
let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;
```

### Génération Aléatoire Sécurisée

```rust
// ✅ CORRECT : Entropie cryptographique
use rand::{rngs::OsRng, RngCore};

let mut key = [0u8; 32];
OsRng.fill_bytes(&mut key);

// ✅ CORRECT : Pour les tests reproductibles
use rand::{rngs::StdRng, SeedableRng};
let mut rng = StdRng::seed_from_u64(42); // Tests uniquement
```

### Comparaisons Constant-Time

```rust
// ✅ CORRECT : Comparaison sécurisée
use subtle::ConstantTimeEq;

fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
```

### Dérivation de Clés (KDF)

```rust
// ✅ CORRECT : PBKDF2 avec sel
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

let salt = b"unique_random_salt_16_bytes_min";
let mut key = [0u8; 32];
pbkdf2_hmac::<Sha256>(password, salt, 100_000, &mut key);
```

## ⚠️ Modules de Démonstration (Vulnérables)

### Activation des Modules Vulnérables

Les modules de démonstration ne sont disponibles qu'avec la feature `vulnerable-demo` :

```bash
# Compilation avec modules vulnérables (TESTS/ÉDUCATION UNIQUEMENT)
cargo build --features vulnerable-demo
cargo test --features vulnerable-demo

# Compilation normale (modules vulnérables EXCLUS)
cargo build
cargo test
```

### Protection par Compilation Conditionnelle

```rust
// Protection automatique - empêche la compilation accidentelle
#[cfg(not(feature = "vulnerable-demo"))]
compile_error!(
    "❌ ACCÈS REFUSÉ : Modules vulnérables désactivés\n\
     Pour les activer (TESTS/ÉDUCATION UNIQUEMENT) :\n\
     cargo build --features vulnerable-demo"
);
```

## 🚨 Vulnérabilités Démonstrées

### 1. Timing Attacks

**Problème** : Comparaisons non-constant-time révèlent des informations via le timing.

```rust
// ❌ VULNÉRABLE : Early return = timing leak
fn insecure_compare(a: &[u8], b: &[u8]) -> bool {
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false; // ⚠️ Timing révèle la position de l'erreur
        }
    }
    true
}

// ✅ SÉCURISÉ : Constant-time
use subtle::ConstantTimeEq;
fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
```

### 2. Nonce Reuse

**Problème** : Réutilisation de nonce en mode CTR révèle le XOR des plaintexts.

```rust
// ❌ VULNÉRABLE : Nonce fixe
let nonce = [0u8; 12]; // Toujours le même
let ciphertext = cipher.encrypt(&nonce, plaintext)?;

// ✅ SÉCURISÉ : Nonce unique
let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
let ciphertext = cipher.encrypt(&nonce, plaintext)?;
```

### 3. RNG Prévisible

**Problème** : Générateurs déterministes permettent la prédiction des clés.

```rust
// ❌ VULNÉRABLE : Seed connu = séquence prévisible
let mut rng = StdRng::seed_from_u64(12345);

// ✅ SÉCURISÉ : Entropie du système
let mut rng = OsRng;
```

### 4. Padding Oracle

**Problème** : Vérification de padding non-constant-time révèle des informations.

```rust
// ❌ VULNÉRABLE : Early return sur padding invalide
fn remove_padding(data: &[u8]) -> Option<&[u8]> {
    let pad_len = data[data.len() - 1] as usize;
    if pad_len > 16 { return None; } // ⚠️ Timing leak
    // ...
}

// ✅ SÉCURISÉ : Vérification constant-time
use subtle::{Choice, ConditionallySelectable};
fn secure_remove_padding(data: &[u8]) -> Option<&[u8]> {
    // Implémentation constant-time complète
}
```

### 5. KDF Naïf

**Problème** : Dérivation sans sel ni itérations, vulnérable aux rainbow tables.

```rust
// ❌ VULNÉRABLE : Hash simple sans sel
fn naive_kdf(password: &[u8]) -> [u8; 32] {
    Sha256::digest(password).into()
}

// ✅ SÉCURISÉ : PBKDF2 avec sel et itérations
use pbkdf2::pbkdf2_hmac;
fn secure_kdf(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password, salt, 100_000, &mut key);
    key
}
```

## 🧪 Tests de Sécurité

### Tests de Timing Attack

```bash
# Benchmark des vulnérabilités de timing
cargo test --features vulnerable-demo timing_attack_benchmark
```

### Tests de Non-Régression

```bash
# Vérifier que les modules vulnérables sont bien bloqués
cargo build  # Doit échouer si vulnerable.rs est importé sans feature

# Vérifier que la feature fonctionne
cargo build --features vulnerable-demo  # Doit réussir
```

## 📋 Checklist de Review Crypto

Avant de merger du code cryptographique :

- [ ] **Entropie** : Utilise `OsRng` pour les clés/nonces de production
- [ ] **Constant-time** : Comparaisons sensibles utilisent `subtle::ConstantTimeEq`
- [ ] **AEAD** : Chiffrement authentifié (ChaCha20-Poly1305, AES-GCM)
- [ ] **Post-quantique** : Signatures ML-DSA-65, hashes Poseidon2 pour ZK
- [ ] **KDF sécurisé** : PBKDF2/scrypt/Argon2 avec sel aléatoire
- [ ] **Nonce unique** : Jamais de réutilisation de nonce
- [ ] **Tests** : Couverture des cas d'erreur et edge cases
- [ ] **Documentation** : Justification des choix cryptographiques

## 🔗 Références

- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) - ML-DSA (Dilithium)
- [RFC 8439](https://tools.ietf.org/html/rfc8439) - ChaCha20-Poly1305
- [Plonky2 Paper](https://github.com/0xPolygonZero/plonky2) - STARKs post-quantiques
- [Timing Attack Prevention](https://github.com/dalek-cryptography/subtle)
- [OWASP Crypto Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

---

**⚠️ RAPPEL IMPORTANT** : Les modules `src/crypto/vulnerable.rs` ne doivent JAMAIS être utilisés en production. Ils sont exclusivement destinés à l'éducation et aux tests de sécurité.