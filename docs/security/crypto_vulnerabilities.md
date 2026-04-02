# Analyse de Sécurité - Modules Crypto Vulnérables

## Vue d'ensemble

Ce document analyse les vulnérabilités intentionnelles présentes dans `src/crypto/vulnerable.rs` et leurs mitigations dans `src/crypto/secure_impl.rs`. Ces modules servent d'exemples pédagogiques et de tests de sécurité.

⚠️ **ATTENTION**: Les fonctions dans `vulnerable.rs` NE DOIVENT JAMAIS être utilisées en production.

## Vulnérabilités Identifiées

### 1. Timing Attack - Comparaison Non Constant-Time

**Fonction vulnérable**: `insecure_compare()`
**Localisation**: `src/crypto/vulnerable.rs:7`

#### Description
```rust
pub fn insecure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false; // ⚠️ VULNÉRABILITÉ: Sortie précoce
        }
    }
    true
}
```

#### Vulnérabilité
- **Type**: Timing Side-Channel Attack
- **Mécanisme**: La fonction retourne dès le premier byte différent
- **Impact**: Un attaquant peut déduire la position de l'erreur en mesurant le temps d'exécution
- **Sévérité**: HAUTE (pour la vérification de tokens/passwords)

#### Exploitation
```rust
// Attaque par timing pour deviner un secret
let secret = b"supersecret";
let mut guess = b"aaaaaaaaaaaa".to_vec();

for pos in 0..secret.len() {
    for byte_val in 0..=255 {
        guess[pos] = byte_val;
        let start = Instant::now();
        insecure_compare(secret, &guess);
        let elapsed = start.elapsed();
        
        // Plus le temps est long, plus on est proche du bon byte
        if elapsed > threshold {
            // Byte correct trouvé à la position pos
            break;
        }
    }
}
```

#### Mitigation
**Fonction sécurisée**: `secure_compare()` dans `src/crypto/secure_impl.rs`
```rust
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}
```

### 2. Mode CTR avec IV Prévisible

**Fonction vulnérable**: `InsecureCtrMode`
**Localisation**: `src/crypto/vulnerable.rs:20`

#### Description
```rust
pub struct InsecureCtrMode {
    key: [u8; 16],
    counter: u64, // ⚠️ VULNÉRABILITÉ: Compteur prévisible
}
```

#### Vulnérabilité
- **Type**: IV/Nonce Reuse Attack
- **Mécanisme**: Le compteur commence toujours à 0 pour chaque instance
- **Impact**: Réutilisation d'IV permet de récupérer XOR des plaintexts
- **Sévérité**: CRITIQUE

#### Exploitation
```rust
let key = [0u8; 16];
let ctr1 = InsecureCtrMode::new(key);
let ctr2 = InsecureCtrMode::new(key);

let msg1 = b"Secret message 1";
let msg2 = b"Secret message 2";

let cipher1 = ctr1.encrypt(msg1);
let cipher2 = ctr2.encrypt(msg2);

// XOR des ciphertexts révèle XOR des plaintexts
let xor_result: Vec<u8> = cipher1.iter()
    .zip(cipher2.iter())
    .map(|(a, b)| a ^ b)
    .collect();
// xor_result == msg1 XOR msg2
```

#### Mitigation
Utiliser `SecureAead` avec nonces aléatoires uniques.

### 3. Générateur de Nombres Pseudo-Aléatoires Prévisible

**Fonction vulnérable**: `PredictableRng`
**Localisation**: `src/crypto/vulnerable.rs:45`

#### Description
```rust
pub struct PredictableRng {
    state: u64, // ⚠️ VULNÉRABILITÉ: État simple, prévisible
}
```

#### Vulnérabilité
- **Type**: Weak Random Number Generation
- **Mécanisme**: LFSR simple avec seed prévisible
- **Impact**: Séquences aléatoires prévisibles pour la cryptographie
- **Sévérité**: CRITIQUE (pour génération de clés/nonces)

#### Exploitation
```rust
// Si on observe quelques valeurs, on peut prédire les suivantes
let mut rng = PredictableRng::new(known_seed);
let observed_values = vec![rng.next(), rng.next(), rng.next()];

// Un attaquant peut maintenant prédire toutes les valeurs futures
let predicted_next = rng.next();
```

### 4. Padding Oracle - PKCS#7

**Fonction vulnérable**: `remove_pkcs7_padding()`
**Localisation**: `src/crypto/vulnerable.rs:65`

#### Description
```rust
pub fn remove_pkcs7_padding(data: &[u8]) -> Option<&[u8]> {
    // Validation basique qui peut leak des informations via timing
}
```

#### Vulnérabilité
- **Type**: Padding Oracle Attack
- **Mécanisme**: Différents temps de traitement selon la validité du padding
- **Impact**: Déchiffrement de messages sans connaître la clé
- **Sévérité**: HAUTE

#### Exploitation
L'attaque padding oracle permet de déchiffrer des messages en observant si le padding est valide ou non.

### 5. Key Derivation Function Faible

**Fonction vulnérable**: `naive_kdf()`
**Localisation**: `src/crypto/vulnerable.rs:85`

#### Description
```rust
pub fn naive_kdf(password: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(password);
    hasher.finalize().into() // ⚠️ VULNÉRABILITÉ: Pas de salt, vulnérable aux rainbow tables
}
```

#### Vulnérabilité
- **Type**: Weak Key Derivation
- **Mécanisme**: Pas de salt, une seule itération de hash
- **Impact**: Vulnérable aux rainbow tables et attaques par dictionnaire
- **Sévérité**: HAUTE

#### Exploitation
```rust
// Précalcul de rainbow table
let common_passwords = ["password", "123456", "admin"];
let mut rainbow_table = HashMap::new();

for pwd in common_passwords {
    let hash = naive_kdf(pwd.as_bytes());
    rainbow_table.insert(hash, pwd);
}

// Attaque instantanée si le password est dans la table
if let Some(password) = rainbow_table.get(&stolen_hash) {
    println!("Password trouvé: {}", password);
}
```

#### Mitigation
**Fonction sécurisée**: `strong_kdf()` avec salt et PBKDF2.

## Tests de Sécurité

### Tests Unitaires
- **Fichier**: `tests/crypto_vulnerable_test.rs`
- **Couverture**: Toutes les vulnérabilités avec tests de régression
- **Property-based tests**: Invariants cryptographiques vérifiés

### Fuzzing
- **Fichier**: `fuzz/fuzz_targets/crypto_vulnerable.rs`
- **Cible**: Entrées malformées et adversariales
- **Exécution**: `cargo fuzz run crypto_vulnerable`

### Tests de Timing
```bash
# Exécution des tests de timing attack
cargo test test_insecure_compare_timing_leak -- --nocapture
cargo test test_secure_compare_constant_time -- --nocapture
```

## Recommandations de Sécurité

### 1. Audit de Code
- [ ] Vérifier l'absence d'utilisation des fonctions vulnérables en production
- [ ] Rechercher les patterns similaires dans le codebase
- [ ] Valider que toutes les comparaisons sensibles utilisent `subtle::ConstantTimeEq`

### 2. Tests Automatisés
- [ ] Intégrer les tests de timing dans la CI
- [ ] Exécuter le fuzzing régulièrement
- [ ] Monitorer les régressions de sécurité

### 3. Formation Équipe
- [ ] Sensibiliser aux timing attacks
- [ ] Former sur les bonnes pratiques crypto
- [ ] Documenter les patterns à éviter

## Références

### Standards
- [RFC 3447 - PKCS #1](https://tools.ietf.org/html/rfc3447)
- [RFC 5652 - PKCS #7](https://tools.ietf.org/html/rfc5652)
- [NIST SP 800-108 - KDF](https://csrc.nist.gov/publications/detail/sp/800-108/final)

### Attaques Documentées
- [Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems](https://www.paulkocher.com/TimingAttacks.pdf)
- [Padding Oracle Attacks](https://robertheaton.com/2013/07/29/padding-oracle-attack/)
- [The Security Impact of a New Cryptographic Library](https://cr.yp.to/highspeed/naclcrypto-20090310.pdf)

### Outils de Sécurité
- [cargo-audit](https://github.com/RustSec/rustsec/tree/main/cargo-audit)
- [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
- [subtle](https://github.com/dalek-cryptography/subtle)

## Changelog Sécurité

| Date | Version | Changement | Sévérité |
|------|---------|------------|----------|
| 2024-01-XX | v0.1.0 | Ajout des modules vulnérables pour tests | INFO |
| 2024-01-XX | v0.1.1 | Ajout des mitigations sécurisées | MEDIUM |
| 2024-01-XX | v0.1.2 | Tests de timing automatisés | HIGH |

---

**Responsable Sécurité**: Marcus.R  
**Dernière révision**: 2024-01-XX  
**Prochaine révision**: 2024-02-XX