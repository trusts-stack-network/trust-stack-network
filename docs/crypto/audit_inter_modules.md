# Audit de Cohérence Inter-Modules Cryptographiques

**Date:** 2024  
**Auditeur:** Elena.M - Cryptography Engineer  
**Scope:** `src/crypto/`, `src/wallet/` (71 fichiers, ~16k lignes)  

## Résumé Exécutif

L'analyse révèle **plusieurs incohérences critiques** entre les modules cryptographiques de TSN. Ces incohérences concernent principalement :
- L'utilisation simultanée de deux schémas de signature post-quantique différents (ML-DSA-65 et SLH-DSA)
- Des tailles de clés et signatures incompatibles entre modules
- Des interfaces de validation dupliquées et divergentes

**Niveau de risque:** ÉLEVÉ - Des incohérences de types peuvent entraîner des erreurs de validation silencieuses.

---

## 1. Incohérences Identifiées

### 1.1 Dualité des Schémas de Signature Post-Quantique

#### Problème
Deux schémas de signature post-quantique sont utilisés simultanément sans stratégie de migration claire :

| Module | Schéma | Taille Clé Publique | Taille Signature | Standard |
|--------|--------|---------------------|------------------|----------|
| `signature.rs` | ML-DSA-65 | 1952 bytes | 3293 bytes | FIPS 204 |
| `pq/slh_dsa.rs` | SLH-DSA-SHA2-128s | 64 bytes | 7856 bytes | FIPS 205 |
| `signature_validator.rs` | SLH-DSA | 32 bytes* | 7808 bytes* | FIPS 205 |

*Tailles incorrectes dans `signature_validator.rs` : PK_BYTES=32 et SIG_BYTES=7808 alors que SLH-DSA-SHA2-128s utilise 64 bytes pour la clé publique.

#### Impact
- Impossibilité de valider des signatures ML-DSA avec le validateur SLH-DSA
- Confusion sur l'algorithme de signature "officiel" de TSN
- Risque d'erreurs de validation silencieuses

#### Références
- FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final
- FIPS 205 (SLH-DSA): https://csrc.nist.gov/pubs/fips/205/final

---

### 1.2 Incohérence des Constantes de Taille

#### `pq/slh_dsa.rs`
```rust
pub const SLH_PUBLIC_KEY_SIZE: usize = 64;   // ✓ Correct pour SLH-DSA-SHA2-128s
pub const SLH_SECRET_KEY_SIZE: usize = 128;
pub const SLH_SIGNATURE_SIZE: usize = 7856;  // ✓ Correct
```

#### `signature_validator.rs`
```rust
pub const PK_BYTES: usize = 32;      // ✗ INCORRECT - Devrait être 64
pub const SIG_BYTES: usize = 7808;   // ✗ INCORRECT - Devrait être 7856
```

#### Impact
- Échec systématique de la validation des signatures SLH-DSA
- Erreurs `MalformedSignature` et `MalformedPublicKey` incorrectes

---

### 1.3 Duplication des Modules de Validation

Deux modules implémentent la validation de signatures :
- `signature_validation.rs` : Système de haut niveau avec cache, rate limiting, batch validation
- `signature_validator.rs` : Validateur bas-niveau avec métriques

#### Problèmes
1. **Divergence des types d'erreurs** :
   - `signature_validation.rs` : `ValidationSystemError`
   - `signature_validator.rs` : `ValidationError`

2. **Incohérence des structures de résultat** :
   - `signature_validation.rs` : `ValidationResult` (champs partiels)
   - `signature_validator.rs` : `ValidationResult` (champs complets avec métriques)

3. **Redondance fonctionnelle** : Les deux modules gèrent des métriques de performance

---

### 1.4 Incohérence des Types de Preuves ZK

| Module | Système de Preuve | Statut |
|--------|-------------------|--------|
| `proof.rs` | Circom/snarkjs (Groth16) | Legacy |
| `halo2_prover.rs` | Halo2 PLONK | Nouveau |

#### Problèmes
- `proof.rs` utilise Groth16 avec BN254 (nécessite trusted setup)
- `halo2_prover.rs` utilise Halo2 (sans trusted setup)
- Pas de stratégie de migration documentée
- Les circuits Circom et Halo2 ne sont pas compatibles

---

### 1.5 Incohérence des Types de Commitments

#### `commitment.rs`
```rust
pub struct NoteCommitment(pub [u8; 32]);  // Poseidon hash
pub struct ValueCommitment {               // Pedersen sur BN254
    pub commitment: G1,
    pub randomness: Fr,
}
```

#### Problèmes
- `NoteCommitment` utilise Poseidon (ZK-friendly)
- `ValueCommitment` utilise Pedersen sur BN254 (homomorphique)
- Pas de trait commun pour les deux types de commitments
- Les conversions entre types ne sont pas standardisées

---

## 2. Interfaces Non Standardisées

### 2.1 Module `secure_impl.rs`

**Fonction publique unique :**
```rust
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool
```

**Problème :** N'utilise pas `subtle::ConstantTimeEq` correctement - retourne `bool` au lieu de `Choice`, permettant des branches sur le résultat secret.

### 2.2 Module `halo2_prover.rs`

**Structures publiques :**
- `CommitmentCircuit`
- `CommitmentConfig`

**Problème :** Pas d'interface commune avec `proof.rs` pour la vérification de preuves.

---

## 3. Recommandations

### 3.1 Court Terme (Critical)

1. **Corriger les constantes dans `signature_validator.rs`** :
   ```rust
   pub const PK_BYTES: usize = 64;    // SLH-DSA-SHA2-128s
   pub const SIG_BYTES: usize = 7856; // SLH-DSA-SHA2-128s
   ```

2. **Unifier les schémas de signature** : Choisir ML-DSA-65 (FIPS 204) comme standard TSN car :
   - Signatures plus compactes (3.3KB vs 7.8KB)
   - Plus rapide à vérifier
   - Recommandé par NIST pour la plupart des applications

3. **Créer un module d'interfaces standardisées** (`crypto_interfaces.rs`)

### 3.2 Moyen Terme (High)

1. **Fusionner `signature_validation.rs` et `signature_validator.rs`**
2. **Implémenter une couche d'abstraction pour les preuves ZK**
3. **Standardiser les traits pour les commitments**

### 3.3 Long Terme (Medium)

1. **Migrer complètement vers Halo2** et déprécier Circom/snarkjs
2. **Implémenter des tests d'intégration inter-modules**
3. **Documenter formellement les interfaces cryptographiques**

---

## 4. Interfaces Standardisées Proposées

### 4.1 Trait `SignatureScheme`

```rust
pub trait SignatureScheme: Send + Sync {
    const PUBLIC_KEY_SIZE: usize;
    const SECRET_KEY_SIZE: usize;
    const SIGNATURE_SIZE: usize;
    
    type PublicKey: Serialize + DeserializeOwned + Clone;
    type SecretKey: Serialize + DeserializeOwned + Zeroize + Clone;
    type Signature: Serialize + DeserializeOwned + Clone;
    
    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> (Self::SecretKey, Self::PublicKey);
    fn sign(secret_key: &Self::SecretKey, message: &[u8]) -> Self::Signature;
    fn verify(public_key: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> bool;
}
```

### 4.2 Trait `ProofSystem`

```rust
pub trait ProofSystem {
    type Proof: Serialize + DeserializeOwned;
    type VerifyingKey: Clone;
    type PublicInputs;
    
    fn verify(
        &self,
        proof: &Self::Proof,
        public_inputs: &Self::PublicInputs,
        vk: &Self::VerifyingKey,
    ) -> Result<bool, ProofError>;
}
```

### 4.3 Trait `CommitmentScheme`

```rust
pub trait CommitmentScheme {
    type Commitment: AsRef<[u8]> + Eq + Clone;
    type Opening: Zeroize;
    
    fn commit<R: RngCore>(value: &[u8], rng: &mut R) -> (Self::Commitment, Self::Opening);
    fn verify(commitment: &Self::Commitment, value: &[u8], opening: &Self::Opening) -> bool;
}
```

---

## 5. Vérification des Constantes

| Constante | Valeur Actuelle | Valeur Attendue | Statut |
|-----------|-----------------|-----------------|--------|
| `PK_BYTES` (SLH) | 32 | 64 | ❌ INCORRECT |
| `SIG_BYTES` (SLH) | 7808 | 7856 | ❌ INCORRECT |
| `SLH_PUBLIC_KEY_SIZE` | 64 | 64 | ✅ CORRECT |
| `SLH_SIGNATURE_SIZE` | 7856 | 7856 | ✅ CORRECT |
| ML-DSA-65 PK | 1952 | 1952 | ✅ CORRECT |
| ML-DSA-65 SIG | 3293 | 3293 | ✅ CORRECT |

---

## 6. Conclusion

Les incohérences identifiées représentent un risque significatif pour la sécurité et l'interopérabilité du système TSN. La correction immédiate des constantes incorrectes dans `signature_validator.rs` est **critique**.

La création d'un module d'interfaces standardisées permettra de :
- Garantir la cohérence entre les implémentations
- Faciliter les futures migrations algorithmiques
- Améliorer la testabilité du code cryptographique

**Prochaine étape :** Implémentation du module `crypto_interfaces.rs` et correction des constantes.

---

*Document généré dans le cadre de l'audit de cohérence inter-modules TSN.*
*Classification: Internal Use - Cryptography Team*
