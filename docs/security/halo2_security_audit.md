# Audit de Sécurité : Validation des Preuves Halo2

**Date** : 2025-01-20  
**Auditeur** : Marcus.R (Security & QA Engineer)  
**Scope** : `src/crypto/halo2_*.rs`, validation des preuves ZK  
**Severity** : CRITICAL

---

## Résumé Exécutif

L'audit révèle **7 vulnérabilités critiques** dans le système de validation des preuves Halo2, dont 3 peuvent conduire à des attaques DoS et 4 à des validations incorrectes de preuves malformées.

### Score de Risque Global : 🔴 HIGH (8.2/10)

---

## Vulnérabilités Identifiées

### V1. [CRITICAL] Régénération des Paramètres SRS à Chaque Vérification

**Fichier** : `src/crypto/halo2_proofs.rs:266`  
**CWE** : CWE-327 (Use of Broken/Risky Cryptographic Algorithm)

```rust
// ❌ INCORRECT - Params régénérés à chaque appel
pub fn verify_commitment(...) -> Result<bool, Box<dyn std::error::Error>> {
    let params = ParamsKZG::<Bn256>::setup(K, &mut OsRng);  // ← DANGER
    ...
}
```

**Problème** : Les paramètres KZG doivent être identiques entre génération et vérification. Leur régénération à chaque appel invalide la sécurité du système.

**Impact** : 
- Attaque par substitution de paramètres
- Preuves invalides peuvent passer la vérification
- Compromission de la soundness ZK

**Mitigation** :
```rust
// ✅ CORRECT - Params statiques vérifiés
lazy_static! {
    static ref HALO2_PARAMS: ParamsKZG<Bn256> = {
        ParamsKZG::setup(K, &mut OsRng)
    };
}
```

---

### V2. [HIGH] Absence de Validation des Points de Courbe

**Fichier** : `src/crypto/halo2_prover.rs`, `src/crypto/halo2_circuit.rs`  
**CWE** : CWE-20 (Improper Input Validation)

Les preuves ne sont pas validées pour s'assurer que :
- Les points de courbe sont sur BN254/pallas
- Les coordonnées ne sont pas le point à l'infini
- Les éléments de champ sont dans le range valide

**Impact** :
- Attaques par point d'ordre faible
- Invalid curve attacks
- Panics potentielles dans les opérations de groupe

**Mitigation** : Validation canonique obligatoire avant toute opération.

---

### V3. [HIGH] Incohérence des Courbes Utilisées

**Fichier** : Multiple  
**CWE** : CWE-1109 (Inconsistent Naming Conventions for Identifiers)

| Fichier | Courbe | Problème |
|---------|--------|----------|
| `halo2_proofs.rs` | BN254 (halo2curves) | OK |
| `halo2_prover.rs` | pasta_curves::Fp | ❌ Incompatible |
| `halo2_circuit.rs` | pasta_curves::pallas | ❌ Incompatible |

**Impact** : Les preuves générées avec une courbe ne peuvent pas être vérifiées avec une autre. Le système est cassé par design.

---

### V4. [MEDIUM] Absence de Limites de Ressources

**Fichier** : `src/crypto/halo2_proofs.rs:225`  
**CWE** : CWE-770 (Allocation of Resources Without Limits)

```rust
// ❌ Pas de validation de taille
pub fn prove_commitment(value: &Fr, blinding: &Fr, ...) {
    // Accepte n'importe quelle valeur sans vérification
}
```

**Impact** :
- DoS par exhaustion mémoire
- Preuves de taille arbitraire
- Timeout de circuit non géré

---

### V5. [MEDIUM] Timing Side-Channel sur la Vérification

**Fichier** : `src/crypto/halo2_circuit.rs`  
**CWE** : CWE-208 (Observable Timing Discrepancy)

```rust
// ❌ Branchement sur résultat secret
match result {
    Ok(true) => Choice::from(1),
    _ => Choice::from(0),  // ← Timing différent
}
```

**Impact** : Fuite d'information sur la validité de la preuve via timing.

---

### V6. [MEDIUM] Absence de Domain Separation

**Fichier** : `src/crypto/halo2_prover.rs`  
**CWE** : CWE-323 (Reusing a Nonce, Key Pair in Encryption)

Le transcript n'utilise pas de label de domaine spécifique à l'application :
```rust
// ❌ Transcript générique
let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
```

**Impact** : Attaques par collision de preuves entre différents contextes.

---

### V7. [LOW] Gestion d'Erreur Inadéquate

**Fichier** : Multiple  
**CWE** : CWE-391 (Unchecked Error Condition)

Plusieurs `unwrap()` et `expect()` dans le code de production :
```rust
let proof = prove_commitment(...).unwrap();  // ← Panic possible
```

---

## Tests de Régression Requis

1. **test_srs_consistency** : Vérifier que les mêmes params sont utilisés
2. **test_invalid_curve_point** : Rejeter les points hors courbe
3. **test_proof_size_limits** : Limiter la taille des preuves
4. **test_timing_constant** : Vérifier le temps constant
5. **test_domain_separation** : Vérifier les labels de transcript

---

## Recommandations

### Immédiates (P0)
- [ ] Corriger la régénération des params SRS
- [ ] Unifier l'utilisation des courbes (BN254)
- [ ] Ajouter validation des points de courbe

### Courte terme (P1)
- [ ] Implémenter limites de ressources
- [ ] Ajouter domain separation
- [ ] Corriger timing side-channels

### Long terme (P2)
- [ ] Audit formel du circuit
- [ ] Fuzzing continu avec cargo-fuzz
- [ ] Benchmarks de performance

---

## Références

- [Halo2 Book](https://zcash.github.io/halo2/)
- [BN254 Security](https://eprint.iacr.org/2015/1027)
- [CWE-327](https://cwe.mitre.org/data/definitions/327.html)
- [ZK Proof Security Best Practices](https://github.com/zcash/zcash/issues/4060)

---

**Signé** : Marcus.R  
**Status** : OPEN - Corrections requises avant release
