# Documentation de sécurité - Modules cryptographiques post-quantiques

## Vue d'ensemble

Ce document décrit les considérations de sécurité pour les modules cryptographiques post-quantiques de TSN.

## Architecture

```
src/crypto/pq/
├── ml_dsa.rs          # Signatures ML-DSA (FIPS 204)
├── slh_dsa.rs         # Signatures SLH-DSA (FIPS 205)
├── slh_dsa_batch.rs   # Vérification batch SLH-DSA
├── slh_dsa_ops.rs     # Opérations internes SLH-DSA
├── proof_pq.rs        # Preuves Plonky2 STARK
├── commitment_pq.rs   # Engagements post-quantiques
├── verify_pq.rs       # Vérification de transactions V2
├── circuit_pq.rs      # Circuits Plonky2
└── mod.rs             # Module principal
```

## Menaces identifiées (STRIDE)

### Spoofing (Falsification d'identité)

| Composant | Menace | Mitigation | Statut |
|-----------|--------|------------|--------|
| ml_dsa.rs | Clé publique malformée | Validation de format ML-DSA | ✅ Implémenté |
| slh_dsa.rs | Clé publique malformée | Validation de format SLH-DSA | ✅ Implémenté |
| verify_pq.rs | Transaction avec clé invalide | Vérification de signature | ✅ Implémenté |

### Tampering (Altération)

| Composant | Menace | Mitigation | Statut |
|-----------|--------|------------|--------|
| commitment_pq.rs | Altération de l'engagement | Hash cryptographique | ✅ Implémenté |
| proof_pq.rs | Altération de la preuve | Vérification STARK | ✅ Implémenté |
| verify_pq.rs | Altération de la transaction | Signature + preuve | ✅ Implémenté |

### Repudiation (Révocation)

| Composant | Menace | Mitigation | Statut |
|-----------|--------|------------|--------|
| ml_dsa.rs | Signature non traçable | Signatures déterministes | ✅ Implémenté |
| slh_dsa.rs | Signature non traçable | Signatures déterministes | ✅ Implémenté |

### Information Disclosure (Divulgation)

| Composant | Menace | Mitigation | Statut |
|-----------|--------|------------|--------|
| commitment_pq.rs | Valeur révélée | Randomness unique | ✅ Implémenté |
| proof_pq.rs | Témoin révélé | Zero-knowledge | ✅ Implémenté |

### Denial of Service (Déni de service)

| Composant | Menace | Mitigation | Statut |
|-----------|--------|------------|--------|
| slh_dsa_batch.rs | Batch trop grand | Limite de taille | ✅ Implémenté |
| circuit_pq.rs | Circuit trop complexe | Limite de profondeur | ✅ Implémenté |
| verify_pq.rs | Transaction malformée | Validation d'entrée | ✅ Implémenté |

### Elevation of Privilege (Élévation de privilèges)

| Composant | Menace | Mitigation | Statut |
|-----------|--------|------------|--------|
| verify_pq.rs | Double dépense | Nullifier unique | ✅ Implémenté |
| proof_pq.rs | Preuve invalide acceptée | Vérification STARK | ✅ Implémenté |

## Tests de fuzzing

### Fuzzers disponibles

| Fuzzer | Cible | Propriétés testées |
|--------|-------|-------------------|
| `commitment_pq_fuzzer.rs` | Engagements | Déterminisme, vérification |
| `proof_pq_fuzzer.rs` | Preuves Plonky2 | Génération, vérification |
| `verify_pq_fuzzer.rs` | Transactions V2 | Validation, cohérence |
| `slh_dsa_batch_fuzzer.rs` | Vérification batch | Limites, cohérence |
| `circuit_pq_fuzzer.rs` | Circuits Plonky2 | Construction, limites |

### Exécution des fuzzers

```bash
# Commitment PQ
cargo fuzz run commitment_pq_fuzzer

# Proof PQ
cargo fuzz run proof_pq_fuzzer

# Verify PQ
cargo fuzz run verify_pq_fuzzer

# SLH-DSA Batch
cargo fuzz run slh_dsa_batch_fuzzer

# Circuit PQ
cargo fuzz run circuit_pq_fuzzer
```

## Tests de propriété

Les tests de propriété (`tests/crypto_pq_proptest.rs`) vérifient:

1. **Déterminisme**: Mêmes entrées → mêmes sorties
2. **Vérification**: Engagement valide → vérification réussie
3. **Binding**: Impossible d'ouvrir vers une valeur différente
4. **Hiding**: Engagements de valeurs différentes sont différents
5. **Cohérence**: Vérification batch = vérification individuelle

## Checklist de sécurité pré-release

### Avant chaque release

- [ ] Tous les fuzzers passent sans crash
- [ ] Tests de propriété passent
- [ ] Pas de `unwrap()`/`expect()` dans le code réseau
- [ ] Validation des entrées complète
- [ ] Documentation des erreurs à jour
- [ ] Audit de dépendances

### Revue de code

- [ ] Pas de panics dans les parsers
- [ ] Arithmetic checked partout
- [ ] Comparaisons constant-time pour crypto
- [ ] Gestion des erreurs appropriée
- [ ] Pas de fuites d'information dans les logs

## Vulnérabilités connues

### Aucune vulnérabilité connue actuellement

En cas de découverte, suivre le processus de divulgation responsable.

## Références

- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) - ML-DSA
- [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) - SLH-DSA
- [Plonky2](https://github.com/0xPolygonZero/plonky2) - STARKs
- [STRIDE](https://owasp.org/www-community/Threat_Modeling_Process) - Threat modeling

## Contact sécurité

Pour signaler une vulnérabilité: security@truststack.network

---

Dernière mise à jour: 2024
