# Threat Model: TSN Faucet Module (PSTR)

**Document Version:** 1.0  
**Last Updated:** 2024  
**Scope:** `src/faucet/mod.rs` (1159 lines)  
**Classification:** Internal - Security Critical

---

## 1. Executive Summary

Le module faucet distribue 50 TSN par wallet par jour. C'est une surface d'attaque critique car:
- Il génère des tokens de valeur réelle
- Il accepte des preuves ZK (Plonky2) externes
- Il maintient un état de rate limiting persistant
- Il est exposé via l'API réseau

**Risk Rating:** HIGH

---

## 2. STRIDE Analysis

### Spoofing (S)
| Threat | Description | Severity | Mitigation |
|--------|-------------|----------|------------|
| S1 | Usurpation d'identité via pk_hash forgé | Critical | Vérification Plonky2 + nullifier unique |
| S2 | Replay d'une preuve valide | Critical | Nullifier stocké en DB + vérification |

### Tampering (T)
| Threat | Description | Severity | Mitigation |
|--------|-------------|----------|------------|
| T1 | Modification du rate limit en DB | High | DB chiffrée + checksums |
| T2 | Modification des paramètres de preuve | Critical | Vérification circuit Plonky2 |

### Repudiation (R)
| Threat | Description | Severity | Mitigation |
|--------|-------------|----------|------------|
| R1 | Négation d'une demande de faucet | Low | Logging audit complet |

### Information Disclosure (I)
| Threat | Description | Severity | Mitigation |
|--------|-------------|----------|------------|
| I1 | Timing attack sur pk_hash existant | High | Comparaison constant-time |
| I2 | Enumeration des wallets ayant claim | Medium | Pas de message différencié |

### Denial of Service (D)
| Threat | Description | Severity | Mitigation |
|--------|-------------|----------|------------|
| D1 | Flood de requêtes de claim | High | Rate limiting IP + proof of work |
| D2 | DB bloat via nullifiers invalides | Medium | Validation preuve avant stockage |

### Elevation of Privilege (E)
| Threat | Description | Severity | Mitigation |
|--------|-------------|----------|------------|
| E1 | Bypass du rate limit | Critical | Timestamp vérifié + DB atomique |

---

## 3. Attack Scenarios

### Scenario 1: Double Spend via Timing Race
**Attack:** Deux requêtes simultanées avec même preuve  
**Impact:** Double distribution de tokens  
**Defense:** 
- Vérification nullifier en DB avant génération note
- Opération atomique check-and-set

### Scenario 2: Proof Replay Attack
**Attack:** Réutilisation d'une preuve valide sur un autre nœud  
**Impact:** Distribution multiple  
**Defense:**
- Nullifier global sur la blockchain
- Synchronisation des nullifiers entre nœuds

### Scenario 3: Timing Side-Channel
**Attack:** Mesure du temps de réponse pour déterminer si un pk_hash existe  
**Impact:** Privacy leak  
**Defense:**
- `subtle::ConstantTimeEq` pour toutes les comparaisons
- Temps de réponse constant (padding artificiel si nécessaire)

### Scenario 4: Malformed Proof DoS
**Attack:** Envoi de preuves malformées pour crash le validateur Plonky2  
**Impact:** Panic / DoS  
**Defense:**
- Parsing défensif avec `Result` partout
- Aucun `unwrap()` dans le hot path
- Fuzzing continu

---

## 4. Security Invariants

Les invariants suivants DOIVENT être préservés:

```rust
// INV-1: Unicité du nullifier
∀ claim ∈ Claims: claim.nullifier ∉ SpentNullifiers

// INV-2: Rate limiting
∀ wallet: count(claims[wallet, 24h]) ≤ 1

// INV-3: Validité de la preuve
∀ claim: verify_plonky2(claim.proof, claim.public_inputs) == true

// INV-4: Intégrité du montant
claim.amount == FAUCET_AMOUNT (50 TSN)

// INV-5: Non-malleabilité
hash(claim) dépend de tous les champs signifiants
```

---

## 5. Security Checklist

### Pre-Deployment
- [ ] Fuzzing passé sans crash pendant 24h
- [ ] Property tests tous verts
- [ ] Audit timing constant-time
- [ ] Review des dépendances crypto
- [ ] Test de charge rate limiting

### Runtime Monitoring
- [ ] Alertes sur rate limit dépassé
- [ ] Alertes sur preuve invalide
- [ ] Métriques de timing (p95, p99)
- [ ] Logs d'audit immuables

---

## 6. References

- Plonky2: https://github.com/0xPolygonZero/plonky2
- Constant-time comparisons: subtle crate
- FIPS 204: ML-DSA post-quantique signatures
