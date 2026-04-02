# Checklist d'Audit Halo2 - TSN

## Préambule

Cette checklist doit être complétée avant chaque release impliquant le système Halo2.

## 1. Validation des Entrées

### 1.1 Taille des Preuves

```rust
// Vérifier: src/crypto/halo2_validator.rs
// La preuve doit avoir une taille raisonnable
assert!(proof.len() >= 32, "Proof too small");
assert!(proof.len() <= 10_000_000, "Proof too large"); // 10MB
```

- [ ] Minimum 32 bytes (taille d'un hash)
- [ ] Maximum 10MB (protection DoS)
- [ ] Test de régression pour preuve vide
- [ ] Test de régression pour preuve excessive

### 1.2 Entrées Publiques

```rust
// Vérifier: nombre d'entrées limité
assert!(public_inputs.len() <= 1000, "Too many inputs");

// Vérifier: taille individuelle limitée
for input in &public_inputs {
    assert!(input.len() <= 1_000_000, "Input too large"); // 1MB
}

// Vérifier: taille totale limitée
let total: usize = public_inputs.iter().map(|v| v.len()).sum();
assert!(total <= 100_000_000, "Total input size too large"); // 100MB
```

- [ ] Nombre max: 1000
- [ ] Taille max par entrée: 1MB
- [ ] Taille totale max: 100MB
- [ ] Test avec entrées vides
- [ ] Test avec entrées maximales

### 1.3 Verifying Key Hash

- [ ] Hash toujours présent (32 bytes)
- [ ] Hash vérifié contre registre on-chain
- [ ] Rejet si hash inconnu

## 2. Sécurité Cryptographique

### 2.1 Points de Courbe

```rust
// Les points ne doivent pas être:
// - Tous à zéro (point à l'infini mal formé)
// - Tous à 0xFF (valeur invalide)
// - Hors de la courbe
```

- [ ] Rejet des points tous zéros
- [ ] Rejet des points tous 0xFF
- [ ] Validation on-curve
- [ ] Test avec points invalides

### 2.2 Non-Malleabilité

```rust
// Une preuve modifiée doit être invalide
let mut modified = proof.clone();
modified[50] ^= 0x01;
assert!(verify(&modified, &inputs, &vk).is_err());
```

- [ ] Test de malleabilité (flip bit)
- [ ] Test de malleabilité (truncation)
- [ ] Test de malleabilité (extension)

### 2.3 Binding

```rust
// La preuve doit être liée aux entrées publiques
let different_inputs = /* ... */;
assert!(verify(&proof, &different_inputs, &vk).is_err());
```

- [ ] Test de binding avec entrées différentes
- [ ] Test de binding avec vk différent

## 3. Protection DoS

### 3.1 Timeouts

```rust
// La vérification doit avoir un timeout
let result = timeout(Duration::from_secs(30), || {
    verify_proof(&proof, &inputs, &vk)
}).await?;
```

- [ ] Timeout configuré (30s par défaut)
- [ ] Test avec preuve lente
- [ ] Ressources libérées après timeout

### 3.2 Circuit Breaker

```rust
// Trop d'erreurs = circuit ouvert
if error_rate > threshold {
    circuit_breaker.open();
}
```

- [ ] Circuit breaker intégré
- [ ] Seuil de déclenchement configuré
- [ ] Récupération automatique

### 3.3 Rate Limiting

- [ ] Limite de preuves par seconde
- [ ] Limite par IP/adresse
- [ ] Backoff exponentiel

## 4. Tests de Régression

### 4.1 Cas Limites Connus

- [ ] Preuve vide
- [ ] Preuve d'un byte
- [ ] Preuve de 31 bytes (juste sous le minimum)
- [ ] Preuve de 10MB+1
- [ ] 1001 entrées publiques
- [ ] Entrée de 1MB+1

### 4.2 Attaques Documentées

- [ ] CVE-20XX-XXXX (si applicable)
- [ ] Attaque par padding
- [ ] Attaque par compression
- [ ] Attaque par désérialisation

## 5. Fuzzing

### 5.1 Couverture

- [ ] Fuzzer cargo-fuzz pour les preuves
- [ ] Fuzzer pour les entrées publiques
- [ ] Fuzzer pour les VK
- [ ] Corpus de graines diversifié

### 5.2 Résultats

- [ ] Pas de crash après 1M+ itérations
- [ ] Pas de panic
- [ ] Pas de fuite mémoire (valgrind)

## 6. Performance

### 6.1 Benchmarks

```bash
cargo bench -- halo2
```

- [ ] Vérification < 100ms (preuve standard)
- [ ] Mémoire < 100MB
- [ ] Pas de dégradation > 10% vs baseline

### 6.2 Scalabilité

- [ ] Test avec 1000 preuves/minute
- [ ] Test avec charge maximale
- [ ] Pas de fuite mémoire sous charge

## 7. Documentation

- [ ] Commentaires de sécurité à jour
- [ ] Guide d'intégration sécurisée
- [ ] Procédure d'incident
- [ ] Contact security team

## Signatures

| Rôle | Nom | Date | Signature |
|------|-----|------|-----------|
| Security Engineer | | | |
| Lead Cryptographer | | | |
| DevOps | | | |

## Notes

- Cette checklist est basée sur les standards TSN
- Tout échec doit être documenté et corrigé
- La checklist doit être revue à chaque changement majeur
