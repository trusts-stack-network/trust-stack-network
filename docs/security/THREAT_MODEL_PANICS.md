# Threat Model: Panics et DoS dans TSN

## Résumé Exécutif

Ce document analyse les risques de sécurité liés aux panics (`unwrap`, `expect`, `panic!`) dans le codebase TSN, en particulier dans les modules critiques (core, consensus, crypto, network).

**Sévérité**: CRITIQUE  
**Probabilité**: ÉLEVÉE (code existant avec unwraps non documentés)  
**Impact**: Crash de nœud, déni de service réseau, perte de consensus

---

## Scénarios d'Attaque

### 1. DoS via Message Réseau Malformé

**Vecteur**: Un attaquant envoie un message réseau spécialement conçu.

**Exemple vulnérable**:
```rust
// Code vulnérable (hypothétique)
fn process_message(data: &[u8]) {
    let header = parse_header(data).unwrap(); // PANIC si malformé
    let payload = &data[4..header.len]; // PANIC si header.len > data.len
}
```

**Impact**: Crash immédiat du nœud, déconnexion du réseau.

**Mitigation**:
- Validation explicite avant unwrap
- Utilisation de `?` avec propagation d'erreur
- Fuzzing systématique des parsers

### 2. DoS via Timestamp Extrême

**Vecteur**: Manipulation de timestamps dans les blocs ou messages.

**Exemple vulnérable**:
```rust
// Code vulnérable (hypothétique)
let duration = SystemTime::now()
    .duration_since(UNIX_EPOCH + Duration::from_secs(timestamp))
    .unwrap(); // PANIC si timestamp dans le futur
```

**Impact**: Panic lors de la validation de blocs futurs.

**Mitigation**:
- Utilisation de `checked_duration_since`
- Validation des bornes avant opération

### 3. DoS via État Corrompu

**Vecteur**: Base de données corrompue ou state invalide.

**Exemple vulnérable**:
```rust
// Code vulnérable (hypothétique)
let account = db.get_account(id).unwrap(); // PANIC si account inexistant
let balance = account.balance.checked_add(amount).unwrap(); // PANIC si overflow
```

**Impact**: Crash lors de la récupération d'état, impossibilité de redémarrer.

**Mitigation**:
- Gestion gracieuse des données manquantes
- Utilisation de `checked_add`/`saturating_add`
- Validation de l'intégrité au démarrage

### 4. DoS via Consensus Manipulation

**Vecteur**: Blocs de consensus malformés.

**Exemple vulnérable**:
```rust
// Code vulnérable (hypothétique)
let proof = verify_proof(&block.proof).unwrap(); // PANIC si preuve invalide
```

**Impact**: Split de chaîne, perte de consensus.

**Mitigation**:
- Validation complète avant acceptation
- Rejet gracieux des blocs invalides

---

## Matrice de Risque

| Module | Unwraps | Risque DoS | Priorité |
|--------|---------|------------|----------|
| core/block.rs | ÉLEVÉ | CRITIQUE | P0 |
| core/transaction.rs | ÉLEVÉ | CRITIQUE | P0 |
| core/state.rs | MOYEN | ÉLEVÉ | P1 |
| consensus/pow.rs | MOYEN | ÉLEVÉ | P1 |
| consensus/validation.rs | ÉLEVÉ | CRITIQUE | P0 |
| crypto/* | FAIBLE | MOYEN | P2 |
| network/* | ÉLEVÉ | CRITIQUE | P0 |

---

## Recommandations

### Court Terme (1-2 semaines)

1. **Audit immédiat** des modules network/ et consensus/validation.rs
2. **Remplacement** des unwraps critiques par des `Result`/`Option`
3. **Ajout** de tests de régression pour chaque unwrap supprimé

### Moyen Terme (1 mois)

1. **Implémentation** du fuzzing systématique (cargo-fuzz)
2. **Configuration** CI pour bloquer les nouveaux unwraps
3. **Documentation** de tous les unwraps restants (avec justification)

### Long Terme (3 mois)

1. **Certification** formelle des modules critiques
2. **Audit** externe de sécurité
3. **Bug bounty** pour les vulnérabilités DoS

---

## Checklist de Validation

Avant chaque release:

- [ ] `cargo clippy -- -D unwrap_used` passe
- [ ] Tests fuzz passent (24h minimum)
- [ ] Audit unwraps manuel complété
- [ ] Documentation des unwraps restants à jour
- [ ] Tests de charge DoS passent

---

## Références

- [Rust Security Guidelines](https://rust-lang.github.io/rust-clippy/master/index.html#unwrap_used)
- [OWASP DoS Prevention](https://owasp.org/www-community/attacks/Denial_of_Service)
- [The DAO Post-Mortem](https://blog.ethereum.org/2016/06/17/critical-update-re-dao-vulnerability/)
- [Wormhole Hack Analysis](https://medium.com/coinmonks/wormhole-hack-analysis-8acc2a343c3c)

---

## Historique des Révisions

| Date | Auteur | Changement |
|------|--------|------------|
| 2024-XX-XX | Marcus.R | Création initiale |

---

**Classification**: TSN-INTERNAL-SECURITY  
**Distribution**: Équipe Core, Équipe Security
