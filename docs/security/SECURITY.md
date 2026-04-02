# Politique de Sécurité - Trust Stack Network

## Version supportée

| Version | Supportée          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Signaler une vulnérabilité

### Processus de divulgation responsable

Si vous découvrez une vulnérabilité de sécurité dans Trust Stack Network, nous vous demandons de suivre ce processus de divulgation responsable :

1. **Ne pas divulguer publiquement** la vulnérabilité avant qu'elle ne soit corrigée
2. **Nous contacter** directement via les canaux sécurisés ci-dessous
3. **Fournir** autant de détails que possible :
   - Description de la vulnérabilité
   - Étapes pour reproduire
   - Impact potentiel
   - Suggestions de correction (si applicable)

### Canaux de contact

- **Email sécurité:** security@truststack.network
- **PGP Key:** [Disponible sur demande]
- **Temps de réponse visé:** 48 heures

### Ce que vous pouvez attendre

- **Accusé de réception** sous 48 heures
- **Évaluation** de la vulnérabilité sous 7 jours
- **Correctif** et divulgation coordonnée
- **Reconnaissance** dans les notes de release (si souhaité)

### Scope

Les vulnérabilités suivantes sont dans le scope :

- Vulnérabilités cryptographiques
- Bugs de consensus
- Failles de sécurité réseau
- Problèmes de validation
- Fuites d'informations

Hors scope :

- Attaques par déni de service (DoS) basiques
- Problèmes de configuration utilisateur
- Vulnérabilités dans les dépendances tierces (signaler upstream)

## Mesures de sécurité

### Cryptographie post-quantique

TSN utilise des primitives cryptographiques résistantes aux attaques quantiques :

- **Signatures:** ML-DSA-65 (FIPS 204)
- **Hachage:** Poseidon2
- **Preuves ZK:** Plonky2 STARKs

### Audit et tests

- Tests de régression pour chaque vulnérabilité connue
- Fuzzing continu avec cargo-fuzz
- Property-based testing avec proptest
- Revues de code systématiques

### Bonnes pratiques

- Pas de `unwrap()` ou `expect()` dans le code de production
- Validation exhaustive des entrées
- Timeouts sur les opérations bloquantes
- Rate limiting sur les interfaces réseau

## Historique des vulnérabilités

| Date | CVE | Description | Sévérité | Statut |
|------|-----|-------------|----------|--------|
| - | - | Aucune vulnérabilité publique connue | - | - |

## Remerciements

Nous remercions les chercheurs en sécurité qui ont contribué à la sécurité de TSN :

*Liste à compléter*

---

**Dernière mise à jour:** 2024
