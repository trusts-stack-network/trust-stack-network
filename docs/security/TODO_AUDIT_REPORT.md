# Rapport d'Audit TODO/FIXME - Trust Stack Network

**Date:** 2025-01-XX  
**Auditeur:** Marcus.R (Security & QA Engineer)  
**Version:** TSN v0.9.0-alpha  
**Statut:** EN COURS - 23 TODOs identifiés

---

## Résumé Exécutif

| Catégorie | Nombre | Criticité |
|-----------|--------|-----------|
| **Sécurité Crypto** | 5 | 🔴 CRITIQUE |
| **Consensus/Réseau** | 8 | 🟠 HAUTE |
| **Performance/DoS** | 6 | 🟡 MOYENNE |
| **Documentation** | 4 | 🟢 FAIBLE |
| **TOTAL** | **23** | - |

---

## TODOs par Fichier (Triés par Criticité)

### 🔴 CRITIQUE - Sécurité Cryptographique

#### 1. `src/crypto/pq/slh_dsa.rs:183`
```rust
/// Vérifie une signature SLH-DSA de manière constante
pub fn verify_constant_time(pk: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    // TODO: Implémenter une vérification en temps constant sans dépendance externe
    // En attendant, utiliser la vérification standard
    verify(pk, message, signature)
}
```
**Impact:** Timing attacks possibles sur la vérification de signatures  
**CVSS:** 6.5 (Medium) - Information Disclosure  
**Mitigation:** Implémenter `subtle::Choice` ou `constant_time_eq`  
**Deadline:** Avant release v1.0

#### 2. `src/crypto/legacy.rs:35`
```rust
// SAFETY: This is a temporary migration function
// TODO: Remove after block height 1_000_000
pub fn verify_legacy_signature(...) -> Result<bool>
```
**Impact:** Code legacy non sécurisé reste actif  
**Mitigation:** Planifier sunset avec hard fork  
**Deadline:** Block height 800,000 (alerte à 900,000)

#### 3. `src/crypto/commitment.rs:89`
```rust
// TODO: Vérifier la preuve Plonky2 avant d'accepter le commitment
// SECURITY: Sans cette vérification, des commitments invalides peuvent être acceptés
```
**Impact:** Acceptation de commitments non prouvés  
**CVSS:** 8.1 (High) - Integrity/Availability  
**Mitigation:** Implémenter `verify_plonky2_proof()` avant merge

#### 4. `src/crypto/nullifier.rs:156`
```rust
// TODO: Vérifier que le nullifier n'est pas déjà utilisé dans l'historique complet
// SECURITY: Nécessite une recherche efficace dans la chaîne complète
```
**Impact:** Double-spend possible si nullifier déjà utilisé  
**CVSS:** 9.8 (Critical) - Financial  
**Mitigation:** Index Bloom + vérification Merkle de l'historique

#### 5. `src/network/mempool_v2.rs:412`
```rust
// TODO: Implémenter la vérification complète des preuves ZK
// SECURITY: Les transactions avec preuves invalides ne sont pas rejetées
```
**Impact:** Mempool pollution, DoS par preuves invalides  
**CVSS:** 7.5 (High) - DoS  
**Mitigation:** Vérification Plonky2 complète avant acceptation mempool

---

### 🟠 HAUTE - Consensus et Réseau

#### 6. `src/network/sync_v2.rs:247`
```rust
// TODO: Implement proper block validation during sync
// SECURITY: Blocks downloaded during sync are not fully validated
```
**Impact:** Sync d'une chaîne invalide possible  
**Mitigation:** Validation complète avant écriture DB

#### 7. `src/network/gossip.rs:267`
```rust
NetworkMessage::GetData(_) => {
    // TODO: serve requested data
}
```
**Impact:** Peers ne peuvent pas récupérer les données demandées  
**Mitigation:** Implémenter le handler GetData

#### 8. `src/network/gossip.rs:261`
```rust
NetworkMessage::Inv(hashes) => {
    for hash in hashes {
        // TODO: request actual data if unknown
        state.known.insert(hash);
    }
}
```
**Impact:** Gossip protocol incomplet - pas de fetch des données inconnues  
**Mitigation:** Implémenter GetData request pour hashes inconnus

#### 9. `src/network/peer.rs:4`
```rust
//! Peer management for TSN P2P network
//! TODO: à implémenter proprement par le bot NETWORK
```
**Impact:** Gestion des peers minimale - pas de scoring avancé  
**Mitigation:** Implémenter PeerManager complet avec scoring

#### 10. `src/consensus/pow.rs:178`
```rust
// TODO: Vérifier que le timestamp n'est pas dans le futur
// SECURITY: Permet de miner des blocs avec timestamp futur
```
**Impact:** Attaque timestamp manipulation  
**Mitigation:** Rejeter blocs avec timestamp > now + drift_max

#### 11. `src/consensus/difficulty.rs:89`
```rust
// TODO: Ajuster la difficulté plus fréquemment pour éviter les oscillations
```
**Impact:** Instabilité du hashrate, temps de bloc irréguliers  
**Mitigation:** Algorithme DigiShield ou similaire

#### 12. `src/core/blockchain.rs:234`
```rust
// TODO: Vérifier la racine Merkle des transactions
// SECURITY: Sans vérification, inclusion de transactions non valides
```
**Impact:** Transactions invalides dans la chaîne  
**Mitigation:** Vérification Merkle root systématique

#### 13. `src/storage/sled_db.rs:156`
```rust
// TODO: Implémenter le pruning des vieilles données
// SECURITY: Croissance illimitée de la DB
```
**Impact:** DoS par remplissage disque  
**Mitigation:** Pruning configurable avec archivage optionnel

---

### 🟡 MOYENNE - Performance et DoS

#### 14. `src/network/mempool_v2.rs:289`
```rust
// TODO: Limiter la taille totale du mempool par peer
```
**Impact:** Un peer peut remplir le mempool  
**Mitigation:** Quota par peer + eviction LRU

#### 15. `src/network/api.rs:445`
```rust
// TODO: Rate limiting sur les endpoints RPC
```
**Impact:** DoS par requêtes massives  
**Mitigation:** Tower rate limiter ou similar

#### 16. `src/network/discovery.rs:234`
```rust
// TODO: Implémenter la protection contre les attaques Eclipse
```
**Impact:** Risque d'isolation du nœud  
**Mitigation:** Diversité des buckets, test de connexité

#### 17. `src/crypto/merkle_tree.rs:178`
```rust
// TODO: Optimiser avec un cache LRU pour les chemins fréquents
```
**Impact:** Performance dégradée sur grands arbres  
**Mitigation:** Cache thread-safe avec TTL

#### 18. `src/network/mempool_v2.rs:567`
```rust
// TODO: Compression des transactions en mémoire
```
**Impact:** Usage mémoire excessif  
**Mitigation:** Compression zstd des payloads

#### 19. `src/core/transaction.rs:312`
```rust
// TODO: Validation parallèle des signatures
```
**Impact:** Latence sur blocs avec beaucoup de transactions  
**Mitigation:** Rayon parallel iterator

---

### 🟢 FAIBLE - Documentation et Tests

#### 20. `tests/crypto_pq_poseidon2_comprehensive.rs:529`
```rust
// TODO: Ajouter les vrais vecteurs de test officiels NIST
```
**Impact:** Confiance réduite dans les tests  
**Mitigation:** Intégrer vecteurs NIST CAVP

#### 21. `tests/property_consensus_invariants.rs:485`
```rust
/// Régression: CVE-2023-XXXX - Validation de timestamp
// TODO: Documenter la CVE réelle une fois publique
```
**Impact:** Documentation incomplète  
**Mitigation:** Mettre à jour avec référence CVE

#### 22. `src/crypto/pq/ml_dsa.rs:89`
```rust
// TODO: Documenter les paramètres de sécurité ML-DSA-65
```
**Impact:** Documentation technique incomplète  
**Mitigation:** Ajouter tableaux de sécurité NIST

#### 23. `src/wallet/backup.rs:45`
```rust
// TODO: Implémenter le chiffrement des backups
```
**Impact:** Backups en clair sur disque  
**Mitigation:** Chiffrement AES-256-GCM avec passphrase

---

## Plan de Résolution

### Phase 1: Sécurité Critique (Sprint 1-2)
- [ ] #4: Nullifier double-spend check
- [ ] #3: Commitment Plonky2 verification
- [ ] #5: Mempool ZK proof validation
- [ ] #1: SLH-DSA constant-time verify

### Phase 2: Consensus/Réseau (Sprint 3-4)
- [ ] #6: Block validation during sync
- [ ] #10: Timestamp future check
- [ ] #12: Merkle root verification
- [ ] #7/#8: Gossip protocol completion

### Phase 3: DoS/Performance (Sprint 5)
- [ ] #14/#15: Rate limiting
- [ ] #16: Eclipse protection
- [ ] #17/#18: Caching & compression

### Phase 4: Cleanup (Sprint 6)
- [ ] #2: Legacy crypto sunset
- [ ] #20-23: Documentation & tests

---

## Tests de Régression Requis

Pour chaque TODO résolu, les tests suivants doivent être ajoutés:

1. **Test unitaire** - Vérification de la logique
2. **Test d'intégration** - Scénario réaliste
3. **Test adversarial** - Tentative de bypass
4. **Fuzz test** - Si applicable (entrées externes)

---

## Signatures

| Rôle | Nom | Date | Signature |
|------|-----|------|-----------|
| Security Engineer | Marcus.R | | |
| Lead Architect | Kai.V | | |
| Tech Lead | | | |

---

## Révisions

| Version | Date | Auteur | Changements |
|---------|------|--------|-------------|
| 1.0 | 2025-01-XX | Marcus.R | Création initiale |
