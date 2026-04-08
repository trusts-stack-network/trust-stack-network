# PLAN — Hybrid Sonnet + Qwen Local : Économie de Tokens

**Created:** 2026-03-09
**Status:** PLANIFIÉ
**Last updated:** 2026-03-09

---

## Architecture Hybride

```
SONNET (cerveau/Architect) → planifie, spec, review, diagnostic erreurs
QWEN3-72B local (workers) → exécute, code, itère avec cargo check
```

**Économie de base vs full Sonnet : ~65-70%**

---

## Hardware Recommandé

### Option 1 — Rig Ryzen 5600 (DÉJÀ DISPONIBLE, 0€)
- 1×3090 (24GB) + 4×3060 (48GB) + 1×3060ti (12GB) = 84GB VRAM
- 64GB RAM
- Qwen3-72B Q4 (~42GB) → rentre en VRAM, ~15-20 tok/s
- **Tester en premier avant tout achat**

### Option 2 — EPYC + 3×3090 (~1600€ pour 2 × 3090 occasion)
- 3×3090 = 72GB VRAM + 512GB RAM + 256 threads
- Qwen3-72B → tout en VRAM, ~20-25 tok/s
- Qwen3-235B-A22B (MoE) → 72GB GPU + 58GB RAM, ~12-18 tok/s
- **Meilleur setup si 72B insuffisant sur Rust**

---

## 7 Techniques d'Optimisation

### 1. Qwen d'abord, Sonnet en escalade
- Qwen tente seul la tâche
- cargo check → passe ? → fini (0 tokens Sonnet)
- cargo check → rate ? → envoie l'erreur à Sonnet pour diagnostic
- **Économie** : ~30-40% des tâches simples passent sans Sonnet

### 2. Sonnet écrit les tests, Qwen code
- Sonnet produit uniquement le test unitaire (20 lignes)
- Qwen code jusqu'à ce que cargo test passe
- Le test EST la spec — pas besoin de spec détaillée
- **Économie** : ~50% de tokens Sonnet output

### 3. Playbooks réutilisables
- Sonnet écrit UNE FOIS des templates pour patterns récurrents de TSN :
  - "Pour ajouter un message P2P : 1) enum Message 2) Serialize 3) handler..."
  - "Pour ajouter un endpoint API : 1) route 2) handler 3) types..."
- Stockés localement, Qwen les suit sans redemander
- **Économie** : 1 appel Sonnet au lieu de N pour le même pattern

### 4. Diff-only review
- Quand Qwen finit, Sonnet review UNIQUEMENT le diff git
- Pas le fichier entier de 800 lignes, juste les +/- (50 lignes)
- **Économie** : ~70% de tokens input sur la review

### 5. Batch planning
- Grouper 3-5 tâches similaires en un seul appel Sonnet
- Sonnet charge le contexte une fois, produit 5 specs d'un coup
- Qwen exécute séquentiellement
- **Économie** : 1 appel Sonnet (contexte chargé 1×) au lieu de 5

### 6. Cache de signatures / index local
- Index automatique des types/traits/fn de TSN (tsn_get_module_api)
- Mis à jour après chaque commit
- Qwen consulte l'index au lieu de lire les fichiers entiers
- Sonnet n'a plus besoin de "cartographier" à chaque tâche
- **Économie** : ~2-3K tokens input économisés par tâche

### 7. Sonnet "compile" son raisonnement en règles
- Après chaque fix, Sonnet extrait la règle générale :
  - "Dans TSN, tous les Hash doivent implémenter AsRef<[u8; 32]>"
  - "Les messages P2P doivent dériver Clone + Debug + Serialize"
- Règles sauvées localement → Qwen les applique automatiquement
- **Économie** : évite de redécouvrir les mêmes erreurs

---

## Estimation Économie Cumulée

| Métrique | Full Sonnet | Hybride basique | Hybride + 7 techniques |
|----------|-------------|-----------------|------------------------|
| Tokens Sonnet/tâche | ~38K | ~12K | **~4-5K** |
| Tâches passant par Sonnet | 100% | 100% | **60-70%** |
| Tokens Sonnet/jour (7 bots, 30-50 tâches) | ~1.5M | ~500K | **~150-200K** |
| **Réduction vs full Sonnet** | — | -65% | **-87-90%** |

---

## Implémentation dans tsn-team

### Fichiers à modifier
- `bots/base.py` — ajouter logique escalade Qwen→Sonnet
- `config.py` — config dual-model (MODEL_BRAIN + MODEL_WORKER)
- `bots/base.py` — cache playbooks + règles locales
- `scripts/build_signatures_index.py` — à créer (index types/traits)

### Flow par tâche
```
1. Bot reçoit tâche
2. Consulte playbooks + règles locales
3. Qwen tente seul (contexte chirurgical + tools)
4. cargo check / cargo test
5. Si pass en <3 itérations → DONE (0 Sonnet)
6. Si fail → envoie erreur + contexte minimal à Sonnet
7. Sonnet diagnostique, renvoie fix précis
8. Qwen applique → cargo check → boucle
9. Sonnet review le diff final (optionnel)
10. Si nouvelle règle découverte → sauvée en local
```

### Métriques à logger
- `sonnet_tokens_used` — tokens Sonnet consommés par tâche
- `qwen_tokens_used` — tokens Qwen consommés par tâche
- `escalation_count` — nombre de fois où Qwen a escaladé à Sonnet
- `cargo_check_iterations` — nombre d'itérations avant pass
- `task_success_rate` — taux de réussite par modèle
- `playbook_hits` — nombre de fois qu'un playbook a été réutilisé

---

## Priorité de test

1. **Installer Qwen3-72B sur le Ryzen** (0€, tester si suffisant comme worker Rust)
2. **Implémenter technique #1** (escalade Qwen→Sonnet) dans bots/base.py
3. **Implémenter technique #2** (Sonnet écrit tests, Qwen implémente)
4. **Mesurer** pendant 1 semaine avec les métriques ci-dessus
5. **Décider** si upgrade EPYC + 3×3090 + Qwen3-235B vaut le coup
