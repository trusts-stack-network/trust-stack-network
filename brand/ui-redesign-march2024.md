# Refonte UI Frontend TSN — Mars 2024  
*Une interface qui respire la sécurité post-quantique*

> 🌌 **L’interface ne doit pas juste *sembler* futuriste — elle doit *incarner* la confiance quantique.**

---

## 🎯 Objectif  
Moderniser l’UI du wallet TypeScript/Vite avec :  
✅ Palette dynamique **cyan/violet post-quantique** (inspirée de la visualisation des circuits ZK)  
✅ Glassmorphism subtil (transparence + flou contrôlé pour profondeur sans surcharge)  
✅ Micro-animations fluides (réactivité perçue, feedback visuel clair)  
✅ Accessibilité WCAG AA+ (contrastes, focus states, réduction des animations sensibles)

---

## 🎨 Palette de couleurs  
Basée sur la **signature visuelle TSN** :  
| Élément              | Couleur (HEX) | Usage                     |
|----------------------|---------------|---------------------------|
| `cyan-quantum`       | `#00F0FF`     | Actions primaires, succès |
| `violet-proof`       | `#7C3AED`     | Sécurité, ZK proofs, badges |
| `dark-core`          | `#0A0A0F`     | Fond principal            |
| `glass-surface`      | `rgba(255,255,255,0.06)` | Cartes, modals (backdrop-filter) |
| `accent-flicker`     | `#C084FC`     | Animations de transition  |

> 💡 *Le cyan = transmission d’état quantique ; le violet = preuve cryptographique non interactive.*

---

## ✨ Animations clés  
- **Entrée des cartes** : `fade-up + scale-in` (150ms ease-out)  
- **Validation transaction** : pulse subtil du badge *“Quantum-Safe”* (3 cycles, 0.8s)  
- **Chargement preuve ZK** : cercle de progress avec dégradé cyan→violet (pas de spinner statique)  
- **Hover sur boutons** : bordure *glitch* ultra-légère (0.05s) → rappelle la rupture avec la crypto classique

> ⚠️ *Toute animation est désactivable via préférence utilisateur (`prefers-reduced-motion`)*

---

## 📱 Design system  
- **Typography** : `Inter` (UI) + `JetBrains Mono` (adresses, hashes, logs)  
- **Grille** : 8px baseline (cohérence avec les logs Rust)  
- **Icons** : lignes fines, remplissage partiel (style *outline with fill-on-hover*)  
- **Responsive** : mobile-first, mais *desktop-first for power users* → layout split wallet/ explorer/ settings

---

## 🔐 Sécurité visuelle  
- Aucun élément ne *cachette* une action critique (ex: confirmation de signature)  
- Les messages d’erreur utilisent `violet-proof` + icône `🔒`  
- Les succès utilisent `cyan-quantum` + icône `✨`  
- Les *nullifiers* et *commitment roots* sont affichés avec un fond `glass-surface` + copie à un clic

---

## 📅 Roadmap  
| Étape | Livrable | Date cible |
|-------|----------|------------|
| Phase 1 | Palette & composants de base | 12 mars |
| Phase 2 | Animations & transitions | 19 mars |
| Phase 3 | Accessibilité & dark/light toggle | 26 mars |
| Phase 4 | Intégration wallet ↔ explorer ↔ API | 2 avril |

---

## 🗣️ Pour la communauté  
> *« On ne cache pas la complexité — on la rend *intuitivement* compréhensible. »*  
> — Zoe.K, Brand & Comms, TSN

---

**Next**:  
→ PR `ui/refactor-vite-theme` (branch `feat/ui-redesign`)  
→ Review par Kai.V (archi) + Lena.S (UX)  
→ Annonce Discord le **13 mars à 18h UTC**
