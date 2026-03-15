# TSN UI Redesign — Creative Brief
## Trust Stack Network Visual Identity 2.0

**Date:** 15 mars 2026
**Demande CEO:** Refonte UI avec couleurs du code TSN, effets modernes et dynamiques
**Référence maquette:** 192.168.1.170:5003

---

## 🎨 PALETTE COULEURS TSN — EXTRAITE DU CODE

### Couleurs principales
```css
/* Background Layers */
--bg-primary: #0a0e14      /* Noir spatial profond */
--bg-secondary: #161b22cc  /* Bleu-noir transparent (80%) */
--bg-tertiary: #0d1117a6   /* Overlay subtil (60%) */

/* Accents Signature TSN */
--accent-blue: #58a6ff     /* Bleu quantum */
--accent-purple: #a371f7   /* Violet cryptographique */
--accent-gradient: linear-gradient(135deg, #58a6ff 0%, #a371f7 100%)

/* Typography */
--text-primary: #e6edf3    /* Blanc cassé lumineux */
--text-secondary: #8b949e  /* Gris technique */

/* States */
--success: #3fb950         /* Vert validation */
--danger: #f85149          /* Rouge alerte */
--warning: #d29922         /* Orange caution */
```

### Philosophie couleur
- **#58a6ff (Bleu quantum)** → Technologie avancée, fiabilité cryptographique
- **#a371f7 (Violet crypto)** → Innovation post-quantique, mystère mathématique
- **Gradient bleu→violet** → Transition vers l'ère post-quantique
- **Background ultra-sombre** → Sobriété technique, focus sur le contenu

---

## ✨ EFFETS MODERNES À IMPLÉMENTER

### 1. Animations fluides
- **Hover states** avec glow bleu-violet
- **Transitions** 0.2s ease sur tous les éléments interactifs
- **Transform translateY(-1px/-2px)** pour les boutons et cards
- **Backdrop-filter: blur(12px)** pour la profondeur

### 2. Effets dynamiques
- **Gradient animé** sur les éléments principaux (title, buttons)
- **Tab glow animation** avec sparkles pour les états actifs
- **Loading states** avec pulse et spin keyframes
- **Box-shadow** réactif avec les couleurs d'accent

### 3. Typography moderne
- **Font-family:** 'Inter' pour le texte, 'Monaco'/'Menlo' pour le code
- **Background-clip: text** pour les gradients sur les titres
- **Letter-spacing** négatif pour les gros titres (-0.02em)
- **Text-transform: uppercase** pour les labels avec letter-spacing 0.05em

---

## 🚀 LANDING PAGE — PRIORITÉ 1

### Éléments à moderniser
1. **Hero section** — Logo TSN + titre avec gradient animé
2. **Features grid** — 3 colonnes avec icons gradient + hover effects
3. **Comparison table** — Styling moderne avec row hover
4. **Interactive demos** — Plonky2 proof generator avec status animations
5. **Nav links** — Primary/secondary buttons avec effets

### Composants techniques existants
- ✅ **ML-DSA-65 signature demo** (3,309 bytes)
- ✅ **Plonky2 WASM integration** avec preuves STARK temps réel
- ✅ **Comparison Zcash/Monero** sur quantum-resistance
- ✅ **Tech specs** détaillées (FIPS 204, Goldilocks field, Poseidon)

---

## 📱 RESPONSIVE & ACCESSIBILITÉ

### Breakpoints
- **Desktop:** 800px+ (design principal)
- **Tablet:** 768px (grid features → 1 colonne)
- **Mobile:** < 768px (navigation adaptée)

### Standards
- **Contraste minimum:** WCAG AA sur tous les texts
- **Focus states** visibles avec box-shadow accent
- **Animation respectueuse** (pas de clignotement agressif)

---

## 🎯 COHÉRENCE DE MARQUE

### Ton visuel
- **Futuriste** mais **accessible** — pas intimidant pour les nouveaux utilisateurs
- **Technique** mais **élégant** — ne sacrifie pas l'UX pour l'esthétique
- **Innovation** mais **confiance** — design moderne qui inspire la fiabilité

### Éléments de différenciation
1. **Quantum-first design** → Couleurs et animations évoquent la physique quantique
2. **Code transparency** → Signatures et preuves visibles, pas cachées
3. **Performance visible** → Temps réels d'exécution (proof time, verify time)
4. **Technical honesty** → Comparison table factuelle avec concurrents

---

## 📋 TIMELINE IMPLÉMENTATION

### Phase 1 — Landing Page (Semaine 1)
- [x] Extraction palette couleurs
- [ ] Application couleurs TSN sur Hero section
- [ ] Modernisation effects sur Features grid
- [ ] Polish des animations interactive demos

### Phase 2 — Wallet Interface (Semaine 2)
- [ ] Application palette sur Wallet/Explorer toggle
- [ ] Modernisation des cards et forms
- [ ] Amélioration des status messages et loading states

### Phase 3 — Finitions (Semaine 3)
- [ ] Tests responsive tous devices
- [ ] Optimisation performance animations
- [ ] Validation accessibilité complète

---

*Ce brief guide l'équipe technique pour maintenir la cohérence visuelle TSN tout en modernisant l'interface. Chaque couleur et effet a une justification technique et de marque.*