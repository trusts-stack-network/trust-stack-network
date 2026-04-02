# Guide d'Implémentation UI TSN — Capturer & Valider la Palette Couleurs

*16 mars 2026 — Zoe.K, Brand & Communications*

## TL;DR
Protocole pour synchroniser la palette couleurs entre la maquette design (192.168.1.170:5003) et l'implémentation React/CSS. Garantit la cohérence brand à travers tous les touchpoints TSN.

## Étape 1 : Capture Couleurs Maquette

### Accès à la Maquette de Référence
- **URL de base :** `http://192.168.1.170:5003`
- **Outil recommandé :** DevTools navigateur + Color Picker extension
- **Format de sortie :** Variables CSS avec notation hexadécimale précise

### Couleurs à Capturer & Valider

#### Couleurs Primaires (confirmées dans App.css)
```css
:root {
  /* ✅ VALIDÉ - Correspond à la maquette */
  --bg-primary: #0a0e14;        /* Noir Quantum */
  --accent-blue: #58a6ff;        /* Bleu Plonky */
  --accent-purple: #a371f7;      /* Violet ML-DSA */
  --accent-gradient: linear-gradient(135deg, #58a6ff 0%, #a371f7 100%);
}
```

#### Couleurs Secondaires (à re-vérifier)
```css
  --bg-secondary: rgba(22, 27, 34, 0.8);   /* Cards/overlays */
  --bg-tertiary: rgba(13, 17, 23, 0.6);    /* Input backgrounds */
  --border-color: rgba(48, 54, 61, 0.6);   /* Bordures subtiles */
  --text-primary: #e6edf3;                 /* Texte principal */
  --text-secondary: #8b949e;               /* Texte secondaire */
```

### Processus de Validation

1. **Screenshot de référence** de chaque état UI :
   - Landing page (état initial)
   - Wallet dashboard (avec balance)
   - Explorer (liste transactions)
   - States hover/focus/disabled

2. **Extraction couleurs avec précision** :
   ```bash
   # Utiliser l'outil ColorSync (macOS) ou équivalent
   # Capturer en format hex exact, pas d'approximation
   ```

3. **Test de contraste WCAG 2.1 AA** :
   - Ratio text-primary/background ≥ 4.5:1
   - Ratio text-secondary/background ≥ 3:1
   - Validation des états focus/hover

## Étape 2 : Synchronisation React Components

### Fichiers CSS à Maintenir en Cohérence

```
wallet/src/App.css              → Variables racine
wallet/src/Landing.css          → Page d'accueil
wallet/src/Explorer.css         → Interface blockchain
wallet/src/components/Faucet.css → Faucet game
```

### Pattern de Nommage des Variables CSS

```css
/* ✅ CONVENTION TSN */
--element-state: #value;

/* Exemples conformes */
--bg-primary: #0a0e14;           /* bg- pour backgrounds */
--accent-blue: #58a6ff;          /* accent- pour couleurs signature */
--text-secondary: #8b949e;       /* text- pour typographie */
--border-color: rgba(48,54,61,0.6); /* Descriptif direct pour les autres */
```

### Validation d'Implémentation

```css
/* ❌ À éviter - couleurs hardcodées */
.button { background: #58a6ff; }

/* ✅ Correct - utilisation des variables */
.button { background: var(--accent-blue); }
```

## Étape 3 : Tests Cross-Platform

### Navigateurs de Référence
- **Chrome 94+** (navigation principale)
- **Firefox 89+** (compatibilité)
- **Safari 14+** (gradient rendering)
- **Edge 94+** (environnement corporate)

### Résolutions Critiques
- **1920×1080** (desktop standard)
- **1366×768** (laptop entry-level)
- **430×932** (iPhone 15 Pro)
- **412×915** (Android flagship)

### Tests d'Accessibilité
```css
/* Validation prefers-reduced-motion */
@media (prefers-reduced-motion: reduce) {
  * { transition-duration: 0.01ms !important; }
}

/* Test mode contrast élevé */
@media (prefers-contrast: high) {
  :root { --border-color: rgba(255, 255, 255, 0.8); }
}
```

## Étape 4 : Build & Deploy Validation

### Pre-Deploy Checklist

#### Technique
- [ ] `npm run build` sans warnings
- [ ] Lighthouse Score ≥ 95 (performance + a11y)
- [ ] Bundle size < 500KB gzip
- [ ] Pas de couleurs hardcodées dans le build

#### Brand
- [ ] Gradient signature présent sur tous les CTA
- [ ] Cohérence typographique (Inter + JetBrains Mono)
- [ ] Animations 60fps sur tous les devices tests
- [ ] Dark theme par défaut respecté

#### Fonctionnel
- [ ] Navigation fluid entre Wallet/Explorer
- [ ] Feedback hover/focus sur tous les éléments interactifs
- [ ] Responsive parfait 1366px → 430px
- [ ] Aucun élément UI cassé en dev/staging/prod

## Signatures Brand dans le Code

### Header Typique d'un Composant TSN
```tsx
/**
 * TSN UI Component — Post-Quantum Design System
 *
 * Couleurs : Noir Quantum (#0a0e14) + Gradient Signature (Bleu → Violet)
 * Animation : 60fps smooth, prefers-reduced-motion compliant
 * Typography : Inter (UI) + JetBrains Mono (crypto data)
 *
 * @quantum-safe Respecte les guidelines brand TSN
 */
```

### Validation Git Pre-Commit
```bash
# Hook pour vérifier cohérence couleurs
git diff --name-only | grep -E '\.(css|tsx?)$' | xargs grep -l '#[0-9a-f]\{6\}' && echo "❌ Couleur hardcodée détectée"
```

## Messages de Communication Post-Deploy

### Discord FR (Internal Team)
```markdown
🎨 **UI 2.0 Validation Complete !**

Palette couleurs synchronisée avec la maquette de référence. Lighthouse Score 98/100.

La crypto post-quantique n'a jamais eu une interface aussi cohérente.

Next : Tests utilisateurs beta + mobile optimization.
```

### Twitter/X EN (Public Announcement)
```markdown
🎯 TSN UI 2.0 is now pixel-perfect.

Every gradient calculated, every animation optimized, every color meaningful.

This is what happens when quantum-safe crypto meets obsessive design standards.

Try the smoothest post-quantum wallet: wallet.tsn.network
```

---

**Quantum-resistant by design, elegant by obsession.**
*TSN Brand Guidelines — Always evolving, never compromising.*