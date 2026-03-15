# TSN UI Redesign — Guide d'Implémentation (Mars 2026)

*CEO Request du 6 mars : Nouveau design dynamique basé maquette dev 192.168.1.170:5003*

## 🎯 Objectif : Landing Page Dynamique

Transformation de `/opt/tsn/wallet/src/Landing.tsx` avec les nouvelles couleurs TSN et effets modernes. Focus sur l'impact visuel immédiat et la différenciation quantum-native.

## 🎨 Palette de Couleurs Extraite

### Variables CSS Principales
```css
:root {
  /* Backgrounds (Profondeur Quantique) */
  --bg-primary: #0a0e14;      /* Espace profond */
  --bg-secondary: #161b22;    /* Surface secondaire */
  --bg-tertiary: #0d1117;     /* Accents tertiaires */

  /* Nouveau : Gradients d'Ambiance */
  --bg-radial-blue: radial-gradient(ellipse at top, rgba(88, 166, 255, 0.12) 0%, transparent 60%);
  --bg-radial-purple: radial-gradient(ellipse at bottom right, rgba(163, 113, 247, 0.08) 0%, transparent 60%);
  --bg-quantum:
    radial-gradient(ellipse at top, rgba(88, 166, 255, 0.08) 0%, transparent 50%),
    radial-gradient(ellipse at bottom right, rgba(163, 113, 247, 0.06) 0%, transparent 50%);

  /* Accents (Signatures Post-Quantiques) */
  --accent-blue: #58a6ff;     /* ML-DSA Blue */
  --accent-purple: #a371f7;   /* STARK Purple */
  --accent-gradient: linear-gradient(135deg, #58a6ff 0%, #a371f7 100%);

  /* Nouveaux : Variants Lumineux */
  --accent-blue-bright: #00d4ff;   /* Pour hover states */
  --accent-purple-bright: #b97fff; /* Pour active states */
  --accent-glow-blue: rgba(88, 166, 255, 0.4);
  --accent-glow-purple: rgba(163, 113, 247, 0.4);

  /* Textes (Optimisés Lisibilité) */
  --text-primary: #e6edf3;
  --text-secondary: #8b949e;
  --text-muted: #6e7681;
  --border-color: #30363d;

  /* États Système */
  --success: #3fb950;
  --danger: #f85149;
  --warning: #d29922;
}
```

## ⚡ Effets Dynamiques à Implémenter

### 1. Hero Section Améliorée
```css
.landing {
  background: var(--bg-primary);
  background-image: var(--bg-quantum);
  min-height: 100vh;
  transition: background 0.3s ease;
}

.title {
  font-size: 4rem; /* Augmenté de 3.5rem */
  background: var(--accent-gradient);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  animation: quantum-pulse 3s ease-in-out infinite;
  text-shadow: 0 0 30px rgba(88, 166, 255, 0.3);
}

@keyframes quantum-pulse {
  0%, 100% {
    filter: brightness(1) saturate(1);
    transform: scale(1);
  }
  50% {
    filter: brightness(1.1) saturate(1.2);
    transform: scale(1.02);
  }
}
```

### 2. Boutons avec Glow Effects
```css
.nav-link, .demo-button, .whitepaper-link {
  background: var(--accent-gradient);
  position: relative;
  overflow: hidden;
  box-shadow: 0 4px 15px rgba(88, 166, 255, 0.3);
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

.nav-link:hover, .demo-button:hover, .whitepaper-link:hover {
  transform: translateY(-3px) scale(1.02);
  box-shadow: 0 8px 25px rgba(88, 166, 255, 0.5);
}

.nav-link::before {
  content: '';
  position: absolute;
  top: 0;
  left: -100%;
  width: 100%;
  height: 100%;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
  transition: left 0.5s;
}

.nav-link:hover::before {
  left: 100%;
}
```

### 3. Cards avec Glass Effect
```css
.feature, .demo-card {
  background: rgba(22, 27, 34, 0.7);
  backdrop-filter: blur(16px);
  border: 1px solid rgba(88, 166, 255, 0.2);
  box-shadow:
    0 8px 32px rgba(0, 0, 0, 0.3),
    inset 0 1px 0 rgba(255, 255, 255, 0.1);
  transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
}

.feature:hover {
  transform: translateY(-5px);
  border-color: rgba(88, 166, 255, 0.5);
  box-shadow:
    0 12px 40px rgba(0, 0, 0, 0.4),
    0 0 30px rgba(88, 166, 255, 0.3);
}
```

### 4. Icones Animées
```css
.feature-icon {
  background: var(--accent-gradient);
  animation: icon-float 4s ease-in-out infinite;
  box-shadow: 0 0 20px rgba(88, 166, 255, 0.4);
}

@keyframes icon-float {
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-8px); }
}

.status-icon {
  transition: all 0.3s ease;
}

.demo-status.loading .status-icon {
  animation: quantum-spin 1s linear infinite;
  color: var(--accent-blue-bright);
  text-shadow: 0 0 10px var(--accent-glow-blue);
}

@keyframes quantum-spin {
  from {
    transform: rotate(0deg) scale(1);
    filter: hue-rotate(0deg);
  }
  to {
    transform: rotate(360deg) scale(1.1);
    filter: hue-rotate(360deg);
  }
}
```

## 🚀 Implémentation par Phase

### Phase 1 : Foundation CSS (Cette semaine)
1. **Mise à jour variables** dans `/opt/tsn/wallet/src/index.css`
2. **Background quantum** sur `.landing`
3. **Hero section améliorée** avec nouveau title size + animation
4. **Boutons glow effects** sur navigation

### Phase 2 : Interactions Avancées (Semaine prochaine)
1. **Glass morphism** sur toutes les cards
2. **Hover animations** avec translateY + scale
3. **Loading states** avec quantum-spin
4. **Micro-interactions** sur tous les éléments cliquables

### Phase 3 : Polish & Performance (Fin mars)
1. **Animations responsives** (réduction sur mobile)
2. **Prefers-reduced-motion** support
3. **60fps optimization**
4. **Dark/light theme toggle**

## 📱 Responsive Adaptations

### Mobile (< 768px)
```css
@media (max-width: 767px) {
  .title {
    font-size: 2.5rem;
    animation: none; /* Économie batterie */
  }

  .feature:hover {
    transform: none; /* Pas de hover sur mobile */
  }

  .landing {
    background-image: none; /* Backgrounds simples */
  }
}
```

### Préférences Utilisateur
```css
@media (prefers-reduced-motion: reduce) {
  * {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}
```

## 🎬 Guideline Animation

### Timing Functions TSN
- **Entrée** : `cubic-bezier(0.4, 0, 0.2, 1)` (Material ease-out)
- **Sortie** : `cubic-bezier(0.4, 0, 1, 1)` (Material ease-in)
- **Hover** : `ease-out` (réactivité)
- **Loading** : `ease-in-out` (fluidité)

### Durées Standards
- **Hover effects** : 0.3s
- **Page transitions** : 0.4s
- **Pulse animations** : 3s
- **Loading states** : 1s

### Restrictions Performance
- Maximum **3 animations simultanées** sur mobile
- **will-change** uniquement pendant l'animation
- **transform** et **opacity** prioritaires (GPU layers)
- Éviter **box-shadow** animations sur mobile

## 🔧 Checklist Implementation

### Technique
- [ ] Variables CSS mises à jour
- [ ] Background quantum appliqué
- [ ] Hero animations fonctionnelles
- [ ] Glass morphism sur cards
- [ ] Hover states avec glow
- [ ] Loading animations optimisées
- [ ] Responsive breakpoints testés
- [ ] Performance 60fps validée

### Brand
- [ ] Couleurs TSN respectées
- [ ] Identité post-quantique visible
- [ ] Différenciation vs concurrence
- [ ] Cohérence avec design system v2
- [ ] Accessibilité preserved
- [ ] Dark theme compatible

---

**Note technique** : Ces modifications s'appuient sur l'existant Landing.tsx/css sans rupture. Chaque effet peut être implémenté progressivement et désactivé individuellement si nécessaire.

**Performance target** : 60fps sur desktop, 30fps mobile, <200ms Time to Interactive.