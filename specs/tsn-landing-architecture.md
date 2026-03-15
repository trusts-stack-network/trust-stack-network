# Architecture Technique - TSN Landing Page

## Table des matières
1. [Vue d'ensemble](#vue-densemble)
2. [Stack Technique](#stack-technique)
3. [Structure du Projet](#structure-du-projet)
4. [Architecture Frontend](#architecture-frontend)
5. [Performance & Optimisation](#performance--optimisation)
6. [Intégration API](#intégration-api)

## Vue d'ensemble

La landing page Trust Stack Network (TSN) est une application web statique de type Single Page Application (SPA) légère, conçue pour un temps de chargement initial < 1.5s et un score Lighthouse > 95 sur tous les critères.

### Objectifs critiques
- **FCP (First Contentful Paint)**: < 0.8s
- **TTI (Time to Interactive)**: < 2.0s
- **CLS (Cumulative Layout Shift)**: < 0.1
- **Accessibilité**: WCAG 2.1 AA

## Stack Technique

| Couche | Technologie | Justification |
|--------|-------------|---------------|
| **Structure** | HTML5 Sémantique | SEO natif, accessibilité screen readers |
| **Styling** | CSS3 (Variables, Grid, Flexbox) | Zero runtime overhead, tree-shaking natif |
| **Interactions** | Vanilla ES6+ | < 15KB JS total, pas de dépendances externes |
| **Animations** | CSS Animations + Web Animations API | 60fps garanti, thread principal déchargé |
| **Assets** | WebP/AVIF avec fallbacks | Optimisation automatique via build pipeline |
| **Hébergement** | CDN Edge (Cloudflare/Netlify) | Cache agressif, SSL automatique |

## Structure du Projet

tsn-landing/
├── src/
│   ├── index.html              # Entry point unique
│   ├── css/
│   │   ├── critical.css        # Above-the-fold (inliné)
│   │   ├── main.css            # Styles différés
│   │   ├── components/
│   │   │   ├── _hero.css
│   │   │   ├── _vision.css
│   │   │   ├── _tech.css
│   │   │   ├── _team.css
│   │   │   └── _roadmap.css
│   │   └── utils/
│   │       ├── _variables.css  # Design tokens
│   │       ├── _reset.css
│   │       └── _animations.css
│   ├── js/
│   │   ├── main.js             # Entry point
│   │   ├── modules/
│   │   │   ├── navigation.js   # Smooth scroll, mobile menu
│   │   │   ├── roadmap.js      # Timeline interactive
│   │   │   ├── animations.js   # Intersection Observer
│   │   │   └── forms.js        # Validation newsletter
│   │   └── utils/
│   │       ├── dom.js          # Helpers DOM
│   │       └── throttle.js     # Performance utils
│   └── assets/
│       ├── images/
│       │   ├── team/           # Photos optimiseés
│       │   ├── tech/           # Logos SVG
│       │   └── hero/           # Background responsive
│       └── fonts/
│           └── inter-var.woff2 # Variable font
├── dist/                       # Build output
├── docs/
└── specs/

## Architecture Frontend

### Diagramme de flux de rendu

```mermaid
graph TD
    A[Requête HTTP] --> B[CDN Edge]
    B --> C{Cache hit?}
    C -->|Oui| D[Retour 304/200]
    C -->|Non| E[Origin Server]
    E --> F[HTML Critique Inliné]
    F --> G[Preload CSS/Fonts]
    G --> H[Parsing HTML]
    H --> I[Render Tree]
    I --> J[Paint]
    J --> K[Lazy Load Images]
    K --> L[Hydratation JS]
    
    style F fill:#f9f,stroke:#333,stroke-width:2px
    style L fill:#bbf,stroke:#333,stroke-width:2px

### Stratégie de chargement

1. **Critical CSS** (14KB max) inliné dans `<head>`
   - Styles hero section
   - Variables CSS
   - Reset minimal
   
2. **Preload hints**
   <link rel="preload" href="/fonts/inter-var.woff2" as="font" type="font/woff2" crossorigin>
   <link rel="preload" href="/css/main.css" as="style">
   <link rel="prefetch" href="/assets/images/team/">

3. **Chargement différé**
   - Images : `loading="lazy"` + `decoding="async"`
   - CSS non-critique : `media="print"` trick ou `rel="stylesheet"` différé
   - JS : `type="module"` + `async` pour modules non-critiques

### Architecture CSS (ITCSS + BEM)

graph BT
    A[Settings] --> B[Tools]
    B --> C[Generic]
    C --> D[Elements]
    D --> E[Objects]
    E --> F[Components]
    F --> G[Utilities]
    
    style A fill:#e1f5fe
    style G fill:#fff3e0

**Convention de nommage BEM**:
.block__element--modifier {}
/* Ex: .roadmap__timeline-item--active */

## Performance & Optimisation

### Budgets de performance

| Ressource | Budget | Stratégie |
|-----------|--------|-----------|
| HTML initial | 50KB | Compression Brotli, minification |
| CSS total | 30KB | PurgeCSS, critical CSS extraction |
| JS total | 20KB | Tree-shaking, code splitting |
| Images | 200KB/page | WebP/AVIF, srcset responsive |
| Fonts | 35KB | Variable font unique, font-display: swap |

### Optimisations techniques

**Intersection Observer pour animations**:
const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('animate-in');
      observer.unobserve(entry.target); // One-shot
    }
  });
}, { rootMargin: '50px' });

**