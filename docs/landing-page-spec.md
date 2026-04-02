# Spécification Technique - Landing Page TSN

## Table des matières
1. [Vue d'ensemble](#vue-densemble)
2. [Architecture Technique](#architecture-technique)
3. [Structure des Sections](#structure-des-sections)
4. [Spécifications Responsive](#spécifications-responsive)
5. [Performance & Optimisation](#performance--optimisation)
6. [Références](#références)

## Vue d'ensemble

### Objectif
Développement de la landing page principale pour **Trust Stack Network (TSN)** - plateforme décentralisée de confiance distribuée. Interface vitrine responsive présentant la vision, la technologie, l'équipe et la roadmap du projet.

### Stack Technique
- **HTML5** sémantique, validé W3C
- **CSS3** avec variables CSS (custom properties)
- **Vanilla JavaScript** (ES6+), aucune dépendance externe
- **Assets** : SVG optimisés, WebP/AVIF avec fallbacks
- **Hébergement** : Static CDN (Cloudflare/Netlify)

### Contraintes
- Lighthouse score > 95 (Performance, Accessibilité, SEO)
- Temps de chargement initial < 1.5s (3G)
- Compatibilité : Chrome 90+, Firefox 88+, Safari 14+, Edge 90+
- Aucune librairie CSS/JS externe (zero-dependency)

## Architecture Technique

### Arborescence des fichiers
tsn-landing/
├── index.html
├── assets/
│   ├── css/
│   │   ├── main.css          # Styles globaux & variables
│   │   ├── sections.css      # Styles spécifiques sections
│   │   └── responsive.css    # Media queries
│   ├── js/
│   │   ├── main.js           # Initialisation & utilities
│   │   ├── animations.js     # IntersectionObserver & transitions
│   │   └── navigation.js     # Smooth scroll & mobile menu
│   └── images/
│       ├── hero/             # Images hero (responsive srcset)
│       ├── team/             # Photos équipe (WebP)
│       └── icons/            # SVG sprites
└── docs/                     # Documentation technique

### Diagramme d'architecture flux données
```mermaid
graph TD
    A[Client Browser] --> B[index.html]
    B --> C[Critical CSS Inline]
    B --> D[Async CSS Load]
    B --> E[Defer JS Bundle]
    
    E --> F[main.js]
    F --> G[IntersectionObserver]
    F --> H[Animation Controller]
    F --> I[Navigation Handler]
    
    G --> J[Lazy Load Images]
    H --> K[Scroll Reveal Effects]
    I --> L[Mobile Menu Toggle]
    
    style C fill:#f9f,stroke:#333,stroke-width:2px
    style E fill:#bbf,stroke:#333,stroke-width:2px

### Variables CSS (Design System)
:root {
  /* Couleurs TSN Brand */
  --tsn-primary: #0A192F;        /* Deep Navy */
  --tsn-secondary: #64FFDA;      /* Cyber Teal */
  --tsn-accent: #FF6B6B;         /* Alert Coral */
  --tsn-text-primary: #E6F1FF;   /* Off White */
  --tsn-text-secondary: #8892B0; /* Slate */
  
  /* Typography */
  --font-mono: 'Fira Code', 'Consolas', monospace;
  --font-sans: 'Inter', -apple-system, sans-serif;
  --font-display: 'Cal Sans', 'Inter', sans-serif;
  
  /* Spacing Scale (8px base) */
  --space-xs: 0.5rem;   /* 8px */
  --space-sm: 1rem;     /* 16px */
  --space-md: 2rem;     /* 32px */
  --space-lg: 4rem;     /* 64px */
  --space-xl: 8rem;     /* 128px */
  
  /* Animation */
  --transition-fast: 0.2s cubic-bezier(0.4, 0, 0.2, 1);
  --transition-medium: 0.4s cubic-bezier(0.4, 0, 0.2, 1);
  --transition-slow: 0.8s cubic-bezier(0.4, 0, 0.2, 1);
}

## Structure des Sections

### 1. Hero Section
**ID**: `#hero`  
**Hauteur**: 100vh (viewport full)  
**Contenu**:
- Logo TSN animé (SVG morphing)
- Tagline: "Infrastructure de confiance distribuée"
- CTA primaire: "Explorer la documentation" → `/docs`
- CTA secondaire: "Visionner la démo" → Modal video
- Background: Mesh gradient animé (Canvas 2D, fallback CSS gradient)

**Spécifications techniques**:
- Preload du font-display critique
- Canvas background avec détection `prefers-reduced-motion`
- Parallax léger sur le tagline (translateY au scroll)

### 2. Vision Section
**ID**: `#vision`  
**Layout**: Grid 2 colonnes (texte | illustration)  
**Contenu**:
- Titre: "Reconstruire la confiance numérique"
- 3 piliers (cards): Décentralisation, Vérification, Souveraineté
- Statistiques clés (compteurs animés)

**Animation**:
- Stagger reveal sur les cards (delay 100ms entre chaque)
- Compteurs: `requestAnimationFrame` pour performance 60fps

### 3. Tech Stack Section
**ID**: `#technology`  
**Layout**: Tabs interactives horizontales  
**Contenu**:
- Architecture: Blockchain layer, Consensus mechanism, Cryptographic primitives
- Code snippets syntax-highlighted (prism.js-like custom lightweight)
- Diagramme architecture technique (SVG interactif)

**Composants JS**:
class TechTabs {
  constructor(container) {
    this.tabs = container.querySelectorAll('[data-tab]');
    this.panels = container.querySelectorAll('[data-panel]');
    this.init();
  }
  
  // Gestion aria-selected, transitions CSS
}

### 4. Team Section
**ID**: `#team`  
**Layout**: Grid responsive (1 col mobile → 4 col desktop)  
**Contenu**:
- Photos équipe (format carré, ratio 1:1)
- Nom, rôle, liens sociaux (GitHub, Twitter, LinkedIn)
- Bio courte (max 140 chars)

**Optimisation images**:
- Format WebP avec fallback JPEG
- Lazy loading natif (`loading="lazy"`)
- Placeholder blur-up technique (LQIP)

### 5. Roadmap Section
**ID**: `#roadmap`  
**Layout**: Timeline verticale centrée  
**Contenu**:
- Phases: Q1 2024 (Research) → Q2 2024 (Testnet) → Q3 2024 (