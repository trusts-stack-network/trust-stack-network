# Spécifications Techniques - TSN Landing Page

## Table des matières
1. [Vue d'ensemble](#vue-densemble)
2. [Stack Technique](#stack-technique)
3. [Architecture des Sections](#architecture-des-sections)
4. [Responsive Design](#responsive-design)
5. [Performance & SEO](#performance--seo)
6. [Intégrations](#intégrations)

## Vue d'ensemble

**Projet** : Trust Stack Network (TSN) Landing Page  
**Version** : 1.0.0  
**Objectif** : Présentation corporate et technique de l'écosystème TSN  
**Cible** : Investisseurs, développeurs, partenaires enterprise  

### User Flow

```mermaid
graph TD
    A[Arrivée] --> B[Hero Section]
    B --> C{Scroll}
    C --> D[Vision/Mission]
    C --> E[Stack Technique]
    C --> F[Équipe]
    C --> G[Roadmap]
    G --> H[CTA Contact/Newsletter]
    H --> I[Conversion]

## Stack Technique

### Core
- **HTML5** : Sémantique, accessibilité ARIA
- **CSS3** : Grid, Flexbox, Custom Properties, Container Queries
- **JavaScript** : Vanilla ES6+ (pas de framework pour la landing)

### Build & Optimisation
- **Bundler** : Vite 5.x
- **PostCSS** : Autoprefixer, CSSNano
- **Minification** : Terser, HTMLMinifier
- **Images** : WebP/AVIF avec fallbacks, lazy loading natif

### Outils
- **Linting** : ESLint, Stylelint
- **Versioning** : Git avec conventional commits
- **Déploiement** : CI/CD GitHub Actions → CDN/Netlify/Vercel

## Architecture des Sections

### 1. Hero Section (`#hero`)
**Objectif** : Accroche immédiate, value proposition

**Structure HTML** :
<section id="hero" aria-label="Introduction">
  <div class="hero__container">
    <h1 class="hero__title">Trust Stack Network</h1>
    <p class="hero__subtitle">Infrastructure décentralisée de confiance</p>
    <div class="hero__cta-group">
      <button class="btn btn--primary">Documentation</button>
      <button class="btn btn--secondary">Whitepaper</button>
    </div>
    <div class="hero__visualization">
      <!-- Canvas/WebGL pour animation réseau -->
      <canvas id="network-viz"></canvas>
    </div>
  </div>
</section>

**Spécifications CSS** :
- Hauteur : 100vh (min-height: 600px)
- Background : Gradient animé CSS + particules canvas
- Typographie : Inter (headings), Source Code Pro (tech elements)
- Animation : Fade-in cascade 0.8s ease-out

### 2. Vision Section (`#vision`)
**Objectif** : Expliquer la problématique et la solution TSN

**Composants** :
- Grid 2 colonnes (texte | illustration)
- Cards avec glassmorphism pour les piliers (Security, Decentralization, Interoperability)
- Counter animation pour les métriques (nodes, transactions)

**Données** :
const visionMetrics = [
  { label: 'Nodes actifs', value: 15000, suffix: '+' },
  { label: 'TPS', value: 50000, suffix: '' },
  { label: 'Latence', value: 0.4, suffix: 's', decimals: 1 }
];

### 3. Tech Stack Section (`#technology`)
**Objectif** : Présentation technique détaillée

**Architecture visuelle** :
graph LR
    A[Application Layer] --> B[Consensus Layer]
    B --> C[Network Layer]
    C --> D[Storage Layer]
    
    style A fill:#4f46e5,stroke:#3730a3
    style B fill:#7c3aed,stroke:#5b21b6
    style C fill:#db2777,stroke:#9d174d
    style D fill:#059669,stroke:#047857

**Implémentation** :
- Tabs interactives (Architecture, Consensus, Cryptographie)
- Code snippets avec syntax highlighting (Prism.js)
- Diagrammes interactifs SVG (hover states)

### 4. Team Section (`#team`)
**Objectif** : Crédibilité et transparence

**Structure** :
- Grid responsive (1 colonne mobile → 4 colonnes desktop)
- Cards profil avec :
  - Photo (lazy loaded)
  - Nom + Rôle
  - Bio courte (max 140 chars)
  - Liens sociaux (LinkedIn, GitHub, Twitter)
  - Badge "Core Contributor" si applicable

**Filtrage** :
- JavaScript filtre par département (Dev, Research, Ops)
- Transition CSS `opacity` + `transform`

### 5. Roadmap Section (`#roadmap`)
**Objectif** : Transparence sur les milestones

**Visualisation** :
- Timeline verticale avec alternance gauche/droite (desktop)
- Timeline single column (mobile)
- Status indicators :
  - ✅ Completed (green)
  - 🔄 In Progress (amber)
  - ⏳ Planned (slate)

**Données JSON** :
[
  {
    "phase": "Phase 1: Genesis",
    "date": "Q1 2024",
    "status": "completed",
    "items": ["Lancement testnet", "Audit sécurité", "SDK Alpha"]
  }
]

## Responsive Design

### Breakpoints
:root {
  --bp-mobile: 480px;
  --bp-tablet: 768px;
  --bp-desktop: 1024px;
  --bp-wide: 1440px;
}

### Stratégie Mobile-First
1. **Base** : Single column, padding 1rem, font-size 16px
2. **Tablet** (768px+) : 2 colonnes pour team/grid, navigation hamburger → horizontale
3. **Desktop** (1024px+) : Layout complet, animations activées
4. **Wide** (1440px+) : Max-width container 1280px, centré

### Optimisations Mobile
- Touch targets minimum 44x44px
- Réduction animations (prefers-reduced-motion)
- Images srcset avec résolutions adaptées
- Navigation sticky avec backdrop-filter blur

## Performance & SEO

### Web Vitals Targets
- **LCP** (Largest Contentful Paint) : < 2.5s
- **FID** (First Input Delay) : < 100ms
- **CLS** (Cumulative Layout Shift) : < 0.1

### SEO Technique
- Schema.org JSON-LD (Organization, WebSite)
- Meta tags Open Graph / Twitter Cards
- Sitemap.xml auto-généré
- robots.txt permissif

### Accessibilité
- Contraste minimum 4.5:1
- Navigation clavier complète (tabindex logique)
- Screen reader