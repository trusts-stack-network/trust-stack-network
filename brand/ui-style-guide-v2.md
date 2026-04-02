# TSN UI Style Guide v2.0 — Interface Moderne
*Trust Stack Network — Mars 2026*

## Vision UI

L'interface TSN reflète notre identité technologique : **moderne, sécurisée, accessible**. Nous construisons la première blockchain post-quantique — notre design doit montrer cette innovation tout en restant familier aux utilisateurs crypto.

## Palette Colorimétrique Post-Quantique

### Couleurs Principales
```css
--bg-primary: #0a0e14        /* Profondeur du vide quantique */
--bg-secondary: rgba(22, 27, 34, 0.8)  /* Glass morphism */
--accent-blue: #58a6ff       /* Quantum Computing Blue */
--accent-purple: #a371f7     /* Cryptographic Purple */
--accent-gradient: linear-gradient(135deg, #58a6ff 0%, #a371f7 100%)
```

### Psychologie Couleur
- **Bleu (#58a6ff)** : Confiance technologique, stabilité des protocoles
- **Violet (#a371f7)** : Innovation cryptographique, mystère quantique
- **Gradient Bleu→Violet** : Transition classique→post-quantique
- **Noir Profond (#0a0e14)** : Sécurité, protection, confidentialité

### Usage Stratégique
- **Logos/Headers** : Gradient pour impact visuel maximal
- **Buttons/CTA** : Gradient pour guider l'action utilisateur
- **States** : Bleu pour information, violet pour success crypto
- **Backgrounds** : Glass morphism pour modernité sans surcharge

## Typographie Technique

### Font Stack
```css
font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
```

### Hiérarchie
- **H1** : 2rem, gradient, pour impact (Balance, Titres majeurs)
- **H2** : 1rem, uppercase, espacement lettres (Sections)
- **Body** : 0.95rem, text-primary/secondary selon contexte
- **Code** : 'Monaco', 'Menlo', monospace (Addresses, Hashes, Keys)

### Règles Lisibilité
- Line-height minimum 1.6 pour textes longs
- Contraste AA minimum : text-primary (#e6edf3) sur bg-primary
- Code toujours en monospace pour éviter confusion crypto

## Effets Visuels Signature

### Glass Morphism
```css
background: var(--bg-secondary);
backdrop-filter: blur(12px);
border: 1px solid var(--border-color);
```
**Usage** : Cards, modals, overlays — effet moderne sans masquer contenu

### Gradients Animés
```css
background: var(--accent-gradient);
-webkit-background-clip: text;
-webkit-text-fill-color: transparent;
```
**Usage** : Logos, balances, éléments critiques — attire l'œil naturellement

### Micro-Interactions
```css
transition: all 0.2s ease;
transform: translateY(-1px);
box-shadow: 0 4px 16px rgba(88, 166, 255, 0.4);
```
**Usage** : Feedback utilisateur instantané, sensation de réactivité

### Sparkles & Glow
Animation sparkles pour états "ready" — gamification subtile
Glow effects pour highlight des éléments critiques (nouveau block, transaction confirmée)

## Principes d'Interface

### 1. Clarté Cognitive
- **Une action primaire par écran** — pas de compétition visuelle
- **States visuels explicites** : loading, success, error, disabled
- **Grouping logique** : carte par fonction, séparation claire

### 2. Affordance Crypto
- **Addresses toujours en monospace** — pattern recognition
- **Colors sémantiques** : rouge pour sent, vert pour received
- **Copy buttons** sur toutes les données exportables
- **Confirmation visuelle** pour actions irréversibles

### 3. Performance Perceptuelle
- **Skeleton loading** pour contenus dynamiques
- **Progressive disclosure** — détails sur demande
- **Chunked information** — pas de wall of text

## Composants Signature TSN

### Balance Display
```tsx
<div className="balance-display">
  <img className="balance-logo" src="/logo.png" alt="TSN"/>
  <div className="balance-info">
    <div className="balance">2,847.39 <span className="currency">TSN</span></div>
    <div className="balance-label">Available Balance</div>
  </div>
</div>
```
**Stratégie** : Logo visible renforce brand recall, gradient balance pour impact

### Card Hover States
```css
.card:hover {
  border-color: rgba(88, 166, 255, 0.3);
  transform: translateY(-1px);
}
```
**Stratégie** : Feedback subtil sans distraction, couleur brand cohérente

### Nav Pills avec Gradient
```css
.nav-toggle a.active {
  background: var(--accent-gradient);
  box-shadow: 0 2px 8px rgba(88, 166, 255, 0.3);
}
```
**Stratégie** : État actif immédiatement visible, profondeur via shadow

## Mobile-First Responsive

### Breakpoints
- **600px** : Mobile → Tablet (nav condensée, padding réduit)
- **900px** : Tablet → Desktop (container min-width)

### Touch Targets
- **Minimum 44px** pour boutons tactiles
- **Spacing 16px minimum** entre éléments cliquables
- **Swipe gestures** pour nav entre sections

## Accessibilité Crypto

### Contraste
- **AA compliance minimum** — texte lisible pour tous
- **Focus indicators** visibles pour navigation clavier
- **Color + shape** pour distinguer états (pas couleur seule)

### Crypto-Specific A11y
- **Screen reader labels** pour addresses/hashes
- **Phonetic spellings** pour seeds/keys critiques
- **Copy confirmation** audio/visuel

## Animation Guidelines

### Performance
- **GPU acceleration** : transform, opacity uniquement
- **60fps target** : animations sous 200ms
- **Respect prefers-reduced-motion**

### Timing Functions
```css
ease-in-out: smooth, natural
ease-out: user-initiated actions (clicks)
linear: infinite loops (loading spinners)
```

### Semantic Animation
- **Slide down** : content appears (accordion, dropdowns)
- **Fade in** : new content loads (balance updates)
- **Scale up** : success confirmations
- **Shake** : errors, invalid inputs

## États d'Interface

### Loading States
- **Skeleton screens** pour layout preservation
- **Progress indicators** pour opérations longues
- **Pulse animation** pour données qui se mettent à jour

### Empty States
- **Illustration + Message** — pas juste "Aucune donnée"
- **Action suggestion** — "Create your first transaction"
- **Brand colors** même dans l'état vide

### Error States
- **Rouge TSN** (#f85149) pour erreurs critiques
- **Orange** (#d29922) pour warnings
- **Message + Action** — toujours proposer next step

## Guidelines Dev

### CSS Architecture
- **Variables CSS custom properties** — pas de hardcoded colors
- **Component-scoped styles** — éviter global cascade
- **Mobile-first media queries** — progressive enhancement

### Implementation
- **Class naming BEM** pour composants complexes
- **Utility classes** pour spacings, colors courantes
- **CSS Grid/Flexbox** — pas de floats/tables pour layout

---

*Ce guide évolue avec la technologie TSN. Prochaine révision : Q2 2026 (mainnet launch).*