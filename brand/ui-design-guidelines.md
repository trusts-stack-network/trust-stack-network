# TSN UI Design Guidelines — Vision & Cohérence

## Vision Créative : Interface Post-Quantique

### Philosophie Design

**"L'interface doit refléter la révolution qu'on porte"**

TSN n'est pas une blockchain comme les autres. Notre interface ne doit pas ressembler aux autres.

✨ **Moderne sans être flashy** — élégance technique
🔮 **Futuriste mais fonctionnel** — pas de gadgets, que de l'utile
🛡️ **Sécurité visible** — on sent la robustesse crypto sous-jacente

---

## Palette Couleurs & Identité

### Couleurs Primaires
```css
/* Post-Quantum Blue */
--tsn-primary: #1a237e;
--tsn-primary-light: #534bae;
--tsn-primary-dark: #000051;

/* Quantum Safe Green */
--tsn-accent: #00e676;
--tsn-accent-light: #66ffa6;
--tsn-accent-dark: #00b248;

/* Security Gray */
--tsn-neutral: #263238;
--tsn-neutral-light: #4f5b62;
--tsn-neutral-dark: #000a12;
```

### Signification des Couleurs
- **Bleu profond** → sécurité, stabilité, confiance technologique
- **Vert quantique** → innovation, énergie, résistance aux attaques
- **Gris sécurisé** → sobriété technique, professionnalisme

---

## Animations & Interactions

### Principes d'Animation
1. **Fluide mais discrète** — 60fps, transitions 300ms max
2. **Significative** — chaque animation raconte l'état du système
3. **Performante** — hardware acceleration, pas de lag

### Exemples d'Usage
```css
/* Transition blocks validation */
.block-validated {
  animation: quantum-seal 0.8s ease-out;
}

/* Hover states sécurisés */
.secure-button:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 20px rgba(26, 35, 126, 0.3);
}
```

---

## Typographie & Hiérarchie

### Stack Typographique
```css
/* Headers — technique mais accessible */
font-family: 'Inter', 'SF Pro Display', -apple-system, sans-serif;

/* Corps de texte — lisibilité maximale */
font-family: 'Inter', 'SF Pro Text', -apple-system, sans-serif;

/* Code/données — clarté technique */
font-family: 'JetBrains Mono', 'SF Mono', monospace;
```

### Tailles & Weights
- **H1** : 2.5rem / 600 weight → titres principales
- **H2** : 2rem / 500 weight → sections importantes
- **Body** : 1rem / 400 weight → texte standard
- **Caption** : 0.875rem / 400 weight → infos secondaires

---

## Composants Signature TSN

### Quantum Status Indicator
```html
<!-- Indicateur état post-quantique -->
<div class="quantum-status quantum-status--secure">
  <span class="status-dot"></span>
  Post-Quantum Secured
</div>
```

### Block Validation Animation
- Animation de "scellement" quantique lors de la validation
- Effet visuel qui montre la sécurité crypto en action

### Security Dashboard Cards
- Cards avec bordures dynamiques selon le niveau de sécurité
- Micro-interactions qui renforcent la confiance

---

## Ton & Voice UI

### Microcopy Guidelines

**❌ Éviter :**
- "Erreur système" → trop technique et effrayant
- "Loading..." → basique et impersonnel
- "Succès !" → trop générique

**✅ Utiliser :**
- "Sécurisation en cours..." → rassure sur la crypto
- "Validation post-quantique..." → éduque sur la techno
- "Transaction blindée ✓" → confirme la protection

### Messages d'Erreur
Toujours expliquer ET rassurer :
```
"Validation interrompue — votre transaction reste sécurisée.
Nouvelle tentative en cours..."
```

---

## Responsive & Performance

### Breakpoints
```css
/* Mobile-first approach */
@media (min-width: 768px) { /* Tablet */ }
@media (min-width: 1024px) { /* Desktop */ }
@media (min-width: 1440px) { /* Large */ }
```

### Performance Targets
- **First Paint** : <500ms
- **Interactive** : <1.5s
- **Animation FPS** : 60fps constant
- **Bundle Size** : <200KB (gzipped)

---

## Checklist Validation Design

Avant de shipper un composant :
- [ ] Cohérent avec la palette TSN ?
- [ ] Animation fluide 60fps ?
- [ ] Accessible (WCAG AA) ?
- [ ] Mobile-friendly ?
- [ ] Microcopy dans le ton TSN ?
- [ ] Reflète l'identité post-quantique ?

---

*Design System TSN — Préparé par Zoe.K*
*Brand & Communications Manager*
*Mars 2026*