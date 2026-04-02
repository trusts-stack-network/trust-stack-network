# TSN UI 2.0 — Palette & Principes Design Dynamique

## Palette Couleurs TSN (Extractée du Code)

### Couleurs Primaires
- **Noir Quantum** : `#0a0e14` — Arrière-plan principal, évoque la profondeur de l'espace cryptographique
- **Bleu Plonky** : `#58a6ff` — Couleur signature TSN, référence aux preuves STARK
- **Violet ML-DSA** : `#a371f7` — Couleur secondaire, évoque les signatures post-quantiques
- **Gradient Signature** : `linear-gradient(135deg, #58a6ff 0%, #a371f7 100%)` — L'ADN visuel TSN

### Couleurs Structurelles
- **Gris Translucides** : `rgba(22, 27, 34, 0.8)`, `rgba(13, 17, 23, 0.6)` — Cartes, overlays
- **Bordures Subtiles** : `rgba(48, 54, 61, 0.6)` — Séparation discrète
- **Texte Principal** : `#e6edf3` — Lisibilité maximale
- **Texte Secondaire** : `#8b949e` — Hiérarchie de l'information

## Principes Design TSN

### 1. **Transparence Technique**
L'UI reflète la philosophie du projet : aucun mystère, tout est visible.
- Les effets de blur (`backdrop-filter: blur(12px)`) simulent la complexité cryptographique rendue accessible
- Les gradients créent de la profondeur sans masquer l'information

### 2. **Quantum-Safe Aesthetic**
Chaque couleur a une signification cryptographique :
- **Bleu** → Plonky2 STARKs (preuves quantiques-résistantes)
- **Violet** → ML-DSA-65 (signatures post-quantiques)
- **Noir profond** → L'espace des possibles cryptographiques

### 3. **Fluidité 60fps**
- Transitions douces (`transition: all 0.2s ease`)
- Animations respectueuses (`prefers-reduced-motion`)
- Micro-interactions qui rassurent (hover, click feedback)

## Identité Visuelle Dynamique

### Logo & Typography
- **Logo** : Simple, géométrique, pas d'effets superflus
- **Police Principale** : Inter (clarté maximale)
- **Police Mono** : JetBrains Mono (pour le code/données cryptographiques)

### Effets Modernes Implémentés
- **Glassmorphism** : `backdrop-filter: blur(12px)` + transparence
- **Glow Effects** : `box-shadow: 0 4px 20px rgba(88, 166, 255, 0.4)`
- **Gradients Animés** : Transition fluide entre bleu et violet
- **Micro-animations** : `transform: translateY(-2px)` au hover

## Messages Brand pour UI 2.0

### Pour Discord FR (Communauté TSN)
```
🎨 **Interface TSN 2.0 déployée !**

Gradients fluides, animations 60fps, glassmorphism raffiné — notre wallet quantum-safe n'a jamais été aussi élégant.

La crypto post-quantique mérite une UX digne de 2026. Mission accomplie.

🔮 **Next** : Mobile app + démos interactives pour démocratiser le PQ.
```

### Pour Twitter/X EN (Audience Tech)
```
🧵 TSN just shipped the most elegant post-quantum wallet interface ever built.

Dark glassmorphism + ML-DSA signatures + 60fps animations = the future of quantum-safe UX.

When an AI team builds crypto interfaces from first principles, this is what happens.

Try it: wallet.tsn.network 🔗
```

### Pour LinkedIn FR (Professionnels)
```
💫 TSN vient de prouver qu'une blockchain post-quantique peut avoir l'élégance d'une fintech 2026.

Derrière chaque gradient, une signature ML-DSA-65. Derrière chaque animation, une preuve Plonky2 STARK.

L'innovation cryptographique + design thinking = adoption mainstream.

C'est notre vision de la crypto responsable.
```

## Guidelines d'Utilisation

### ✅ Faire
- Utiliser le gradient signature sur les CTA importants
- Maintenir les ratios de contraste (WCAG AA minimum)
- Préserver la fluidité 60fps sur tous les devices
- Garder la cohérence typographique (Inter + JetBrains Mono)

### ❌ Éviter
- Surcharger d'effets visuels (reste sobre et technique)
- Utiliser d'autres couleurs sans validation brand
- Casser la hiérarchie de l'information
- Négliger l'accessibilité (respect des préférences utilisateur)

---

**Signature TSN** : *Quantum-resistant by design, elegant by choice.*