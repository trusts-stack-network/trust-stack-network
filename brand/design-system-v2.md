# TSN Design System v2.0
**Post-Quantum Visual Identity**

## Palette de Couleurs Principale

### Backgrounds (Profondeur Quantique)
```css
--bg-primary: #0a0e14     /* Espace profond */
--bg-secondary: #161b22   /* Surface secondaire (rgba 0.8) */
--bg-tertiary: #0d1117    /* Accents tertiaires (rgba 0.6) */
```

### Accents (Signatures Post-Quantiques)
```css
--accent-blue: #58a6ff     /* ML-DSA Blue - signatures crypto */
--accent-purple: #a371f7   /* STARK Purple - zero-knowledge */
--accent-gradient: linear-gradient(135deg, #58a6ff 0%, #a371f7 100%)
```
**Symbolisme** : Le bleu représente les signatures ML-DSA (infrastructure sécurisée), le violet les preuves STARK (privacy avancée). Le gradient unit ces deux technologies.

### Textes (Lisibilité Optimisée)
```css
--text-primary: #e6edf3    /* Headers, contenus importants */
--text-secondary: #8b949e  /* Descriptions, métadonnées */
--border-color: #30363d    /* Séparations subtiles (rgba 0.6) */
```

### États Système
```css
--success: #3fb950   /* Transactions confirmées, validations */
--danger: #f85149    /* Erreurs, échecs de preuves */
--warning: #d29922   /* Synchronisation, attentes */
```

## Effets Dynamiques (Post-Quantum Motion)

### Radial Gradients d'Ambiance
```css
background-image:
  radial-gradient(ellipse at top, rgba(88, 166, 255, 0.08) 0%, transparent 50%),
  radial-gradient(ellipse at bottom right, rgba(163, 113, 247, 0.06) 0%, transparent 50%);
```

### Animations Crypto-Inspiration
- **Pulse** : Simulation du processus de preuve STARK (génération/vérification)
- **Spin** : États de chargement cryptographique
- **Transform** : Hover effects avec translate pour suggérer l'innovation

### Shadows & Depth
```css
/* Pour éléments importants (CTA, preuves) */
box-shadow: 0 4px 20px rgba(88, 166, 255, 0.4);

/* Pour cartes et surfaces */
box-shadow: 0 4px 24px rgba(0, 0, 0, 0.2);
```

## Philosophie Visuelle

**"Quantum-Native Design"**
- Les couleurs évoluent selon l'état cryptographique
- Les animations reflètent les processus de preuves
- L'UI communique la sécurité post-quantique visuellement

**Hiérarchie Technique**
1. **Gradient** = Actions principales (générer preuve, envoyer)
2. **Blue** = Éléments ML-DSA (signatures, comptes)
3. **Purple** = Éléments STARK/ZK (preuves, privacy)
4. **Success** = Confirmations blockchain
5. **Secondary** = Métadonnées et navigation

## Composants Signature

### Demo Cards
Structure qui met en avant la technologie :
- Header avec label technique + taille/métrique
- Content area avec monospace pour le code crypto
- Footer avec spécifications (field, hash, security level)

### Interactive Buttons
```css
.quantum-button {
  background: var(--accent-gradient);
  transform: translateY(-2px) on hover;
  box-shadow animate on interaction;
}
```

### Proof Displays
Code cryptographique affiché avec :
- Purple pour STARK proofs
- Blue pour ML-DSA signatures
- Monospace obligatoire
- Word-break pour responsive

Cette identité visuelle traduit TSN comme **LA** blockchain post-quantique — moderne, sécurisée, techniquement avancée mais accessible.