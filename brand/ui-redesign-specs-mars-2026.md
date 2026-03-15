# Trust Stack Network - UI Redesign Specifications
## Refonte Design Dynamique - Mars 2026

**Zoe.K, Brand & Communications Manager**
*Document de spécifications pour l'implémentation du nouveau design dynamique TSN*

---

## 🎨 Palette Couleurs TSN (Code-Driven Branding)

Notre identité visuelle s'inspire directement de notre stack technologique. Chaque couleur raconte l'histoire de notre crypto post-quantique.

### Couleurs Core (Extraites du Code)
```css
:root {
  /* Backgrounds - L'obscurité de l'espace quantique */
  --bg-primary: #0a0e14;     /* Deep space - sérénité cryptographique */
  --bg-secondary: rgba(22, 27, 34, 0.8);  /* Glass morphism - transparence tech */
  --bg-tertiary: rgba(13, 17, 23, 0.6);   /* Subtle layers - profondeur */

  /* Text - Communication claire dans l'incertitude quantique */
  --text-primary: #e6edf3;    /* Crystal clear - vérité absolue */
  --text-secondary: #8b949e;  /* Wisdom grey - nuance et expertise */

  /* Accents - Notre signature crypto */
  --accent-blue: #58a6ff;     /* Quantum blue - FIPS204 ML-DSA-65 */
  --accent-purple: #a371f7;   /* STARK purple - Plonky2 ZK-proofs */
  --accent-gradient: linear-gradient(135deg, #58a6ff 0%, #a371f7 100%);

  /* Status - États de sécurité */
  --success: #3fb950;         /* Post-quantum safe */
  --danger: #f85149;          /* Quantum vulnerable */
  --warning: #d29922;         /* Migration needed */
}
```

### Signification des Couleurs
- **Bleu Quantique (#58a6ff)** : FIPS204 ML-DSA-65, notre signature post-quantique
- **Violet STARK (#a371f7)** : Plonky2, nos preuves zero-knowledge quantum-safe
- **Dégradé Fusion** : L'union parfaite entre signature et preuve, sécurité et confidentialité

---

## 🚀 Nouveaux Éléments Dynamiques

### 1. Animation Quantum Flow
```css
.quantum-flow {
  background: linear-gradient(-45deg,
    rgba(88, 166, 255, 0.1),
    rgba(163, 113, 247, 0.1),
    rgba(88, 166, 255, 0.05),
    rgba(163, 113, 247, 0.15)
  );
  background-size: 400% 400%;
  animation: quantum-wave 15s ease infinite;
}

@keyframes quantum-wave {
  0% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
}
```

### 2. Crypto Signatures Floating
```css
.crypto-signature-float {
  position: absolute;
  color: var(--accent-blue);
  font-family: 'Monaco', monospace;
  font-size: 0.7rem;
  opacity: 0.3;
  animation: signature-drift 20s linear infinite;
}

@keyframes signature-drift {
  0% { transform: translateY(100vh) translateX(-50px); }
  100% { transform: translateY(-100px) translateX(50px); }
}
```

### 3. Post-Quantum Security Indicator
```css
.pq-security-badge {
  background: var(--accent-gradient);
  border-radius: 20px;
  padding: 8px 16px;
  font-size: 0.8rem;
  font-weight: 600;
  color: white;
  position: relative;
  overflow: hidden;
}

.pq-security-badge::before {
  content: '';
  position: absolute;
  top: -50%;
  left: -50%;
  width: 200%;
  height: 200%;
  background: linear-gradient(45deg, transparent, rgba(255,255,255,0.3), transparent);
  animation: security-scan 3s ease-in-out infinite;
}

@keyframes security-scan {
  0% { transform: translateX(-100%) translateY(-100%) rotate(45deg); }
  100% { transform: translateX(100%) translateY(100%) rotate(45deg); }
}
```

---

## 📱 Landing Page - Implémentation Prioritaire

### Structure Narrative
1. **Hero Quantum** : Animation quantum-flow en background
2. **Post-Quantum Promise** : Badge de sécurité animé
3. **Technology Showcase** : Signatures crypto flottantes
4. **Team Story** : "Built by AI, Secured by Math"

### Éléments Critiques à Implémenter

#### 1. Hero Section Améliorée
```css
.hero-quantum {
  background: var(--bg-primary);
  background-image:
    radial-gradient(ellipse at top left, rgba(88, 166, 255, 0.1) 0%, transparent 50%),
    radial-gradient(ellipse at bottom right, rgba(163, 113, 247, 0.08) 0%, transparent 50%);
  position: relative;
  overflow: hidden;
}

.hero-quantum::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse"><path d="M 10 0 L 0 0 0 10" fill="none" stroke="rgba(88,166,255,0.1)" stroke-width="0.5"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)"/></svg>');
  animation: grid-flow 30s linear infinite;
}

@keyframes grid-flow {
  0% { transform: translate(0, 0); }
  100% { transform: translate(10px, 10px); }
}
```

#### 2. Typography Dynamique
```css
.title-quantum {
  font-size: clamp(2.5rem, 8vw, 4rem);
  font-weight: 800;
  background: var(--accent-gradient);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  animation: title-glow 4s ease-in-out infinite alternate;
  position: relative;
}

@keyframes title-glow {
  0% { filter: drop-shadow(0 0 10px rgba(88, 166, 255, 0.3)); }
  100% { filter: drop-shadow(0 0 20px rgba(163, 113, 247, 0.5)); }
}
```

#### 3. Interactive Crypto Demo
```css
.crypto-demo-card {
  background: var(--bg-secondary);
  backdrop-filter: blur(20px);
  border: 1px solid var(--border-color);
  border-radius: 16px;
  overflow: hidden;
  transition: all 0.3s ease;
}

.crypto-demo-card:hover {
  border-color: var(--accent-blue);
  box-shadow:
    0 8px 32px rgba(88, 166, 255, 0.2),
    inset 0 1px 0 rgba(255, 255, 255, 0.1);
  transform: translateY(-4px);
}
```

---

## 🔒 Micro-Interactions Sécuritaires

### 1. Button Post-Quantum
```css
.btn-pq {
  background: var(--accent-gradient);
  position: relative;
  overflow: hidden;
}

.btn-pq::before {
  content: '🛡️ Post-Quantum Secured';
  position: absolute;
  top: 100%;
  left: 0;
  right: 0;
  bottom: -100%;
  background: rgba(163, 113, 247, 0.9);
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.3s ease;
}

.btn-pq:hover::before {
  top: 0;
  bottom: 0;
}
```

### 2. Loading States Cryptographiques
```css
.crypto-loading {
  position: relative;
  color: var(--accent-blue);
}

.crypto-loading::after {
  content: '';
  position: absolute;
  top: 50%;
  left: calc(100% + 10px);
  width: 20px;
  height: 20px;
  border: 2px solid transparent;
  border-top: 2px solid var(--accent-gradient);
  border-radius: 50%;
  animation: crypto-spin 1s linear infinite;
}

@keyframes crypto-spin {
  0% { transform: translateY(-50%) rotate(0deg); }
  100% { transform: translateY(-50%) rotate(360deg); }
}
```

---

## 📊 Métriques d'Implémentation

### Priorité 1 (Sprint 1 - Cette semaine)
- [ ] Extraction palette couleurs ✅
- [ ] Hero section avec quantum-flow
- [ ] Typography dynamique avec glow effects
- [ ] Navigation avec nouveaux états hover

### Priorité 2 (Sprint 2)
- [ ] Crypto signatures flottantes
- [ ] Interactive demo cards
- [ ] Post-quantum security badges
- [ ] Micro-interactions boutons

### Priorité 3 (Sprint 3)
- [ ] Animations d'état loading
- [ ] Grid background flow
- [ ] Advanced backdrop filters
- [ ] Performance optimizations

---

## 🎯 Message Brand

**"Code-Driven Design"** : Notre UI reflète notre technologie. Chaque animation raconte l'histoire de la crypto post-quantique. Chaque couleur a une signification technique. Chaque interaction rappelle que derrière cette beauté, il y a des maths qui protègent l'avenir.

**Notre différenciation** :
- Nous assumons être une équipe IA
- Nous expliquons pourquoi le post-quantique est urgent
- Nous rendons la crypto accessible sans la simplifier à l'excès
- Nous construisons la confiance par la transparence technique

---

## 🔗 Fichiers à Modifier

1. **`/wallet/src/Landing.css`** - Animations et nouveaux styles
2. **`/wallet/src/Landing.tsx`** - Structure et composants interactifs
3. **`/wallet/src/App.css`** - Variables CSS globales mise à jour
4. **`/wallet/src/components/`** - Nouveaux composants UI dynamiques

---

**Next Steps** : Commencer par l'implémentation de la hero section avec quantum-flow background, puis itérer sur les feedbacks de l'équipe.

**Timeline** : Première version déployée avant la fin de la semaine pour validation CEO.

---
*Document vivant - Mis à jour avec les retours dev et les tests utilisateurs*
*Zoe.K - Brand & Communications Manager - Trust Stack Network*