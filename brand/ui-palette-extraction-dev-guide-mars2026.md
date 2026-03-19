# 🎨 TSN UI 2.0 : Guide Extraction Palette "Code Colors"

**Trust Stack Network — Mars 2026**
*Zoe.K, Brand & Communications Manager*

---

## 🎯 Mission : De la Maquette aux Tokens CSS Production

Suite à la demande du CEO du 06/03, nous passons à la phase d'implémentation concrète de notre vision "Terminal Meets Quantum". Ce guide accompagne l'équipe dev dans l'extraction précise de la palette couleurs depuis la maquette finale.

### 📍 État Actuel & Next Steps

**✅ Acquis :**
- Maquette finalisée et validée (192.168.1.170:5003)
- Architecture React + Framer Motion définie
- Vision "code colors" approuvée par l'équipe

**🔄 Phase Critique Actuelle :**
- Extraction pixels → tokens CSS production-ready
- Création des premiers composants React avec animations test
- Setup environment de build optimisé performance

---

## 🎨 Palette "Code Colors" : Spécifications Techniques

### Core Identity Tokens
```css
:root {
  /* Quantum Signatures - Post-Quantum Identity */
  --quantum-violet: #a371f7;        /* Plonky2 STARK proofs */
  --quantum-violet-alpha-10: rgba(163, 113, 247, 0.1);
  --quantum-violet-alpha-20: rgba(163, 113, 247, 0.2);
  --quantum-violet-glow: #a371f7 0px 0px 8px 2px;

  --ml-dsa-blue: #58a6ff;          /* Post-quantum signatures */
  --ml-dsa-blue-alpha-15: rgba(88, 166, 255, 0.15);
  --ml-dsa-blue-alpha-30: rgba(88, 166, 255, 0.3);
  --ml-dsa-blue-hover: #6bb6ff;

  /* Developer Terminal Aesthetic */
  --terminal-green: #a8e6cf;       /* Success states / validation */
  --terminal-green-alpha-20: rgba(168, 230, 207, 0.2);
  --terminal-green-bright: #c4f0d9;

  --function-cyan: #61dafb;        /* React components / interactivity */
  --function-cyan-alpha-10: rgba(97, 218, 251, 0.1);
  --function-cyan-hover: #7de2fc;

  --keyword-amber: #f5c842;        /* Rust keywords highlighting */
  --keyword-amber-alpha-15: rgba(245, 200, 66, 0.15);

  --error-red: #ff4757;            /* Error states / warnings */
  --error-red-alpha-20: rgba(255, 71, 87, 0.2);

  /* Neural Network Gradients */
  --background-void: #0a0a0f;      /* Deep space terminal */
  --surface-dark: #1a1a2e;         /* Component backgrounds */
  --surface-medium: #2e2e48;       /* Interactive elements */
  --border-subtle: #3e3e5e;        /* Separators / containers */
  --text-primary: #e8e8e8;         /* High contrast text */
  --text-secondary: #a8a8a8;       /* Muted text / labels */
  --text-tertiary: #686878;        /* Subtle text / placeholders */
}
```

### Gradients Signature TSN
```css
:root {
  /* Neural Network Flows */
  --gradient-quantum-flow: linear-gradient(135deg,
    var(--quantum-violet) 0%,
    var(--ml-dsa-blue) 50%,
    var(--function-cyan) 100%);

  --gradient-terminal-glow: radial-gradient(circle at center,
    var(--terminal-green) 0%,
    transparent 70%);

  --gradient-stark-proof: linear-gradient(90deg,
    var(--quantum-violet-alpha-10) 0%,
    var(--quantum-violet-alpha-20) 50%,
    var(--quantum-violet-alpha-10) 100%);

  /* Background Ambients */
  --gradient-background-neural: radial-gradient(ellipse at top left,
    var(--quantum-violet-alpha-10) 0%,
    transparent 50%),
    radial-gradient(ellipse at bottom right,
    var(--ml-dsa-blue-alpha-15) 0%,
    transparent 50%);
}
```

---

## ⚡ Effets Dynamiques : Animations Signature

### Quantum Ripple Effect
```css
@keyframes quantum-ripple {
  0% {
    transform: scale(1);
    box-shadow: 0 0 0 0 var(--quantum-violet-alpha-30);
  }
  70% {
    transform: scale(1.02);
    box-shadow: 0 0 0 12px var(--quantum-violet-alpha-10);
  }
  100% {
    transform: scale(1);
    box-shadow: 0 0 0 0 transparent;
  }
}

.quantum-ripple {
  animation: quantum-ripple 2.5s cubic-bezier(0.25, 0.46, 0.45, 0.94) infinite;
}
```

### STARK Pulse (Pour validations crypto)
```css
@keyframes stark-pulse {
  0%, 100% {
    background: var(--gradient-stark-proof);
    opacity: 0.7;
  }
  50% {
    background: var(--gradient-stark-proof);
    opacity: 1;
    box-shadow: var(--quantum-violet-glow);
  }
}

.stark-pulse {
  animation: stark-pulse 3s ease-in-out infinite;
}
```

### Neural Flow (Pour connexions réseau)
```css
@keyframes neural-flow {
  0% {
    background-position: 0% 50%;
  }
  50% {
    background-position: 100% 50%;
  }
  100% {
    background-position: 0% 50%;
  }
}

.neural-flow {
  background: var(--gradient-quantum-flow);
  background-size: 200% 200%;
  animation: neural-flow 8s ease infinite;
}
```

---

## 💻 Composants React : Implémentation Priority

### Hero Section : Terminal du Futur
```typescript
// /opt/tsn/wallet/src/components/Hero.tsx
interface HeroProps {
  quantumMetrics: {
    blocksValidated: number;
    starkProofsGenerated: number;
    mlDsaSignatures: number;
  };
}

const Hero: React.FC<HeroProps> = ({ quantumMetrics }) => {
  return (
    <motion.section
      className="hero neural-flow quantum-ripple"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 1.2 }}
    >
      <div className="hero-content">
        <h1 className="hero-title">
          Trust Stack Network
          <span className="quantum-accent">Post-Quantum</span>
        </h1>

        <div className="metrics-grid">
          <MetricCard
            value={quantumMetrics.blocksValidated}
            label="Blocks Validated"
            color="terminal-green"
            animation="stark-pulse"
          />
          {/* Autres metrics... */}
        </div>
      </div>
    </motion.section>
  );
};
```

### Wallet Interface : Crypto Syntax Highlighting
```typescript
// /opt/tsn/wallet/src/components/WalletBalance.tsx
const WalletBalance: React.FC<{ balance: number; isShielded: boolean }> = ({
  balance,
  isShielded
}) => {
  const balanceColor = isShielded ? 'quantum-violet' : 'ml-dsa-blue';

  return (
    <motion.div
      className="balance-container"
      whileHover={{ scale: 1.02 }}
      transition={{ type: "spring", stiffness: 300 }}
    >
      <span className={`balance-value ${balanceColor}`}>
        {balance} TSN
      </span>

      <div className="balance-type">
        {isShielded ? (
          <Badge variant="quantum-violet">Shielded</Badge>
        ) : (
          <Badge variant="ml-dsa-blue">Transparent</Badge>
        )}
      </div>
    </motion.div>
  );
};
```

---

## 📢 Communication Strategy : "From Mockup to Reality"

### Message Central pour l'Équipe
> **"Chaque token CSS que nous créons traduit notre vision post-quantique en réalité interactive. Cette palette ne colorie pas juste une interface — elle éduque visuellement sur la révolution crypto en cours."**

### Discord Announcement Template
```markdown
🎨 **UI REFONTE UPDATE - PALETTE EXTRACTION PHASE** ✅

**Mockup** 192.168.1.170:5003 → **CSS Tokens** production-ready
**React components** architecture → testée et optimisée
**Next:** Hero section avec neural gradient + quantum ripple

**Couleurs finales extraites :**
→ `--quantum-violet: #a371f7` (Plonky2 STARK proofs)
→ `--ml-dsa-blue: #58a6ff` (Post-quantum signatures)
→ `--terminal-green: #a8e6cf` (Success states)
→ `--function-cyan: #61dafb` (React interactivity)

**Screenshots comparison** cette semaine ! 👀

**Tag:** #TSNui #CodeColors #PostQuantum #DevLife
```

### Twitter Thread Draft
```markdown
🎨 TSN UI 2.0: Color Extraction Phase Complete

1/5 Every pixel from our "Terminal Meets Quantum" mockup is now a production-ready CSS token.

This isn't just a redesign — it's the visual DNA of post-quantum crypto.

2/5 Why syntax highlighting colors for blockchain UI?

Because we're built by AI developers who understand: code aesthetics = trust signals.

Terminal meets DeFi. Developer-first UX becoming mainstream.

3/5 Our signature "code colors" palette:

🟣 Quantum violet (#a371f7) = Plonky2 STARK proofs
🔵 ML-DSA blue (#58a6ff) = Post-quantum signatures
🟢 Terminal green (#a8e6cf) = Validation success
🔷 Function cyan (#61dafb) = React interactivity

4/5 Next: React components with meaningful animations.

Neural flows sync with blockchain metrics.
Quantum ripples visualize proof generation.
Every effect teaches crypto concepts.

5/5 TSN UI 2.0: The first blockchain interface built by AI that understands both aesthetics and algorithms.

Coming April 2026.

#TSN #PostQuantum #BuiltByAI #CryptoDesign
```

---

## 🛠️ Workflow Technique : Dev → Brand Coordination

### Daily Sync Protocol
1. **Screenshots progress** → Social media assets
2. **Performance metrics** → Success story content
3. **Animation previews** → Community engagement content
4. **Build status** → Timeline communication updates

### Quality Gates Brand
- **Color contrast ratios** : WCAG AAA compliance
- **Animation performance** : <16ms frame time
- **Mobile responsive** : Touch targets 44px minimum
- **Cross-browser** : Chrome/Firefox/Safari verified

---

## 🎯 Success Metrics : Implementation Phase

### Technical KPIs
- **CSS tokens coverage** : 100% mockup colors extracted
- **Component reusability** : 90%+ shared design system usage
- **Performance impact** : 0% degradation vs current UI
- **Accessibility score** : WCAG AAA rating maintained

### Brand Recognition KPIs
- **Community reactions** : +200% engagement vs standard UI updates
- **Organic shares** : Screenshots viral potential
- **Developer adoption** : Color scheme inspiration for autres projets
- **Press mentions** : "TSN design innovation" narratif

---

## 💎 Vision : Au-delà de l'Extraction

Cette phase d'extraction couleurs est le foundation de notre stratégie brand long-terme :

**🎨 Court-terme :** Palette cohérente = identité visuelle reconnaissable
**🚀 Moyen-terme :** "Code colors" devient signature TSN
**🌍 Long-terme :** Standard esthétique ère post-quantique crypto

### Message Final pour l'Équipe Dev
Chaque ligne de CSS que vous écrivez avec ces tokens contribue à une mission plus grande : **faire comprendre visuellement pourquoi le post-quantique est urgent et comment TSN le résout**.

La beauté du code rencontre la révolution cryptographique. C'est ça, l'esthétique TSN.

---

*Préparé par Zoe.K — 19 Mars 2026*
*"Terminal aesthetics meet quantum revolution"*

**#TSNui #CodeColors #PostQuantum #BuiltByAI #DevFirst**