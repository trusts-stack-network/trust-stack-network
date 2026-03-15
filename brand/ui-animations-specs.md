# TSN UI Animations - Spécifications Techniques

## Vue d'ensemble
Amélioration de l'expérience utilisateur TSN avec des animations avancées Framer Motion. L'objectif est de créer des interactions fluides qui renforcent l'identité premium post-quantique sans nuire aux performances.

## Dépendance requise
```bash
npm install framer-motion
```

---

## 1. Hover Buttons - Micro-interactions Avancées

### 1.1 Navigation Buttons (`.nav-link`)
**Fichier:** `src/components/AnimatedNavLink.tsx`

```tsx
import { motion } from 'framer-motion';

const buttonVariants = {
  rest: {
    scale: 1,
    y: 0,
    boxShadow: "0 4px 16px rgba(88, 166, 255, 0.0)"
  },
  hover: {
    scale: 1.02,
    y: -2,
    boxShadow: "0 8px 32px rgba(88, 166, 255, 0.4)",
    transition: {
      type: "spring",
      stiffness: 400,
      damping: 10
    }
  },
  tap: {
    scale: 0.98,
    y: 0
  }
};

// Remplacer les liens de navigation par :
<motion.a
  className="nav-link"
  variants={buttonVariants}
  initial="rest"
  whileHover="hover"
  whileTap="tap"
>
```

### 1.2 Demo Button - Effet Quantum Pulse
**Fichier:** `src/components/QuantumButton.tsx`

```tsx
const quantumPulse = {
  rest: {
    boxShadow: [
      "0 0 20px rgba(88, 166, 255, 0.2)",
      "0 0 40px rgba(88, 166, 255, 0.1)",
      "0 0 20px rgba(88, 166, 255, 0.2)"
    ],
    transition: {
      duration: 2,
      repeat: Infinity,
      ease: "easeInOut"
    }
  },
  hover: {
    scale: 1.05,
    boxShadow: "0 0 60px rgba(88, 166, 255, 0.6)",
    transition: {
      type: "spring",
      stiffness: 300
    }
  }
};

// Appliquer au bouton "Generate Proof"
<motion.button
  className="demo-button"
  variants={quantumPulse}
  initial="rest"
  whileHover="hover"
  animate="rest"
>
```

---

## 2. Transitions Pages - Scroll progressif

### 2.1 Section Reveal Animations
**Fichier:** `src/components/RevealSection.tsx`

```tsx
const sectionVariants = {
  hidden: {
    opacity: 0,
    y: 50,
    scale: 0.95
  },
  visible: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: {
      duration: 0.6,
      ease: [0.25, 0.25, 0.25, 1], // Custom cubic-bezier
      staggerChildren: 0.1
    }
  }
};

// Wrapper pour chaque section
<motion.section
  className="section"
  variants={sectionVariants}
  initial="hidden"
  whileInView="visible"
  viewport={{ once: true, margin: "-100px" }}
>
```

### 2.2 Features Grid - Animation en cascade
**Fichier:** `src/components/AnimatedFeatures.tsx`

```tsx
const containerVariants = {
  visible: {
    transition: {
      staggerChildren: 0.2
    }
  }
};

const featureVariants = {
  hidden: {
    opacity: 0,
    y: 30,
    rotateX: -15
  },
  visible: {
    opacity: 1,
    y: 0,
    rotateX: 0,
    transition: {
      type: "spring",
      stiffness: 200,
      damping: 20
    }
  }
};

// Application :
<motion.div
  className="features"
  variants={containerVariants}
  initial="hidden"
  whileInView="visible"
  viewport={{ once: true }}
>
  {features.map((feature, index) => (
    <motion.div
      key={index}
      className="feature"
      variants={featureVariants}
      whileHover={{
        scale: 1.05,
        rotateY: 5,
        boxShadow: "0 10px 30px rgba(88, 166, 255, 0.2)"
      }}
    >
```

---

## 3. Effet Parallax Hero Section

### 3.1 Hero Parallax Container
**Fichier:** `src/components/ParallaxHero.tsx`

```tsx
import { useScroll, useTransform, motion } from 'framer-motion';

export function ParallaxHero() {
  const { scrollY } = useScroll();

  // Parallax values
  const logoY = useTransform(scrollY, [0, 500], [0, -150]);
  const titleY = useTransform(scrollY, [0, 500], [0, -100]);
  const taglineY = useTransform(scrollY, [0, 500], [0, -50]);
  const logoScale = useTransform(scrollY, [0, 300], [1, 0.8]);
  const logoOpacity = useTransform(scrollY, [0, 400], [1, 0.3]);

  return (
    <header className="hero">
      <motion.div
        style={{
          y: logoY,
          scale: logoScale,
          opacity: logoOpacity
        }}
        initial={{ opacity: 0, scale: 0.5, rotateY: -180 }}
        animate={{
          opacity: 1,
          scale: 1,
          rotateY: 0,
          transition: {
            duration: 1,
            type: "spring",
            stiffness: 200
          }
        }}
      >
        <img src="/logo.png" alt="TSN" className="logo" />
      </motion.div>

      <motion.h1
        className="title"
        style={{ y: titleY }}
        initial={{ opacity: 0, y: 50 }}
        animate={{
          opacity: 1,
          y: 0,
          transition: { delay: 0.2, duration: 0.8 }
        }}
      >
        TSN
      </motion.h1>

      <motion.p
        className="tagline"
        style={{ y: taglineY }}
        initial={{ opacity: 0, y: 30 }}
        animate={{
          opacity: 1,
          y: 0,
          transition: { delay: 0.4, duration: 0.6 }
        }}
      >
        Fully Quantum-Resistant Private Transactions
      </motion.p>
    </header>
  );
}
```

### 3.2 Floating Elements
**Ajout d'éléments décoratifs flottants**

```tsx
const FloatingOrb = ({ delay = 0, size = 40, color = "rgba(88, 166, 255, 0.1)" }) => (
  <motion.div
    style={{
      position: 'absolute',
      width: size,
      height: size,
      borderRadius: '50%',
      background: `radial-gradient(circle, ${color}, transparent)`,
      pointerEvents: 'none'
    }}
    animate={{
      y: [-20, 20, -20],
      x: [-10, 10, -10],
      rotate: [0, 360],
    }}
    transition={{
      duration: 6,
      delay,
      repeat: Infinity,
      ease: "easeInOut"
    }}
  />
);

// Placer 3-4 orbes autour du hero
```

---

## 4. Améliorations Spécifiques TSN

### 4.1 Quantum Signature Animation
**Pour la section ML-DSA demo**

```tsx
const signatureReveal = {
  hidden: {
    opacity: 0,
    scaleX: 0,
    originX: 0
  },
  visible: {
    opacity: 1,
    scaleX: 1,
    transition: {
      duration: 1.5,
      ease: "easeOut"
    }
  }
};

// Application sur .demo-content.signature
<motion.pre
  className="demo-content signature"
  variants={signatureReveal}
  initial="hidden"
  whileInView="visible"
  viewport={{ once: true }}
>
```

### 4.2 STARK Proof Generator - États animés

```tsx
const proofStates = {
  idle: {
    borderColor: "var(--border-color)",
    boxShadow: "none"
  },
  loading: {
    borderColor: "var(--accent-blue)",
    boxShadow: [
      "0 0 20px rgba(88, 166, 255, 0.3)",
      "0 0 40px rgba(88, 166, 255, 0.1)",
      "0 0 20px rgba(88, 166, 255, 0.3)"
    ],
    transition: {
      duration: 1.5,
      repeat: Infinity
    }
  },
  success: {
    borderColor: "#5cb85c",
    boxShadow: "0 0 30px rgba(92, 184, 92, 0.4)",
    scale: [1, 1.02, 1]
  }
};

// Application dynamique basée sur demoState.status
<motion.div
  className="demo-card interactive"
  variants={proofStates}
  animate={demoState.status}
>
```

---

## 5. Performance & Optimisation

### 5.1 Configuration Framer Motion
```tsx
// Dans main.tsx ou App.tsx
import { LazyMotion, domAnimation } from 'framer-motion';

// Wrapper pour lazy loading
<LazyMotion features={domAnimation}>
  <App />
</LazyMotion>
```

### 5.2 Reduced Motion Support
```tsx
// Hook pour respecter les préférences utilisateur
const prefersReducedMotion = useReducedMotion();

const animations = prefersReducedMotion ? {
  initial: { opacity: 0 },
  animate: { opacity: 1 }
} : fullAnimations;
```

---

## 6. Mise en œuvre prioritaire

### Phase 1 (High Impact)
1. ✅ **Hero Parallax** - Effet wow immédiat
2. ✅ **Hover Buttons** - Micro-interactions premium
3. ✅ **Section Reveals** - Scroll progressif engageant

### Phase 2 (Polish)
1. Features Grid cascade
2. Quantum signature typewriter
3. STARK proof états animés

### Phase 3 (Enhancement)
1. Floating orbs
2. Advanced parallax layers
3. Custom loading states

---

## Impact Brand
- **Professionnalisme** : Animations subtiles et performantes
- **Innovation** : Effets "quantum" uniques au secteur
- **Trust** : Transitions fluides = confiance technique
- **Différenciation** : Expérience premium vs. concurrents statiques

*Cette implémentation positionne TSN comme la blockchain post-quantique la plus avancée du marché, tant techniquement qu'esthétiquement.*