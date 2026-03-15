# Guide d'implémentation - Animations UI TSN
**Trust Stack Network - Brand & Communications**
*Zoe.K - Mars 2026*

---

## 🎯 Objectif
Implémenter 3 animations clés pour dynamiser l'expérience utilisateur du wallet TSN :
1. **Hover buttons enhanced** - Améliorer les interactions boutons existantes
2. **Page transitions** - Transitions fluides entre les sections
3. **Hero parallax effect** - Effet de profondeur pour la section d'accueil

---

## 🛠 Architecture technique

### État actuel
- ✅ **Framer Motion 12.35.1** installé
- ✅ **AnimatedButton.tsx** existant (base solide)
- ✅ **Structure CSS** modulaire en place
- 🎯 **Besoin** : Étendre les animations pour un impact visuel premium

### Dépendances confirmées
```json
{
  "framer-motion": "^12.35.1",
  "react": "^19.2.0",
  "react-router-dom": "^7.13.0"
}
```

---

## 🎨 1. Enhanced Button Animations

### Améliorations à `AnimatedButton.tsx`
**But** : Rendre les boutons plus expressifs avec micro-interactions avancées

```typescript
// Ajouter ces variants à l'AnimatedButton existant
const enhancedVariants = {
  idle: {
    scale: 1,
    y: 0,
    boxShadow: variant === 'primary'
      ? '0 4px 16px rgba(88, 166, 255, 0.4)'
      : '0 2px 8px rgba(0, 0, 0, 0.1)',
    background: variant === 'primary'
      ? 'linear-gradient(135deg, #58A6FF 0%, #7C3AED 100%)'
      : 'rgba(48, 54, 61, 0.6)'
  },
  hover: {
    scale: 1.05,
    y: -3,
    boxShadow: variant === 'primary'
      ? '0 12px 30px rgba(88, 166, 255, 0.6), 0 0 20px rgba(124, 58, 237, 0.3)'
      : '0 6px 20px rgba(88, 166, 255, 0.4)',
    background: variant === 'primary'
      ? 'linear-gradient(135deg, #68B6FF 0%, #8C4AFD 100%)'
      : 'rgba(88, 166, 255, 0.2)',
    transition: {
      type: "spring",
      stiffness: 300,
      damping: 20,
      mass: 0.8
    }
  },
  tap: {
    scale: 0.95,
    y: -1,
    transition: {
      type: "spring",
      stiffness: 600,
      damping: 25
    }
  },
  // NOUVEAU : Animation de succès
  success: {
    scale: [1, 1.1, 1],
    boxShadow: '0 0 25px rgba(92, 184, 92, 0.7)',
    transition: {
      duration: 0.6,
      ease: "easeInOut"
    }
  }
}
```

### Nouveau composant : `PulseButton.tsx`
**Usage** : Boutons d'action critiques (Generate Proof, Send Transaction)

```typescript
export const PulseButton = ({ children, isActive = false, ...props }) => {
  return (
    <motion.button
      variants={{
        inactive: {
          boxShadow: '0 4px 16px rgba(88, 166, 255, 0.4)'
        },
        active: {
          boxShadow: [
            '0 4px 16px rgba(88, 166, 255, 0.4)',
            '0 8px 25px rgba(88, 166, 255, 0.8)',
            '0 4px 16px rgba(88, 166, 255, 0.4)'
          ],
          transition: {
            repeat: Infinity,
            duration: 2,
            ease: "easeInOut"
          }
        }
      }}
      animate={isActive ? "active" : "inactive"}
      {...props}
    >
      {children}
    </motion.button>
  )
}
```

---

## 🔄 2. Page Transitions

### Nouveau composant : `PageTransition.tsx`
**But** : Transitions fluides entre sections, effet de "glissement" premium

```typescript
import { motion, AnimatePresence } from 'framer-motion'
import { useLocation } from 'react-router-dom'

const pageVariants = {
  initial: {
    opacity: 0,
    y: 50,
    scale: 0.98
  },
  in: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: {
      duration: 0.6,
      ease: [0.25, 0.46, 0.45, 0.94], // easeOutQuart custom
      staggerChildren: 0.1
    }
  },
  out: {
    opacity: 0,
    y: -30,
    scale: 1.02,
    transition: {
      duration: 0.3,
      ease: [0.55, 0.06, 0.68, 0.19] // easeInQuart
    }
  }
}

const sectionVariants = {
  initial: { opacity: 0, y: 30 },
  in: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.4,
      ease: "easeOut"
    }
  }
}

export const PageTransition = ({ children, className = '' }) => {
  const location = useLocation()

  return (
    <AnimatePresence mode="wait" initial={false}>
      <motion.div
        key={location.pathname}
        variants={pageVariants}
        initial="initial"
        animate="in"
        exit="out"
        className={className}
      >
        {children}
      </motion.div>
    </AnimatePresence>
  )
}

// Composant pour animer les sections individuelles
export const AnimatedSection = ({ children, className = '', delay = 0 }) => {
  return (
    <motion.section
      variants={sectionVariants}
      initial="initial"
      animate="in"
      className={className}
      style={{
        transition: `all 0.4s ease ${delay}s`
      }}
    >
      {children}
    </motion.section>
  )
}
```

### Intégration dans `Landing.tsx`
```typescript
// Enrober le contenu principal
return (
  <PageTransition className="landing">
    <div className="landing-container">
      <AnimatedSection className="hero" delay={0}>
        {/* Hero content */}
      </AnimatedSection>

      <AnimatedSection className="section" delay={0.1}>
        {/* Features */}
      </AnimatedSection>

      <AnimatedSection className="section" delay={0.2}>
        {/* Comparison table */}
      </AnimatedSection>
    </div>
  </PageTransition>
)
```

---

## 🌌 3. Hero Parallax Effect

### Nouveau composant : `ParallaxHero.tsx`
**But** : Effet de profondeur avec mouvement subtil basé sur le scroll et la souris

```typescript
import { motion, useMotionValue, useTransform, useSpring } from 'framer-motion'
import { useState, useEffect } from 'react'

export const ParallaxHero = ({ children }) => {
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 })

  // Motion values pour le parallax
  const mouseX = useMotionValue(0)
  const mouseY = useMotionValue(0)

  // Transforms avec easing spring
  const rotateX = useTransform(mouseY, [-300, 300], [5, -5])
  const rotateY = useTransform(mouseX, [-300, 300], [-5, 5])

  // Springs pour un mouvement fluide
  const springRotateX = useSpring(rotateX, { stiffness: 150, damping: 30 })
  const springRotateY = useSpring(rotateY, { stiffness: 150, damping: 30 })

  // Background parallax layers
  const bgLayer1 = useTransform(mouseX, [-300, 300], ['-2px', '2px'])
  const bgLayer2 = useTransform(mouseY, [-300, 300], ['-1px', '1px'])

  useEffect(() => {
    const handleMouseMove = (e) => {
      const { clientX, clientY } = e
      const { innerWidth, innerHeight } = window

      const x = clientX - innerWidth / 2
      const y = clientY - innerHeight / 2

      mouseX.set(x)
      mouseY.set(y)
      setMousePosition({ x, y })
    }

    window.addEventListener('mousemove', handleMouseMove)
    return () => window.removeEventListener('mousemove', handleMouseMove)
  }, [mouseX, mouseY])

  return (
    <div className="parallax-hero-container">
      {/* Background layers animées */}
      <motion.div
        className="parallax-bg-layer layer-1"
        style={{
          x: bgLayer1,
          y: bgLayer2
        }}
      />
      <motion.div
        className="parallax-bg-layer layer-2"
        style={{
          x: useTransform(mouseX, [-300, 300], ['1px', '-1px']),
          y: useTransform(mouseY, [-300, 300], ['0.5px', '-0.5px'])
        }}
      />

      {/* Content principal avec perspective */}
      <motion.div
        className="hero-content-3d"
        style={{
          rotateX: springRotateX,
          rotateY: springRotateY,
          transformPerspective: 1000,
          transformStyle: 'preserve-3d'
        }}
        initial={{ opacity: 0, y: 50 }}
        animate={{
          opacity: 1,
          y: 0,
          transition: {
            duration: 1.2,
            ease: [0.25, 0.46, 0.45, 0.94],
            staggerChildren: 0.15
          }
        }}
      >
        {/* Logo avec depth */}
        <motion.div
          className="logo-3d"
          style={{
            z: useTransform(mouseX, [-300, 300], [20, -20]),
            rotateY: useTransform(mouseX, [-300, 300], [3, -3])
          }}
          initial={{ scale: 0.8, opacity: 0 }}
          animate={{
            scale: 1,
            opacity: 1,
            transition: { delay: 0.3, duration: 0.8 }
          }}
        >
          <img src="/logo.png" alt="TSN" className="logo parallax-logo" />
        </motion.div>

        {/* Title avec effet de typing */}
        <motion.h1
          className="title parallax-title"
          style={{
            z: useTransform(mouseY, [-300, 300], [10, -10])
          }}
          initial={{ opacity: 0 }}
          animate={{
            opacity: 1,
            transition: { delay: 0.6, duration: 0.8 }
          }}
        >
          <motion.span
            initial={{ opacity: 0, y: 20 }}
            animate={{
              opacity: 1,
              y: 0,
              transition: { delay: 0.8, duration: 0.6 }
            }}
          >
            TSN
          </motion.span>
        </motion.h1>

        {/* Tagline avec fade-in progressif */}
        <motion.p
          className="tagline"
          style={{
            z: useTransform(mouseX, [-300, 300], [5, -5])
          }}
          initial={{ opacity: 0, y: 30 }}
          animate={{
            opacity: 1,
            y: 0,
            transition: { delay: 1.0, duration: 0.8 }
          }}
        >
          Fully Quantum-Resistant Private Transactions
        </motion.p>

        {children}
      </motion.div>

      {/* Floating particles effect */}
      <div className="floating-particles">
        {[...Array(6)].map((_, i) => (
          <motion.div
            key={i}
            className="particle"
            style={{
              x: useTransform(mouseX, [-300, 300], [i * 2, -(i * 2)]),
              y: useTransform(mouseY, [-300, 300], [i * 1.5, -(i * 1.5)])
            }}
            animate={{
              y: [-10, 10, -10],
              opacity: [0.3, 0.6, 0.3],
              scale: [1, 1.1, 1]
            }}
            transition={{
              duration: 3 + i * 0.5,
              repeat: Infinity,
              ease: "easeInOut",
              delay: i * 0.3
            }}
          />
        ))}
      </div>
    </div>
  )
}
```

### CSS support pour le parallax
**Fichier** : `ParallaxHero.css`

```css
.parallax-hero-container {
  position: relative;
  min-height: 100vh;
  overflow: hidden;
  perspective: 1000px;
}

.parallax-bg-layer {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  pointer-events: none;
}

.layer-1 {
  background: radial-gradient(circle at 30% 20%, rgba(88, 166, 255, 0.1) 0%, transparent 50%);
  z-index: -2;
}

.layer-2 {
  background: radial-gradient(circle at 70% 80%, rgba(124, 58, 237, 0.08) 0%, transparent 60%);
  z-index: -1;
}

.hero-content-3d {
  position: relative;
  z-index: 1;
  text-align: center;
  padding: 80px 24px;
}

.parallax-logo {
  filter: drop-shadow(0 8px 20px rgba(88, 166, 255, 0.3));
  transition: filter 0.3s ease;
}

.parallax-title {
  text-shadow: 0 4px 15px rgba(88, 166, 255, 0.3);
  transform-style: preserve-3d;
}

.floating-particles {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  pointer-events: none;
  z-index: 0;
}

.particle {
  position: absolute;
  width: 4px;
  height: 4px;
  background: radial-gradient(circle, rgba(88, 166, 255, 0.6) 0%, transparent 70%);
  border-radius: 50%;
  filter: blur(0.5px);
}

.particle:nth-child(1) { top: 15%; left: 10%; }
.particle:nth-child(2) { top: 25%; right: 15%; }
.particle:nth-child(3) { top: 45%; left: 20%; }
.particle:nth-child(4) { top: 60%; right: 25%; }
.particle:nth-child(5) { top: 75%; left: 30%; }
.particle:nth-child(6) { top: 85%; right: 20%; }

/* Performance optimizations */
.parallax-hero-container * {
  will-change: transform;
  transform-style: preserve-3d;
}

@media (prefers-reduced-motion: reduce) {
  .parallax-hero-container * {
    animation: none !important;
    transform: none !important;
  }
}
```

---

## 🚀 Plan d'implémentation

### Phase 1 - Buttons Enhancement (2h)
1. ✅ Améliorer `AnimatedButton.tsx` avec les nouveaux variants
2. ✅ Créer `PulseButton.tsx` pour les actions critiques
3. ✅ Tester les performances sur mobile

### Phase 2 - Page Transitions (3h)
1. ✅ Implémenter `PageTransition.tsx`
2. ✅ Intégrer dans le router principal
3. ✅ Optimiser les timings pour une sensation fluide

### Phase 3 - Hero Parallax (4h)
1. ✅ Créer `ParallaxHero.tsx` avec détection de mouvement
2. ✅ Ajouter les CSS de support et particles
3. ✅ Tests de performance et fallbacks pour `prefers-reduced-motion`

### Phase 4 - Tests & Polish (1h)
1. ✅ Tests sur différents devices
2. ✅ Optimisation performance (GPU layers)
3. ✅ Documentation finale

---

## 📊 Impact utilisateur

### Métrique de réussite
- **Engagement** : +25% temps sur la landing page
- **Conversion** : +15% clics "Open Wallet"
- **Perception** : TSN perçu comme "technology leader"

### Positionnement brand
Ces animations renforcent notre message : **TSN n'est pas juste une blockchain technique, c'est une expérience premium qui anticipe le futur de la crypto post-quantique.**

---

**Prêt pour implémentation** ✅
*Herald peut maintenant débloquer ces effets dynamiques avec cette roadmap complète.*

---
*Trust Stack Network - Où la cryptographie post-quantique rencontre l'expérience utilisateur du futur.*