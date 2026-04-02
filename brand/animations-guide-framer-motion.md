# Guide Animations TSN - Framer Motion

## Contexte : Débloquer Herald sur les Effets Dynamiques

L'UI TSN actuelle a des hovers CSS statiques mais manque de fluidité moderne. Cette spec implémente **3 animations clés** avec Framer Motion (déjà installé v12.35.1) :

1. **Hover Buttons** - Animations fluides micro-interactions
2. **Transitions Pages** - Smooth routing entre Landing/Wallet/Explorer
3. **Parallax Hero** - Effet depth scrolling section hero

---

## 🎯 Animation 1 : Hover Buttons Enhanced

**Objectif :** Remplacer les CSS :hover basiques par des animations Framer sophistiquées.

### Composants à migrer :
- `.nav-link` (Open Wallet, Block Explorer)
- `.demo-button` (Generate Proof)
- `.whitepaper-link`
- `.feature` cards

### Code : Hook Custom useButtonHover

```tsx
// src/hooks/useButtonHover.ts
import { useAnimation } from 'framer-motion'
import { useState } from 'react'

export function useButtonHover() {
  const controls = useAnimation()
  const [isHovered, setIsHovered] = useState(false)

  const handleHoverStart = () => {
    setIsHovered(true)
    controls.start({
      scale: 1.02,
      y: -3,
      transition: { duration: 0.2, ease: "easeOut" }
    })
  }

  const handleHoverEnd = () => {
    setIsHovered(false)
    controls.start({
      scale: 1,
      y: 0,
      transition: { duration: 0.2, ease: "easeOut" }
    })
  }

  return {
    controls,
    isHovered,
    handleHoverStart,
    handleHoverEnd
  }
}
```

### Implémentation Landing.tsx

```tsx
import { motion } from 'framer-motion'
import { useButtonHover } from './hooks/useButtonHover'

// Dans le composant Landing
const primaryButton = useButtonHover()
const secondaryButton = useButtonHover()
const demoButton = useButtonHover()

// Remplacer les <Link> par des motion.div
<motion.div
  animate={primaryButton.controls}
  onHoverStart={primaryButton.handleHoverStart}
  onHoverEnd={primaryButton.handleHoverEnd}
  whileTap={{ scale: 0.98 }}
  style={{
    filter: primaryButton.isHovered
      ? 'drop-shadow(0 8px 32px rgba(88, 166, 255, 0.4))'
      : 'drop-shadow(0 2px 8px rgba(88, 166, 255, 0.2))'
  }}
>
  <Link to="/wallet" className="nav-link">
    Open Wallet
  </Link>
</motion.div>
```

---

## 🎯 Animation 2 : Page Transitions

**Objectif :** Smooth transitions entre routes avec AnimatePresence.

### Architecture : Router Wrapper

```tsx
// src/components/PageTransition.tsx
import { motion, AnimatePresence } from 'framer-motion'
import { useLocation } from 'react-router-dom'

interface PageTransitionProps {
  children: React.ReactNode
}

export function PageTransition({ children }: PageTransitionProps) {
  const location = useLocation()

  return (
    <AnimatePresence mode="wait">
      <motion.div
        key={location.pathname}
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -20 }}
        transition={{
          duration: 0.3,
          ease: "easeInOut"
        }}
      >
        {children}
      </motion.div>
    </AnimatePresence>
  )
}
```

### Modification main.tsx

```tsx
// Wraper chaque route avec PageTransition
<Routes>
  <Route path="/wallet/*" element={
    <PageTransition>
      <Wallet />
    </PageTransition>
  } />
  <Route path="/explorer/*" element={
    <PageTransition>
      <Explorer />
    </PageTransition>
  } />
  <Route path="/" element={
    <PageTransition>
      <Landing />
    </PageTransition>
  } />
</Routes>
```

### Transition Spécialisées par Route

```tsx
// Variants pour différents types de pages
export const pageVariants = {
  landing: {
    initial: { opacity: 0, scale: 0.95 },
    animate: { opacity: 1, scale: 1 },
    exit: { opacity: 0, scale: 1.05 }
  },
  wallet: {
    initial: { opacity: 0, x: -30 },
    animate: { opacity: 1, x: 0 },
    exit: { opacity: 0, x: 30 }
  },
  explorer: {
    initial: { opacity: 0, y: 30 },
    animate: { opacity: 1, y: 0 },
    exit: { opacity: 0, y: -30 }
  }
}
```

---

## 🎯 Animation 3 : Parallax Hero Section

**Objectif :** Effet depth sur la hero section avec scroll-driven animation.

### Hook useParallax

```tsx
// src/hooks/useParallax.ts
import { useScroll, useTransform } from 'framer-motion'
import { useRef } from 'react'

export function useParallax(speed = 0.5) {
  const ref = useRef<HTMLDivElement>(null)
  const { scrollY } = useScroll()

  const y = useTransform(scrollY, [0, 1000], [0, -speed * 1000])
  const opacity = useTransform(scrollY, [0, 400], [1, 0.3])
  const scale = useTransform(scrollY, [0, 400], [1, 0.95])

  return { ref, y, opacity, scale }
}
```

### Implémentation Hero Parallax

```tsx
// Dans Landing.tsx - section hero
const heroParallax = useParallax(0.3)
const logoParallax = useParallax(0.5)
const textParallax = useParallax(0.2)

<motion.header
  ref={heroParallax.ref}
  className="hero"
  style={{
    y: heroParallax.y,
    opacity: heroParallax.opacity,
    scale: heroParallax.scale
  }}
>
  <motion.img
    src="/logo.png"
    alt="TSN"
    className="logo"
    style={{ y: logoParallax.y }}
    initial={{ scale: 0, rotate: -180 }}
    animate={{ scale: 1, rotate: 0 }}
    transition={{ duration: 0.8, delay: 0.2 }}
  />

  <motion.h1
    className="title"
    style={{ y: textParallax.y }}
    initial={{ opacity: 0, y: 30 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ duration: 0.6, delay: 0.4 }}
  >
    TSN
  </motion.h1>

  <motion.p
    className="tagline"
    initial={{ opacity: 0 }}
    animate={{ opacity: 1 }}
    transition={{ duration: 0.6, delay: 0.8 }}
  >
    Fully Quantum-Resistant Private Transactions
  </motion.p>
</motion.header>
```

---

## 🔧 Animations Bonus : Staggered Reveals

### Features Grid Animation

```tsx
// Animation en cascade pour les feature cards
const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.15
    }
  }
}

const itemVariants = {
  hidden: { opacity: 0, y: 20, scale: 0.95 },
  visible: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: { duration: 0.4 }
  }
}

<motion.div
  className="features"
  variants={containerVariants}
  initial="hidden"
  whileInView="visible"
  viewport={{ once: true, margin: "-100px" }}
>
  {features.map((feature, index) => (
    <motion.div
      key={index}
      className="feature"
      variants={itemVariants}
      whileHover={{
        scale: 1.03,
        borderColor: "rgba(88, 166, 255, 0.5)",
        transition: { duration: 0.2 }
      }}
    >
      {/* contenu feature */}
    </motion.div>
  ))}
</motion.div>
```

---

## 📱 Responsive & Performance

### Reduce Motion Support

```tsx
// src/hooks/useReducedMotion.ts
import { useEffect, useState } from 'react'

export function useReducedMotion() {
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false)

  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)')
    setPrefersReducedMotion(mediaQuery.matches)

    const handler = () => setPrefersReducedMotion(mediaQuery.matches)
    mediaQuery.addEventListener('change', handler)

    return () => mediaQuery.removeEventListener('change', handler)
  }, [])

  return prefersReducedMotion
}
```

### Configuration Global Motion

```tsx
// src/components/MotionConfig.tsx
import { LazyMotion, domAnimation, MotionConfig } from 'framer-motion'
import { useReducedMotion } from '../hooks/useReducedMotion'

export function AppMotionConfig({ children }: { children: React.ReactNode }) {
  const shouldReduceMotion = useReducedMotion()

  return (
    <LazyMotion features={domAnimation}>
      <MotionConfig reducedMotion={shouldReduceMotion ? "always" : "never"}>
        {children}
      </MotionConfig>
    </LazyMotion>
  )
}
```

---

## 🎬 Mise en Œuvre : Étapes

### Phase 1 : Setup (30min)
1. Créer `src/hooks/useButtonHover.ts`
2. Créer `src/hooks/useParallax.ts`
3. Créer `src/components/PageTransition.tsx`
4. Wrapper `main.tsx` avec MotionConfig

### Phase 2 : Buttons (45min)
1. Migrer tous les buttons vers motion.div + useButtonHover
2. Tester interactions mobile touch
3. Ajuster timing & easing

### Phase 3 : Page Transitions (30min)
1. Wrapper routes avec PageTransition
2. Test navigation fluide
3. Fix any layout shift

### Phase 4 : Parallax Hero (45min)
1. Implement useParallax sur hero section
2. Stagger animations logo/title/tagline
3. Test performance scroll

### Phase 5 : Polish (30min)
1. Features grid staggered reveals
2. Reduced motion support
3. Cross-browser testing

---

## 🎯 Résultat Attendu

**Avant :** CSS hovers statiques, transitions abruptes
**Après :** Interface fluide post-quantique digne d'une tech révolutionnaire

- **Micro-interactions** engageantes sur tous les CTAs
- **Navigation** fluide qui guide l'attention
- **Hero parallax** qui donne depth et modernité
- **Performance** optimisée (LazyMotion + reduced motion)
- **Cohérence** avec l'identité tech premium TSN

La combinaison parallax + staggered reveals + smooth transitions positionne TSN comme innovation UI autant que crypto innovation.

**Next :** Une fois implémenté, documenter les patterns pour Wallet et Explorer components.