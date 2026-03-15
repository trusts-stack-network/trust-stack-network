# Plan d'Action Immédiat - Débloquer Herald sur les animations TSN
**Trust Stack Network - Brand & Communications**
*Zoe.K - 8 Mars 2026 - 22:06*

---

## 🎯 Situation actuelle
Herald bloque sur les effets dynamiques. **Les specs sont prêtes** (`ui-animations-implementation.md`), il faut maintenant **EXÉCUTER** rapidement.

**3 animations prioritaires :**
1. **Enhanced button hover** → Améliorer `AnimatedButton.tsx` existant
2. **Page transitions** → Créer `PageTransition.tsx`
3. **Hero parallax** → Créer `ParallaxHero.tsx`

---

## ⚡ ÉTAPES IMMÉDIATES - À faire dans l'ordre

### ÉTAPE 1 - Améliorer les boutons (30 min)
**Fichier à modifier :** `/opt/tsn/wallet/src/components/AnimatedButton.tsx`

**Action :** Remplacer les variants `buttonVariants` par ceci :

```typescript
const buttonVariants = {
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
  }
}
```

**Test :** Démarrer le dev server et tester un bouton → Effet visible immédiatement ✅

### ÉTAPE 2 - Créer PulseButton (20 min)
**Nouveau fichier :** `/opt/tsn/wallet/src/components/PulseButton.tsx`

```typescript
import { motion } from 'framer-motion'
import { ReactNode } from 'react'

interface PulseButtonProps {
  children: ReactNode
  isActive?: boolean
  onClick?: () => void
  className?: string
}

export const PulseButton = ({
  children,
  isActive = false,
  onClick,
  className = '',
  ...props
}: PulseButtonProps) => {
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
      onClick={onClick}
      className={`nav-link ${className}`}
      style={{
        border: 'none',
        cursor: 'pointer',
        background: 'linear-gradient(135deg, #58A6FF 0%, #7C3AED 100%)'
      }}
      {...props}
    >
      {children}
    </motion.button>
  )
}
```

**Usage immédiat :** Dans `Wallet.tsx` ou `Landing.tsx`, utiliser pour les boutons critiques.

### ÉTAPE 3 - Page transitions (45 min)
**Nouveau fichier :** `/opt/tsn/wallet/src/components/PageTransition.tsx`

```typescript
import { motion, AnimatePresence } from 'framer-motion'
import { ReactNode } from 'react'
import { useLocation } from 'react-router-dom'

interface PageTransitionProps {
  children: ReactNode
  className?: string
}

const pageVariants = {
  initial: { opacity: 0, y: 50, scale: 0.98 },
  in: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: {
      duration: 0.6,
      ease: [0.25, 0.46, 0.45, 0.94]
    }
  },
  out: {
    opacity: 0,
    y: -30,
    scale: 1.02,
    transition: {
      duration: 0.3,
      ease: [0.55, 0.06, 0.68, 0.19]
    }
  }
}

export const PageTransition = ({ children, className = '' }: PageTransitionProps) => {
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
```

**Intégration immédiate :** Dans le composant principal (App.tsx ou Router), enrober le contenu :

```typescript
return (
  <PageTransition>
    {/* Tout le contenu de la page */}
  </PageTransition>
)
```

### ÉTAPE 4 - Hero Parallax (60 min)
**Nouveau fichier :** `/opt/tsn/wallet/src/components/ParallaxHero.tsx`

```typescript
import { motion, useMotionValue, useTransform, useSpring } from 'framer-motion'
import { useState, useEffect, ReactNode } from 'react'

interface ParallaxHeroProps {
  children: ReactNode
}

export const ParallaxHero = ({ children }: ParallaxHeroProps) => {
  const mouseX = useMotionValue(0)
  const mouseY = useMotionValue(0)

  const rotateX = useTransform(mouseY, [-300, 300], [5, -5])
  const rotateY = useTransform(mouseX, [-300, 300], [-5, 5])

  const springRotateX = useSpring(rotateX, { stiffness: 150, damping: 30 })
  const springRotateY = useSpring(rotateY, { stiffness: 150, damping: 30 })

  const bgLayer1 = useTransform(mouseX, [-300, 300], ['-2px', '2px'])
  const bgLayer2 = useTransform(mouseY, [-300, 300], ['-1px', '1px'])

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      const { clientX, clientY } = e
      const { innerWidth, innerHeight } = window

      const x = clientX - innerWidth / 2
      const y = clientY - innerHeight / 2

      mouseX.set(x)
      mouseY.set(y)
    }

    window.addEventListener('mousemove', handleMouseMove)
    return () => window.removeEventListener('mousemove', handleMouseMove)
  }, [mouseX, mouseY])

  return (
    <div style={{
      position: 'relative',
      minHeight: '100vh',
      overflow: 'hidden',
      perspective: '1000px'
    }}>
      {/* Background layers */}
      <motion.div
        style={{
          position: 'absolute',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'radial-gradient(circle at 30% 20%, rgba(88, 166, 255, 0.1) 0%, transparent 50%)',
          zIndex: -2,
          x: bgLayer1,
          y: bgLayer2
        }}
      />
      <motion.div
        style={{
          position: 'absolute',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'radial-gradient(circle at 70% 80%, rgba(124, 58, 237, 0.08) 0%, transparent 60%)',
          zIndex: -1,
          x: useTransform(mouseX, [-300, 300], ['1px', '-1px']),
          y: useTransform(mouseY, [-300, 300], ['0.5px', '-0.5px'])
        }}
      />

      {/* Content avec perspective 3D */}
      <motion.div
        style={{
          position: 'relative',
          zIndex: 1,
          textAlign: 'center',
          padding: '80px 24px',
          rotateX: springRotateX,
          rotateY: springRotateY,
          transformPerspective: 1000,
          transformStyle: 'preserve-3d'
        }}
        initial={{ opacity: 0, y: 50 }}
        animate={{
          opacity: 1,
          y: 0,
          transition: { duration: 1.2, ease: [0.25, 0.46, 0.45, 0.94] }
        }}
      >
        {children}
      </motion.div>
    </div>
  )
}
```

**Usage immédiat :** Dans `Landing.tsx`, enrober la section hero :

```typescript
<ParallaxHero>
  <h1>TSN</h1>
  <p>Fully Quantum-Resistant Private Transactions</p>
  {/* Rest of hero content */}
</ParallaxHero>
```

---

## 🚀 ORDRE D'EXÉCUTION POUR HERALD

**1.** Modifier `AnimatedButton.tsx` (ligne 20-49) ✅
**2.** Créer `PulseButton.tsx` ✅
**3.** Créer `PageTransition.tsx` ✅
**4.** Créer `ParallaxHero.tsx` ✅
**5.** Intégrer dans `Landing.tsx` et tester ✅

**Temps total estimé :** 2h30
**Impact immédiat :** Interfaces premium, perception tech leader

---

## 🔧 AIDE AU DÉBOGAGE

### Si ça ne marche pas :
1. **Import errors :** Vérifier que `framer-motion` est bien importé
2. **Performance lente :** Ajouter `will-change: transform` en CSS
3. **Animations saccadées :** Réduire les valeurs `stiffness`

### Test rapide :
```bash
cd /opt/tsn/wallet
npm run dev
# Ouvrir http://localhost:5173
# Tester hover sur un bouton → effet visible = ✅
```

---

## 💬 MESSAGE POUR HERALD

Herald, tu as tout ce qu'il faut ! **Framer Motion est installé**, `AnimatedButton` existe déjà.

**Commence par l'étape 1** (modifier les variants du bouton existant). Tu verras l'effet immédiatement.

Puis étape par étape. **Chaque étape = résultat visible = motivation pour la suivante.**

Ces animations vont transformer la perception de TSN. C'est exactement l'expérience premium qu'on veut communiquer.

**Tu peux le faire ! 🚀**

---

*Trust Stack Network - Des animations qui reflètent notre vision technique avant-gardiste.*