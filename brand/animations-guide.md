# Guide d'Animations TSN - Framer Motion
> Guide technique pour Herald : 3 animations clés pour l'UI TSN

## 🎯 Animations Implémentées

### 1. **Hover Buttons** - Effets fluides sur les boutons
### 2. **Page Transitions** - Transitions entre pages
### 3. **Parallax Hero** - Effet parallax sur la hero section

---

## 1. 🎮 **HOVER BUTTONS** - Améliorer les interactions

### Implementation des boutons avec micro-interactions

```tsx
// /wallet/src/components/AnimatedButton.tsx
import { motion } from 'framer-motion'

export const AnimatedButton = ({
  children,
  variant = 'primary',
  onClick,
  ...props
}) => {
  const buttonVariants = {
    idle: {
      scale: 1,
      y: 0,
      boxShadow: variant === 'primary'
        ? '0 4px 12px rgba(88, 166, 255, 0.2)'
        : '0 2px 8px rgba(0, 0, 0, 0.1)'
    },
    hover: {
      scale: 1.02,
      y: -2,
      boxShadow: variant === 'primary'
        ? '0 8px 25px rgba(88, 166, 255, 0.4)'
        : '0 4px 16px rgba(0, 0, 0, 0.2)',
      transition: {
        type: "spring",
        stiffness: 400,
        damping: 10
      }
    },
    tap: {
      scale: 0.98,
      y: 0,
      transition: {
        type: "spring",
        stiffness: 500,
        damping: 15
      }
    }
  }

  return (
    <motion.button
      variants={buttonVariants}
      initial="idle"
      whileHover="hover"
      whileTap="tap"
      className={`nav-link ${variant === 'secondary' ? 'secondary' : ''}`}
      onClick={onClick}
      {...props}
    >
      {children}
    </motion.button>
  )
}
```

### Remplacement dans Landing.tsx

```tsx
// Remplacer dans /wallet/src/Landing.tsx (lignes 161-168)
import { AnimatedButton } from './components/AnimatedButton'

// Dans la hero section :
<nav className="nav-links hero-nav">
  <Link to="/wallet">
    <AnimatedButton variant="primary">
      Open Wallet
    </AnimatedButton>
  </Link>
  <Link to="/explorer">
    <AnimatedButton variant="secondary">
      Block Explorer
    </AnimatedButton>
  </Link>
</nav>
```

---

## 2. 🔄 **PAGE TRANSITIONS** - Navigation fluide

### Router avec transitions animées

```tsx
// /wallet/src/components/PageTransition.tsx
import { motion, AnimatePresence } from 'framer-motion'
import { useLocation } from 'react-router-dom'

const pageVariants = {
  initial: {
    opacity: 0,
    x: -20,
    filter: 'blur(4px)'
  },
  in: {
    opacity: 1,
    x: 0,
    filter: 'blur(0px)'
  },
  out: {
    opacity: 0,
    x: 20,
    filter: 'blur(4px)'
  }
}

const pageTransition = {
  type: 'tween',
  ease: 'anticipate',
  duration: 0.5
}

export const PageTransition = ({ children }) => {
  const location = useLocation()

  return (
    <AnimatePresence mode="wait" initial={false}>
      <motion.div
        key={location.pathname}
        initial="initial"
        animate="in"
        exit="out"
        variants={pageVariants}
        transition={pageTransition}
        style={{ height: '100%', width: '100%' }}
      >
        {children}
      </motion.div>
    </AnimatePresence>
  )
}
```

### Update du main.tsx

```tsx
// Mettre à jour /wallet/src/main.tsx
import { PageTransition } from './components/PageTransition'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter basename="/">
      <PageTransition>
        <Routes>
          <Route path="/wallet/*" element={<Wallet />} />
          <Route path="/explorer/*" element={<Explorer />} />
          <Route path="/plonky-test" element={<PlonkyTest />} />
          <Route path="/" element={<Landing />} />
        </Routes>
      </PageTransition>
    </BrowserRouter>
  </StrictMode>,
)
```

---

## 3. 🌌 **PARALLAX HERO** - Effet de profondeur

### Hero section avec parallax et animations échelonnées

```tsx
// Update de Landing.tsx - hero section (lignes 156-169)
import { motion, useScroll, useTransform } from 'framer-motion'

export default function Landing() {
  const { scrollY } = useScroll()
  const y1 = useTransform(scrollY, [0, 300], [0, -50])
  const y2 = useTransform(scrollY, [0, 300], [0, -100])
  const opacity = useTransform(scrollY, [0, 200], [1, 0])

  const heroVariants = {
    hidden: { opacity: 0, y: 30 },
    visible: {
      opacity: 1,
      y: 0,
      transition: {
        duration: 0.8,
        staggerChildren: 0.2
      }
    }
  }

  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: {
      opacity: 1,
      y: 0,
      transition: { duration: 0.6, ease: "easeOut" }
    }
  }

  return (
    <div className="landing">
      <div className="landing-container">
        {/* Hero Section avec Parallax */}
        <motion.header
          className="hero"
          variants={heroVariants}
          initial="hidden"
          animate="visible"
          style={{ opacity }}
        >
          <motion.div style={{ y: y1 }}>
            <motion.img
              src="/logo.png"
              alt="TSN"
              className="logo"
              variants={itemVariants}
              whileHover={{
                scale: 1.1,
                rotate: [0, -5, 5, 0],
                transition: { duration: 0.6 }
              }}
            />
            <motion.h1 className="title" variants={itemVariants}>
              TSN
            </motion.h1>
          </motion.div>

          <motion.div style={{ y: y2 }}>
            <motion.p className="tagline" variants={itemVariants}>
              Fully Quantum-Resistant Private Transactions
            </motion.p>

            <motion.nav
              className="nav-links hero-nav"
              variants={itemVariants}
            >
              {/* Boutons animés déjà implémentés ci-dessus */}
            </motion.nav>
          </motion.div>
        </motion.header>

        {/* Sections animées au scroll */}
        <AnimatedSection>
          <h2>What is TSN?</h2>
          {/* ... contenu existant */}
        </AnimatedSection>
      </div>
    </div>
  )
}
```

### Composant de section animée

```tsx
// /wallet/src/components/AnimatedSection.tsx
import { motion } from 'framer-motion'
import { useInView } from 'framer-motion'
import { useRef } from 'react'

export const AnimatedSection = ({ children, className = "section" }) => {
  const ref = useRef(null)
  const isInView = useInView(ref, {
    once: true,
    margin: "-100px"
  })

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
        ease: "easeOut",
        staggerChildren: 0.1
      }
    }
  }

  const itemVariants = {
    hidden: { opacity: 0, x: -20 },
    visible: {
      opacity: 1,
      x: 0,
      transition: { duration: 0.4 }
    }
  }

  return (
    <motion.section
      ref={ref}
      className={className}
      variants={sectionVariants}
      initial="hidden"
      animate={isInView ? "visible" : "hidden"}
    >
      <motion.div variants={itemVariants}>
        {children}
      </motion.div>
    </motion.section>
  )
}
```

---

## 4. 🎨 **CSS Améliorations** - Transitions fluides

### Mise à jour Landing.css

```css
/* Ajouts à /wallet/src/Landing.css */

/* Transitions fluides pour tous les éléments */
* {
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}

/* Hero amélioré */
.hero {
  position: relative;
  overflow: hidden;
}

.hero::before {
  content: '';
  position: absolute;
  top: -50%;
  left: -50%;
  width: 200%;
  height: 200%;
  background: radial-gradient(
    ellipse at center,
    rgba(88, 166, 255, 0.1) 0%,
    transparent 50%
  );
  animation: rotate 20s linear infinite;
  z-index: -1;
}

@keyframes rotate {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

/* Améliorations features */
.feature {
  transform-origin: center;
  will-change: transform;
}

/* Demo interactif amélioré */
.demo-card.interactive {
  background: linear-gradient(
    135deg,
    var(--bg-secondary) 0%,
    rgba(88, 166, 255, 0.05) 100%
  );
}

/* Effets sur les tableaux */
.comparison-table tbody tr {
  transition: background-color 0.2s ease, transform 0.2s ease;
}

.comparison-table tbody tr:hover {
  transform: translateY(-2px);
  background: rgba(88, 166, 255, 0.1);
}
```

---

## 5. 🛠️ **INSTALLATION** - Instructions pour Herald

### 1. Créer les composants
```bash
mkdir -p /opt/tsn/wallet/src/components
```

### 2. Créer les fichiers
- `AnimatedButton.tsx`
- `PageTransition.tsx`
- `AnimatedSection.tsx`

### 3. Mettre à jour les imports dans Landing.tsx
```tsx
import { motion, useScroll, useTransform } from 'framer-motion'
import { AnimatedButton } from './components/AnimatedButton'
import { AnimatedSection } from './components/AnimatedSection'
```

### 4. Tester les animations
```bash
cd /opt/tsn/wallet
npm run dev
```

---

## 6. 🎯 **PERFORMANCE** - Optimisations

### Configuration Framer Motion optimisée

```tsx
// /wallet/src/utils/animations.ts
import { MotionConfig } from 'framer-motion'

// Configuration globale pour de meilleures performances
export const motionConfig = {
  transition: { type: "tween", ease: "easeOut" },
  reducedMotion: "user" // Respecter les préférences utilisateur
}

// Wrap l'app dans main.tsx
<MotionConfig {...motionConfig}>
  {/* App content */}
</MotionConfig>
```

### Lazy loading des animations
```tsx
// Utiliser React.lazy pour les composants lourds
const HeavyAnimatedComponent = lazy(() =>
  import('./components/HeavyAnimatedComponent')
)
```

---

## 🚀 **RÉSULTAT ATTENDU**

✅ **Buttons hover** - Micro-interactions fluides sur tous les boutons
✅ **Page transitions** - Navigation avec fade + blur + slide
✅ **Parallax hero** - Effet de profondeur avec parallax et stagger
✅ **Sections animées** - Révélation au scroll avec intersection observer
✅ **Performance** - <60ms pour toutes les animations

**Temps d'implémentation estimé :** 2-3h

---

*Guide créé par Zoe.K - Brand & Communications Manager TSN*
*Pour questions techniques : ping @Herald sur Discord #dev*