# Guide d'Implémentation des Animations TSN
*Interface utilisateur et expérience de marque*

## Vision des animations TSN

Les animations TSN doivent refléter notre identité : **technologie de pointe, sécurité quantique, confiance et innovation**. Chaque animation renforce le message que TSN est la blockchain la plus avancée cryptographiquement.

### Principes directeurs
- **Précision technique** : Mouvements nets, timing précis (comme la cryptographie)
- **Fluidité quantique** : Transitions douces qui évoquent les superpositions quantiques
- **Performance native** : Optimisées pour ne jamais ralentir l'expérience
- **Sobriété professionnelle** : Impressive mais jamais flashy

---

## 1. Animations Hover des Boutons

### Code d'implémentation

```tsx
// components/AnimatedButton.tsx
import { motion } from 'framer-motion';

interface AnimatedButtonProps {
  children: React.ReactNode;
  variant?: 'primary' | 'secondary' | 'demo';
  onClick?: () => void;
  disabled?: boolean;
}

const buttonVariants = {
  primary: {
    initial: {
      scale: 1,
      boxShadow: "0 0 0 rgba(45, 212, 191, 0)"
    },
    hover: {
      scale: 1.02,
      boxShadow: "0 0 20px rgba(45, 212, 191, 0.3)",
      transition: { duration: 0.2, ease: "easeOut" }
    },
    tap: {
      scale: 0.98,
      transition: { duration: 0.1 }
    }
  },
  secondary: {
    initial: {
      scale: 1,
      borderColor: "rgba(255, 255, 255, 0.2)"
    },
    hover: {
      scale: 1.02,
      borderColor: "rgba(255, 255, 255, 0.4)",
      backgroundColor: "rgba(255, 255, 255, 0.05)",
      transition: { duration: 0.2 }
    },
    tap: {
      scale: 0.98
    }
  },
  demo: {
    initial: {
      scale: 1,
      backgroundImage: "linear-gradient(135deg, #0ea5e9, #06b6d4)"
    },
    hover: {
      scale: 1.03,
      backgroundImage: "linear-gradient(135deg, #0284c7, #0891b2)",
      boxShadow: "0 10px 30px rgba(6, 182, 212, 0.3)",
      transition: { duration: 0.3, ease: "easeOut" }
    },
    tap: {
      scale: 0.97
    }
  }
};

export default function AnimatedButton({
  children,
  variant = 'primary',
  onClick,
  disabled
}: AnimatedButtonProps) {
  return (
    <motion.button
      className={`animated-button animated-button--${variant}`}
      variants={buttonVariants[variant]}
      initial="initial"
      whileHover={disabled ? "initial" : "hover"}
      whileTap={disabled ? "initial" : "tap"}
      onClick={onClick}
      disabled={disabled}
    >
      {children}
    </motion.button>
  );
}
```

### CSS complémentaire

```css
/* Landing.css - Ajouts pour les boutons animés */
.animated-button {
  position: relative;
  overflow: hidden;
  border: none;
  cursor: pointer;
  font-weight: 600;
  transition: all 0.2s ease;
}

.animated-button--primary {
  background: linear-gradient(135deg, #2dd4bf, #06b6d4);
  color: white;
  padding: 12px 24px;
  border-radius: 8px;
}

.animated-button--secondary {
  background: transparent;
  color: rgba(255, 255, 255, 0.9);
  padding: 12px 24px;
  border: 2px solid rgba(255, 255, 255, 0.2);
  border-radius: 8px;
}

.animated-button--demo {
  background: linear-gradient(135deg, #0ea5e9, #06b6d4);
  color: white;
  padding: 16px 32px;
  border-radius: 12px;
  font-size: 18px;
  font-weight: 700;
}

.animated-button:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
```

---

## 2. Transitions de Pages

### Layout avec animations de page

```tsx
// components/PageTransition.tsx
import { motion, AnimatePresence } from 'framer-motion';
import { useLocation } from 'react-router-dom';

const pageVariants = {
  initial: {
    opacity: 0,
    y: 20,
    scale: 0.98
  },
  enter: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: {
      duration: 0.4,
      ease: [0.25, 0.46, 0.45, 0.94] // easeOutQuart
    }
  },
  exit: {
    opacity: 0,
    y: -20,
    scale: 1.02,
    transition: {
      duration: 0.3,
      ease: [0.55, 0.06, 0.68, 0.19] // easeInQuart
    }
  }
};

interface PageTransitionProps {
  children: React.ReactNode;
}

export default function PageTransition({ children }: PageTransitionProps) {
  const location = useLocation();

  return (
    <AnimatePresence mode="wait">
      <motion.div
        key={location.pathname}
        variants={pageVariants}
        initial="initial"
        animate="enter"
        exit="exit"
        style={{ width: '100%' }}
      >
        {children}
      </motion.div>
    </AnimatePresence>
  );
}
```

### Mise à jour du main.tsx

```tsx
// main.tsx - Intégration des transitions
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import './index.css'
import Wallet from './Wallet.tsx'
import Explorer from './Explorer.tsx'
import Landing from './Landing.tsx'
import PlonkyTest from './PlonkyTest.tsx'
import PageTransition from './components/PageTransition.tsx'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter basename="/">
      <Routes>
        <Route path="/wallet/*" element={<PageTransition><Wallet /></PageTransition>} />
        <Route path="/explorer/*" element={<PageTransition><Explorer /></PageTransition>} />
        <Route path="/plonky-test" element={<PageTransition><PlonkyTest /></PageTransition>} />
        <Route path="/" element={<PageTransition><Landing /></PageTransition>} />
      </Routes>
    </BrowserRouter>
  </StrictMode>,
)
```

---

## 3. Effet Parallax Hero Section

### Composant Hero avec parallax

```tsx
// components/ParallaxHero.tsx
import { motion, useScroll, useTransform } from 'framer-motion';
import { useRef } from 'react';

export default function ParallaxHero() {
  const containerRef = useRef<HTMLElement>(null);
  const { scrollYProgress } = useScroll({
    target: containerRef,
    offset: ["start start", "end start"]
  });

  // Transformations parallax
  const logoY = useTransform(scrollYProgress, [0, 1], [0, -100]);
  const titleY = useTransform(scrollYProgress, [0, 1], [0, -80]);
  const taglineY = useTransform(scrollYProgress, [0, 1], [0, -60]);
  const navY = useTransform(scrollYProgress, [0, 1], [0, -40]);

  // Opacity qui diminue avec le scroll
  const opacity = useTransform(scrollYProgress, [0, 0.8], [1, 0]);

  // Effet de blur subtil
  const blur = useTransform(scrollYProgress, [0, 1], [0, 3]);

  return (
    <motion.header
      ref={containerRef}
      className="hero parallax-hero"
      style={{ opacity }}
    >
      <motion.div
        style={{
          y: logoY,
          filter: useTransform(blur, (value) => `blur(${value}px)`)
        }}
      >
        <img src="/logo.png" alt="TSN" className="logo" />
      </motion.div>

      <motion.h1
        className="title"
        style={{ y: titleY }}
        initial={{ opacity: 0, scale: 0.8 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.8, delay: 0.2 }}
      >
        TSN
      </motion.h1>

      <motion.p
        className="tagline"
        style={{ y: taglineY }}
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8, delay: 0.4 }}
      >
        Fully Quantum-Resistant Private Transactions
      </motion.p>

      <motion.nav
        className="nav-links hero-nav"
        style={{ y: navY }}
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8, delay: 0.6 }}
      >
        <AnimatedButton variant="primary">
          Open Wallet
        </AnimatedButton>
        <AnimatedButton variant="secondary">
          Block Explorer
        </AnimatedButton>
      </motion.nav>
    </motion.header>
  );
}
```

### CSS pour le parallax

```css
/* Landing.css - Parallax styles */
.parallax-hero {
  position: relative;
  height: 100vh;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  overflow: hidden;
  background:
    radial-gradient(ellipse at 20% 80%, rgba(45, 212, 191, 0.1) 0%, transparent 50%),
    radial-gradient(ellipse at 80% 20%, rgba(6, 182, 212, 0.1) 0%, transparent 50%),
    linear-gradient(180deg, #0f172a 0%, #1e293b 100%);
}

.parallax-hero::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background:
    url('data:image/svg+xml,<svg width="60" height="60" viewBox="0 0 60 60" xmlns="http://www.w3.org/2000/svg"><g fill="none" fill-rule="evenodd"><g fill="%234ade80" fill-opacity="0.05"><polygon points="30,0 60,30 30,60 0,30"/></g></svg>');
  animation: float 20s ease-in-out infinite;
}

@keyframes float {
  0%, 100% { transform: translateY(0px) rotate(0deg); }
  50% { transform: translateY(-20px) rotate(180deg); }
}

.parallax-hero .logo {
  width: 120px;
  height: 120px;
  margin-bottom: 2rem;
}

.parallax-hero .title {
  font-size: 4rem;
  font-weight: 900;
  margin-bottom: 1rem;
  background: linear-gradient(135deg, #2dd4bf, #06b6d4);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  text-shadow: 0 0 40px rgba(45, 212, 191, 0.3);
}

.parallax-hero .tagline {
  font-size: 1.25rem;
  margin-bottom: 3rem;
  color: rgba(255, 255, 255, 0.8);
  text-align: center;
}
```

---

## 4. Animations des Sections lors du Scroll

### Hook pour animations sur scroll

```tsx
// hooks/useScrollAnimation.ts
import { useScroll, useTransform } from 'framer-motion';
import { useRef } from 'react';

export function useScrollAnimation() {
  const ref = useRef<HTMLElement>(null);
  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ["start 0.8", "start 0.2"]
  });

  const y = useTransform(scrollYProgress, [0, 1], [50, 0]);
  const opacity = useTransform(scrollYProgress, [0, 1], [0, 1]);

  return { ref, y, opacity };
}
```

### Composant Section animée

```tsx
// components/AnimatedSection.tsx
import { motion } from 'framer-motion';
import { useScrollAnimation } from '../hooks/useScrollAnimation';

interface AnimatedSectionProps {
  children: React.ReactNode;
  className?: string;
  delay?: number;
}

export default function AnimatedSection({
  children,
  className = '',
  delay = 0
}: AnimatedSectionProps) {
  const { ref, y, opacity } = useScrollAnimation();

  return (
    <motion.section
      ref={ref}
      className={`section ${className}`}
      style={{ y, opacity }}
      initial={{ opacity: 0, y: 50 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6, delay, ease: "easeOut" }}
    >
      {children}
    </motion.section>
  );
}
```

---

## 5. Animation de la Démo Interactive Plonky2

### États animés pour la démo

```tsx
// Amélioration de la démo dans Landing.tsx
const demoButtonVariants = {
  idle: {
    scale: 1,
    background: "linear-gradient(135deg, #0ea5e9, #06b6d4)"
  },
  loading: {
    scale: 1.05,
    background: [
      "linear-gradient(135deg, #0ea5e9, #06b6d4)",
      "linear-gradient(135deg, #06b6d4, #0ea5e9)",
      "linear-gradient(135deg, #0ea5e9, #06b6d4)"
    ],
    transition: {
      background: {
        duration: 2,
        repeat: Infinity,
        ease: "easeInOut"
      }
    }
  },
  success: {
    scale: 1.02,
    background: "linear-gradient(135deg, #10b981, #059669)",
    transition: { duration: 0.5 }
  },
  error: {
    scale: 0.98,
    background: "linear-gradient(135deg, #ef4444, #dc2626)",
    transition: { duration: 0.3 }
  }
};

// Dans le JSX de la démo
<motion.button
  className="demo-button"
  variants={demoButtonVariants}
  animate={demoState.status}
  onClick={runPlonkyDemo}
  disabled={demoState.status === 'loading'}
>
  {demoState.status === 'loading' ? 'Generating...' : 'Generate Proof'}
</motion.button>
```

---

## 6. Micros-animations d'Interface

### Animations des features cards

```tsx
// components/FeatureCard.tsx
import { motion } from 'framer-motion';

const cardVariants = {
  hidden: { opacity: 0, y: 20, scale: 0.95 },
  visible: (index: number) => ({
    opacity: 1,
    y: 0,
    scale: 1,
    transition: {
      delay: index * 0.1,
      duration: 0.4,
      ease: "easeOut"
    }
  }),
  hover: {
    y: -5,
    scale: 1.02,
    transition: { duration: 0.2 }
  }
};

interface FeatureCardProps {
  icon: string;
  title: string;
  description: string;
  index: number;
}

export default function FeatureCard({ icon, title, description, index }: FeatureCardProps) {
  return (
    <motion.div
      className="feature"
      variants={cardVariants}
      initial="hidden"
      animate="visible"
      whileHover="hover"
      custom={index}
    >
      <motion.div
        className="feature-icon"
        whileHover={{ rotate: 360, scale: 1.1 }}
        transition={{ duration: 0.6 }}
      >
        {icon}
      </motion.div>
      <h3>{title}</h3>
      <p>{description}</p>
    </motion.div>
  );
}
```

---

## Implementation Roadmap

### Phase 1 : Bases (Sprint actuel)
1. ✅ Installer et configurer Framer Motion
2. 🔄 Implémenter les boutons animés
3. 🔄 Ajouter les transitions de page
4. 🔄 Créer l'effet parallax hero

### Phase 2 : Enrichissement
1. Animations des sections au scroll
2. Micro-animations de la démo interactive
3. Animations des feature cards

### Phase 3 : Optimisation
1. Performance monitoring
2. Réduction des animations sur mobile si nécessaire
3. A/B testing des timings

---

## Guidelines Techniques

### Performance
- Utiliser `transform` et `opacity` (GPU-accelerated)
- Éviter `width`, `height`, `margin` dans les animations
- Limiter les animations simultanées à 3-4 éléments max

### Accessibilité
```css
@media (prefers-reduced-motion: reduce) {
  * {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}
```

### Timing quantique
- Durées principales : 0.2s, 0.4s, 0.6s, 0.8s (multiples de 0.2)
- Ease curves : `easeOut` pour les entrées, `easeIn` pour les sorties
- Delays échelonnés : 0.1s entre éléments d'une série

---

*Ce guide respecte l'identité TSN : technologie de pointe avec élégance, sans sacrifier les performances ni l'accessibilité.*