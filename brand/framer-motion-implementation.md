# Implémentation Framer Motion pour TSN
## Guide technique pour Herald - Animations prioritaires

### 🎯 Roadmap technique immédiate

**Phase 1 - Foundations (Cette semaine)**
1. ✅ Setup Framer Motion (déjà dans les deps)
2. 🔧 Implement hover button effects
3. 🔧 Add page transitions
4. 🔧 Create parallax hero section

---

## 1. Button Hover Effects

### Code base réutilisable

```tsx
// components/TSNButton.tsx
import { motion } from 'framer-motion';

interface TSNButtonProps {
  children: React.ReactNode;
  variant?: 'primary' | 'secondary' | 'outline';
  onClick?: () => void;
}

export const TSNButton: React.FC<TSNButtonProps> = ({
  children,
  variant = 'primary',
  onClick
}) => {
  const baseStyles = {
    padding: '12px 24px',
    borderRadius: '8px',
    fontWeight: '600',
    cursor: 'pointer',
    border: 'none',
  };

  const variantStyles = {
    primary: {
      backgroundColor: '#2563EB',
      color: 'white',
    },
    secondary: {
      backgroundColor: '#10B981',
      color: 'white',
    },
    outline: {
      backgroundColor: 'transparent',
      color: '#2563EB',
      border: '2px solid #2563EB',
    }
  };

  return (
    <motion.button
      style={{...baseStyles, ...variantStyles[variant]}}
      onClick={onClick}
      whileHover={{
        scale: 1.02,
        y: -2,
        boxShadow: '0 4px 12px rgba(37, 99, 235, 0.3)'
      }}
      whileTap={{ scale: 0.98 }}
      transition={{
        type: 'spring',
        stiffness: 400,
        damping: 17
      }}
    >
      {children}
    </motion.button>
  );
};
```

### Usage
```tsx
// Dans tes composants
<TSNButton variant="primary" onClick={handleSubmit}>
  Connect Wallet
</TSNButton>
```

---

## 2. Page Transitions

### Setup du router avec animations

```tsx
// hooks/usePageTransition.ts
import { AnimatePresence, motion } from 'framer-motion';

export const pageVariants = {
  initial: {
    opacity: 0,
    x: 20,
  },
  in: {
    opacity: 1,
    x: 0,
  },
  out: {
    opacity: 0,
    x: -20,
  },
};

export const pageTransition = {
  type: 'tween',
  ease: 'anticipate',
  duration: 0.3,
};

// Wrapper component
export const PageTransition: React.FC<{ children: React.ReactNode }> = ({
  children
}) => {
  return (
    <motion.div
      initial="initial"
      animate="in"
      exit="out"
      variants={pageVariants}
      transition={pageTransition}
    >
      {children}
    </motion.div>
  );
};
```

### Intégration avec React Router

```tsx
// App.tsx ou ton router principal
import { AnimatePresence } from 'framer-motion';
import { useLocation } from 'react-router-dom';

function App() {
  const location = useLocation();

  return (
    <AnimatePresence mode="wait">
      <Routes location={location} key={location.pathname}>
        <Route path="/" element={
          <PageTransition>
            <HomePage />
          </PageTransition>
        } />
        <Route path="/explorer" element={
          <PageTransition>
            <ExplorerPage />
          </PageTransition>
        } />
        {/* Autres routes... */}
      </Routes>
    </AnimatePresence>
  );
}
```

---

## 3. Hero Section Parallax

### Component parallax principal

```tsx
// components/HeroParallax.tsx
import { motion, useScroll, useTransform } from 'framer-motion';
import { useRef } from 'react';

export const HeroParallax: React.FC = () => {
  const ref = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ["start start", "end start"]
  });

  // Différentes vitesses pour créer l'effet de profondeur
  const backgroundY = useTransform(scrollYProgress, [0, 1], ["0%", "50%"]);
  const textY = useTransform(scrollYProgress, [0, 1], ["0%", "25%"]);
  const blockchainY = useTransform(scrollYProgress, [0, 1], ["0%", "75%"]);

  return (
    <div ref={ref} className="hero-container" style={{ height: '100vh', overflow: 'hidden' }}>
      {/* Background layer - plus lent */}
      <motion.div
        className="hero-background"
        style={{
          y: backgroundY,
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'linear-gradient(135deg, #1e3a8a 0%, #1e40af 50%, #2563eb 100%)',
          zIndex: 1
        }}
      />

      {/* Blockchain visualization - plus rapide */}
      <motion.div
        className="blockchain-viz"
        style={{
          y: blockchainY,
          position: 'absolute',
          top: '20%',
          right: '10%',
          zIndex: 2,
          opacity: 0.6
        }}
      >
        <BlockchainAnimation />
      </motion.div>

      {/* Text content - vitesse intermédiaire */}
      <motion.div
        className="hero-content"
        style={{
          y: textY,
          position: 'relative',
          zIndex: 3,
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          alignItems: 'center',
          height: '100%',
          color: 'white',
          textAlign: 'center'
        }}
      >
        <h1 className="hero-title">Trust Stack Network</h1>
        <p className="hero-subtitle">La première blockchain post-quantique</p>
        <TSNButton variant="secondary">
          Explorer la documentation
        </TSNButton>
      </motion.div>
    </div>
  );
};

// Petit bonus - animation de blockchain stylée
const BlockchainAnimation: React.FC = () => {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 1, delay: 0.5 }}
      style={{ display: 'flex', gap: '10px' }}
    >
      {[...Array(5)].map((_, i) => (
        <motion.div
          key={i}
          style={{
            width: '40px',
            height: '40px',
            backgroundColor: 'rgba(16, 185, 129, 0.8)',
            borderRadius: '8px',
          }}
          animate={{
            scale: [1, 1.1, 1],
            opacity: [0.8, 1, 0.8],
          }}
          transition={{
            duration: 2,
            repeat: Infinity,
            delay: i * 0.2,
          }}
        />
      ))}
    </motion.div>
  );
};
```

---

## 🚀 Étapes d'implémentation

### Jour 1 - Buttons
1. Créer `TSNButton.tsx` avec les variantes
2. Remplacer tous les buttons existants
3. Tester sur mobile + `prefers-reduced-motion`

### Jour 2 - Page transitions
1. Setup `PageTransition` wrapper
2. Intégrer avec React Router
3. Tester navigation fluide

### Jour 3 - Hero parallax
1. Implémenter `HeroParallax` component
2. Optimiser performance scroll
3. Tests cross-browser

---

## 🧪 Tests & Performance

```tsx
// utils/performanceTests.ts
export const measureFrameRate = () => {
  let lastTime = performance.now();
  let frames = 0;

  function tick() {
    const now = performance.now();
    if (now - lastTime >= 1000) {
      console.log(`FPS: ${frames}`);
      frames = 0;
      lastTime = now;
    }
    frames++;
    requestAnimationFrame(tick);
  }

  requestAnimationFrame(tick);
};
```

### Checklist final
- [ ] FPS constant à 60
- [ ] Transitions fluides sur mobile
- [ ] Respect de `prefers-reduced-motion`
- [ ] Pas de layout shift
- [ ] Loading states animés

---

*Guide technique v1.0 pour Herald - Mars 2026*
*Ping @Zoe.K quand c'est déployé pour validation brand* 🚀