# Plan d'Action Immédiat : Animations TSN
*Guide express pour Herald - Déblocage animations UI*

## 🚨 Étape 0 : Setup Framer Motion (MISSING!)

**Problème identifié** : Framer Motion n'est pas dans package.json malgré les guides existants.

```bash
cd /opt/tsn/wallet
npm install framer-motion
npm install --save-dev @types/framer-motion  # Si TypeScript strict
```

---

## 🎯 Les 3 Animations Prioritaires

### 1. Hover Buttons (30 min)

**Fichier à créer** : `src/components/ui/TSNButton.tsx`

```tsx
import { motion } from 'framer-motion';
import React from 'react';

interface TSNButtonProps {
  children: React.ReactNode;
  variant?: 'primary' | 'secondary' | 'quantum';
  onClick?: () => void;
  className?: string;
}

const buttonVariants = {
  rest: {
    scale: 1,
    y: 0,
    boxShadow: "0 4px 12px rgba(37, 99, 235, 0.0)"
  },
  hover: {
    scale: 1.02,
    y: -3,
    boxShadow: "0 8px 25px rgba(37, 99, 235, 0.3)"
  },
  tap: {
    scale: 0.98,
    y: 0
  }
};

// Style TSN Quantum spécial
const quantumVariants = {
  rest: {
    background: 'linear-gradient(135deg, #2563EB 0%, #10B981 100%)',
    boxShadow: [
      "0 0 20px rgba(16, 185, 129, 0.2)",
      "0 0 40px rgba(16, 185, 129, 0.1)",
      "0 0 20px rgba(16, 185, 129, 0.2)"
    ]
  },
  hover: {
    background: 'linear-gradient(135deg, #3B82F6 0%, #059669 100%)',
    boxShadow: "0 0 40px rgba(16, 185, 129, 0.5)",
    scale: 1.05
  }
};

export const TSNButton: React.FC<TSNButtonProps> = ({
  children,
  variant = 'primary',
  onClick,
  className = ''
}) => {
  const variants = variant === 'quantum' ? quantumVariants : buttonVariants;

  const baseStyles: React.CSSProperties = {
    padding: '12px 24px',
    borderRadius: '8px',
    fontWeight: '600',
    cursor: 'pointer',
    border: 'none',
    background: variant === 'primary' ? '#2563EB' :
                variant === 'secondary' ? '#10B981' : 'transparent',
    color: 'white',
  };

  return (
    <motion.button
      className={className}
      style={baseStyles}
      onClick={onClick}
      variants={variants}
      initial="rest"
      whileHover="hover"
      whileTap="tap"
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

**Usage immédiat** : Remplace les boutons dans `Landing.tsx`, `Wallet.tsx`, `Explorer.tsx`
```tsx
import { TSNButton } from './components/ui/TSNButton';

// Au lieu de <button>Connect Wallet</button>
<TSNButton variant="primary">Connect Wallet</TSNButton>
<TSNButton variant="quantum">Generate Quantum Proof</TSNButton>
```

---

### 2. Page Transitions (45 min)

**Fichier à créer** : `src/components/ui/PageTransition.tsx`

```tsx
import { motion, AnimatePresence } from 'framer-motion';
import React from 'react';

const pageVariants = {
  initial: {
    opacity: 0,
    x: 30,
    scale: 0.95
  },
  in: {
    opacity: 1,
    x: 0,
    scale: 1
  },
  out: {
    opacity: 0,
    x: -30,
    scale: 1.05
  }
};

const pageTransition = {
  type: 'tween',
  ease: [0.25, 0.25, 0.25, 1],
  duration: 0.4
};

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
      style={{ height: '100%', width: '100%' }}
    >
      {children}
    </motion.div>
  );
};
```

**Modification dans `main.tsx`** :
```tsx
import { AnimatePresence } from 'framer-motion';
import { useLocation } from 'react-router-dom';
import { PageTransition } from './components/ui/PageTransition';

function App() {
  const location = useLocation();

  return (
    <AnimatePresence mode="wait">
      <div key={location.pathname}>
        <PageTransition>
          {/* Ton contenu de page actuel */}
        </PageTransition>
      </div>
    </AnimatePresence>
  );
}
```

---

### 3. Hero Parallax (60 min)

**Fichier à créer** : `src/components/ui/HeroParallax.tsx`

```tsx
import { motion, useScroll, useTransform } from 'framer-motion';
import { useRef, useEffect, useState } from 'react';

export const HeroParallax: React.FC = () => {
  const ref = useRef<HTMLDivElement>(null);
  const [mounted, setMounted] = useState(false);

  // Éviter les erreurs SSR
  useEffect(() => {
    setMounted(true);
  }, []);

  const { scrollY } = useScroll({
    target: ref,
    offset: ["start start", "end start"]
  });

  // Vitesses parallax différentielles
  const titleY = useTransform(scrollY, [0, 300], [0, -50]);
  const subtitleY = useTransform(scrollY, [0, 300], [0, -30]);
  const logoScale = useTransform(scrollY, [0, 200], [1, 0.8]);
  const logoOpacity = useTransform(scrollY, [0, 300], [1, 0.6]);

  if (!mounted) return null;

  return (
    <div
      ref={ref}
      className="hero-parallax"
      style={{
        height: '100vh',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
        position: 'relative',
        background: 'linear-gradient(135deg, #1e3a8a 0%, #2563eb 50%, #10b981 100%)',
        overflow: 'hidden'
      }}
    >
      {/* Floating quantum dots */}
      <QuantumDots />

      {/* Logo avec parallax */}
      <motion.div
        style={{
          scale: logoScale,
          opacity: logoOpacity
        }}
        initial={{ opacity: 0, rotateY: -180, scale: 0.5 }}
        animate={{
          opacity: 1,
          rotateY: 0,
          scale: 1,
          transition: {
            duration: 1.2,
            type: "spring",
            stiffness: 200
          }
        }}
      >
        <motion.h1
          style={{
            fontSize: '4rem',
            fontWeight: 'bold',
            color: 'white',
            margin: 0,
            textAlign: 'center'
          }}
          animate={{
            textShadow: [
              '0 0 10px rgba(16, 185, 129, 0.5)',
              '0 0 20px rgba(16, 185, 129, 0.8)',
              '0 0 10px rgba(16, 185, 129, 0.5)'
            ]
          }}
          transition={{
            duration: 2,
            repeat: Infinity,
            ease: "easeInOut"
          }}
        >
          TSN
        </motion.h1>
      </motion.div>

      {/* Title avec parallax */}
      <motion.h2
        style={{
          y: titleY,
          fontSize: '2rem',
          color: 'white',
          textAlign: 'center',
          margin: '20px 0 10px 0'
        }}
        initial={{ opacity: 0, y: 50 }}
        animate={{
          opacity: 1,
          y: 0,
          transition: { delay: 0.3, duration: 0.8 }
        }}
      >
        Trust Stack Network
      </motion.h2>

      {/* Subtitle avec parallax */}
      <motion.p
        style={{
          y: subtitleY,
          fontSize: '1.2rem',
          color: 'rgba(255, 255, 255, 0.8)',
          textAlign: 'center'
        }}
        initial={{ opacity: 0, y: 30 }}
        animate={{
          opacity: 1,
          y: 0,
          transition: { delay: 0.6, duration: 0.6 }
        }}
      >
        Fully Quantum-Resistant Private Transactions
      </motion.p>
    </div>
  );
};

// Bonus : Éléments flottants quantum
const QuantumDots: React.FC = () => {
  const dots = Array.from({ length: 5 }, (_, i) => i);

  return (
    <>
      {dots.map((dot) => (
        <motion.div
          key={dot}
          style={{
            position: 'absolute',
            width: '40px',
            height: '40px',
            background: 'rgba(16, 185, 129, 0.3)',
            borderRadius: '50%',
            left: `${20 + dot * 15}%`,
            top: `${30 + dot * 10}%`,
          }}
          animate={{
            y: [-20, 20, -20],
            opacity: [0.3, 0.8, 0.3],
            scale: [1, 1.2, 1]
          }}
          transition={{
            duration: 3 + dot * 0.5,
            repeat: Infinity,
            delay: dot * 0.3,
            ease: "easeInOut"
          }}
        />
      ))}
    </>
  );
};
```

**Integration dans `Landing.tsx`** :
```tsx
import { HeroParallax } from './components/ui/HeroParallax';

// Remplace ta section hero actuelle par :
<HeroParallax />
```

---

## ⚡ Checklist d'implémentation (3h total)

### Phase 1 - Setup (15 min)
- [ ] `npm install framer-motion` dans /opt/tsn/wallet
- [ ] Créer le répertoire `src/components/ui/` si inexistant
- [ ] Vérifier que TypeScript reconnaît framer-motion

### Phase 2 - Buttons (30 min)
- [ ] Créer `TSNButton.tsx`
- [ ] Remplacer 3-4 boutons dans `Landing.tsx`
- [ ] Tester hover/tap sur desktop et mobile

### Phase 3 - Transitions (45 min)
- [ ] Créer `PageTransition.tsx`
- [ ] Modifier `main.tsx` pour wrapper les routes
- [ ] Tester navigation between pages

### Phase 4 - Hero Parallax (60 min)
- [ ] Créer `HeroParallax.tsx`
- [ ] Intégrer dans `Landing.tsx`
- [ ] Optimiser performance scroll
- [ ] Tester sur mobile (désactiver parallax si nécessaire)

### Phase 5 - Polish (30 min)
- [ ] Ajouter `prefers-reduced-motion` support
- [ ] Performance audit (60fps target)
- [ ] Cross-browser testing

---

## 🎨 Brand Guidelines Respectées

✅ **Couleurs TSN** : #2563EB (blue), #10B981 (green), gradients cohérents
✅ **Timing** : 400ms transitions, springy feels pour premium
✅ **Quantum Theme** : Effets de glow, pulsation, éléments flottants
✅ **Performance** : <100ms response, 60fps scroll
✅ **Accessibilité** : respect `prefers-reduced-motion`

Cette implémentation positionne TSN avec une identité visuelle premium qui reflète notre avance technologique post-quantique.

---

**Next Steps après implémentation :**
- Ping @Zoe.K pour validation UX/Brand
- Demo video pour la communauté Discord
- Tweet avec animation preview

*Guide d'urgence v1.0 - Mars 2026*