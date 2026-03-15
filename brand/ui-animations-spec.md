# Spécifications Animations UI — Trust Stack Network

## Vision Brand pour l'Expérience Utilisateur

L'interface TSN doit refléter notre identité : **précision technique et fluidité futuriste**. Chaque animation sert un objectif UX précis — pas de bling gratuit, juste de l'efficacité avec du style.

**Principe directeur** : "Smooth as quantum entanglement, fast as post-quantum signatures"

---

## 🎯 Animation 1 : Button Hover Effects

**Objectif** : Feedback visuel immédiat pour les CTA critiques (Connect Wallet, Send Transaction, Mine Block)

### Spécifications Techniques

```javascript
// Utiliser ces variants Framer Motion
const buttonVariants = {
  idle: {
    scale: 1,
    boxShadow: "0 4px 12px rgba(59, 130, 246, 0.15)",
    backgroundColor: "rgb(59, 130, 246)"
  },
  hover: {
    scale: 1.02,
    boxShadow: "0 8px 24px rgba(59, 130, 246, 0.3)",
    backgroundColor: "rgb(37, 99, 235)",
    transition: {
      duration: 0.2,
      ease: "easeOut"
    }
  },
  tap: {
    scale: 0.98,
    transition: {
      duration: 0.1
    }
  }
}
```

### Couleurs TSN Brand
- **Primary** : #3B82F6 (TSN Blue)
- **Hover** : #2563EB (Darker Blue)
- **Success** : #10B981 (Transaction Confirmed)
- **Warning** : #F59E0B (Pending States)

---

## 🎯 Animation 2 : Page Transitions

**Objectif** : Continuité narrative entre Dashboard → Wallet → Explorer → Mining

### Route Mapping
```
Dashboard → Wallet     : slideInRight (nouveau contexte)
Wallet → Dashboard     : slideInLeft (retour contexte)
Explorer → Mining      : fadeThrough (changement de domaine)
Any → Settings         : slideInFromBottom (overlay context)
```

### Spécifications Framer Motion

```javascript
// Layout global avec AnimatePresence
const pageVariants = {
  enter: {
    opacity: 0,
    x: 300,
  },
  center: {
    opacity: 1,
    x: 0,
    transition: {
      duration: 0.4,
      ease: [0.25, 0.46, 0.45, 0.94] // cubic-bezier custom TSN
    }
  },
  exit: {
    opacity: 0,
    x: -300,
    transition: {
      duration: 0.3,
      ease: "easeIn"
    }
  }
}

// Utilisation dans App.tsx
<AnimatePresence mode="wait">
  <motion.div
    key={location.pathname}
    variants={pageVariants}
    initial="enter"
    animate="center"
    exit="exit"
  >
    {children}
  </motion.div>
</AnimatePresence>
```

---

## 🎯 Animation 3 : Parallax Hero Section

**Objectif** : Immersion immediate — communiquer "Post-Quantum is Now" dès l'arrivée

### Concept Visual
Hero section en 3 couches :
1. **Background** : Gradient quantique (mouvement subtil)
2. **Midground** : Logo TSN + tagline (mouvement moyen)
3. **Foreground** : CTA buttons (mouvement rapide)

### Implémentation avec `useScroll`

```javascript
import { useScroll, useTransform, motion } from "framer-motion"

export default function HeroParallax() {
  const { scrollY } = useScroll()

  // Différentiel de vitesse pour effet parallax
  const backgroundY = useTransform(scrollY, [0, 800], [0, 200])
  const midgroundY = useTransform(scrollY, [0, 800], [0, 100])
  const foregroundY = useTransform(scrollY, [0, 800], [0, 50])

  return (
    <section className="relative h-screen overflow-hidden">
      {/* Background Layer */}
      <motion.div
        className="absolute inset-0 bg-gradient-to-br from-blue-900 via-purple-900 to-black"
        style={{ y: backgroundY }}
      />

      {/* Midground Layer */}
      <motion.div
        className="absolute inset-0 flex items-center justify-center"
        style={{ y: midgroundY }}
      >
        <div className="text-center">
          <h1 className="text-6xl font-bold text-white mb-6">
            Trust Stack Network
          </h1>
          <p className="text-xl text-blue-200">
            La blockchain post-quantique qui protège votre futur
          </p>
        </div>
      </motion.div>

      {/* Foreground Layer */}
      <motion.div
        className="absolute bottom-32 left-1/2 transform -translate-x-1/2"
        style={{ y: foregroundY }}
      >
        <motion.button
          variants={buttonVariants}
          initial="idle"
          whileHover="hover"
          whileTap="tap"
          className="px-8 py-4 bg-blue-600 text-white rounded-lg font-semibold"
        >
          Explorer la Blockchain TSN
        </motion.button>
      </motion.div>
    </section>
  )
}
```

---

## 📊 Performance Guidelines

### Budgets Animation
- **60fps minimum** pour toutes les interactions
- **Budget GPU** : max 3 layers parallax simultanés
- **Mobile first** : réduire les effets sur viewport < 768px

### Code de Performance

```javascript
// Utiliser transform au lieu de left/top
// ✅ Bon
transform: `translateX(${x}px)`

// ❌ Mauvais
left: `${x}px`

// ✅ Utiliser will-change pour optimiser
.parallax-layer {
  will-change: transform;
}

// ✅ Cleanup des animations
useEffect(() => {
  return () => {
    // Cleanup listeners scroll
  }
}, [])
```

---

## 🎨 Brand Consistency

### Timing Signature TSN
- **Fast interactions** : 0.1-0.2s (buttons, hovers)
- **Medium transitions** : 0.3-0.5s (page changes, modals)
- **Slow storytelling** : 0.8-1.2s (parallax, hero reveals)

### Easing Curves Personnalisées
```css
/* TSN Signature Easing */
--tsn-ease-in: cubic-bezier(0.25, 0.46, 0.45, 0.94);
--tsn-ease-out: cubic-bezier(0.16, 1, 0.3, 1);
--tsn-ease-bounce: cubic-bezier(0.68, -0.55, 0.265, 1.55);
```

---

## 🚀 Roadmap Implementation

### Phase 1 (Cette semaine)
- [ ] Button hover effects sur tous les CTA
- [ ] Page transitions Dashboard ↔ Wallet
- [ ] Parallax hero basic (3 layers)

### Phase 2 (Semaine suivante)
- [ ] Micro-interactions form validation
- [ ] Transaction status animations
- [ ] Loading states avec physics

### Phase 3 (Future)
- [ ] Graph mining animations (canvas)
- [ ] Blockchain visualization effects
- [ ] Advanced scroll-triggered animations

---

**Note pour Herald** : Toutes ces animations utilisent Framer Motion déjà dans `package.json`. Pas de nouvelle dépendance. Le code est optimisé pour le SSG Vite.

*Questions technique ? Ping moi sur Discord — Zoe.K*