# Guide d'implémentation : Animations UI TSN avec Framer Motion

## 🎯 Objectif
Rendre l'interface TSN aussi fluide que la blockchain qu'elle représente — des transitions qui communiquent la sécurité post-quantique sans un mot.

## 1. Hover Buttons — "Trust in Motion"

### Effet principal
```typescript
// components/ui/QuantumButton.tsx
<motion.button
  whileHover={{ 
    scale: 1.02,
    boxShadow: "0 0 20px rgba(59, 130, 246, 0.5)",
    transition: { duration: 0.2, ease: "easeOut" }
  }}
  whileTap={{ scale: 0.98 }}
  className="quantum-glow"
>
  {children}
</motion.button>
.quantum-glow {
  position: relative;
  overflow: hidden;
}

.quantum-glow::before {
  content: '';
  position: absolute;
  top: 50%;
  left: 50%;
  width: 0;
  height: 0;
  background: radial-gradient(circle, rgba(59, 130, 246, 0.3) 0%, transparent 70%);
  transform: translate(-50%, -50%);
  transition: width 0.4s, height 0.4s;
}

.quantum-glow:hover::before {
  width: 300%;
  height: 300%;
}
// components/layout/PageTransition.tsx
<AnimatePresence mode="wait">
  <motion.div
    key={router.pathname}
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    exit={{ opacity: 0, y: -20 }}
    transition={{ 
      duration: 0.4,
      ease: [0.43, 0.13, 0.23, 0.96]
    }}
  >
    {children}
  </motion.div>
</AnimatePresence>
<motion.div
  initial={{ opacity: 0, scale: 0.9 }}
  animate={{ opacity: 1, scale: 1 }}
  transition={{ 
    duration: 0.3,
    delay: 0.1,
    type: "spring",
    stiffness: 200,
    damping: 20
  }}
>
// components/sections/HeroParallax.tsx
const { scrollY } = useScroll();
const y1 = useTransform(scrollY, [0, 1000], [0, -200]);
const y2 = useTransform(scrollY, [0, 1000], [0, -100]);
const opacity = useTransform(scrollY, [0, 500], [1, 0]);

return (
  <div className="relative h-screen overflow-hidden">
    {/* Background layers */}
    <motion.div 
      style={{ y: y1 }}
      className="absolute inset-0 bg-gradient-to-b from-blue-900 via-purple-900 to-black"
    />
    
    {/* Particules quantiques */}
    <motion.div 
      style={{ y: y2 }}
      className="absolute inset-0"
    >
      {[...Array(20)].map((_, i) => (
        <motion.div
          key={i}
          className="absolute w-1 h-1 bg-blue-400 rounded-full"
          style={{
            left: `${Math.random() * 100}%`,
            top: `${Math.random() * 100}%`,
          }}
          animate={{
            opacity: [0, 1, 0],
            scale: [0, 1, 0],
          }}
          transition={{
            duration: 3 + Math.random() * 2,
            repeat: Infinity,
            delay: Math.random() * 2,
          }}
        />
      ))}
    </motion.div>

    {/* Contenu */}
    <motion.div
      style={{ opacity }}
      className="relative z-10 flex items-center justify-center h-full"
    >
      <h1 className="text-6xl font-bold text-white">
        Trust Stack Network
      </h1>
    </motion.div>
  </div>
);
export const animationTiming = {
  instant: 0.15,
  fast: 0.3,
  normal: 0.4,
  slow: 0.6,
  quantum: 1.2,
};
export const easing = {
  quantum: [0.43, 0.13, 0.23, 0.96],
  smooth: [0.25, 0.46, 0.45, 0.94],
  bounce: [0.68, -0.55, 0.265, 1.55],
};
.quantum-animated {
  will-change: transform, opacity;
  transform: translateZ(0);
}
const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

<motion.div
  animate={prefersReducedMotion ? {} : { scale: [1, 1.05, 1] }}
>
const controls = useAnimation();
const [ref, inView] = useInView();

useEffect(() => {
  if (inView) {
    controls.start({ opacity: 1, y: 0 });
  }
}, [controls, inView]);