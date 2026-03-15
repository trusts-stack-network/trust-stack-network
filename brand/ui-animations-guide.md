# Guide d'implémentation : Animations UI TSN avec Framer Motion

## 🎯 Objectif
Rendre l'interface TSN aussi fluide que la blockchain qu'elle représente — avec des animations qui communiquent la sécurité post-quantique sans sacrifier la performance.

## 1. Hover Buttons — "Quantum Entanglement Effect"

```typescript
// components/ui/QuantumButton.tsx
import { motion } from 'framer-motion';

const QuantumButton = ({ children, ...props }) => {
  return (
    <motion.button
      whileHover={{ 
        scale: 1.02,
        boxShadow: "0 0 20px rgba(59, 130, 246, 0.5)",
        transition: { duration: 0.2, ease: "easeOut" }
      }}
      whileTap={{ scale: 0.98 }}
      className="relative overflow-hidden bg-gradient-to-r from-blue-600 to-purple-600 text-white px-6 py-3 rounded-lg font-medium"
      {...props}
    >
      <motion.div
        className="absolute inset-0 bg-white/20"
        initial={{ x: "-100%" }}
        whileHover={{ x: "100%" }}
        transition={{ duration: 0.6, ease: "easeInOut" }}
      />
      {children}
    </motion.button>
  );
};
// components/TransitionWrapper.tsx
import { motion, AnimatePresence } from 'framer-motion';

const pageVariants = {
  initial: { 
    opacity: 0, 
    y: 20,
    filter: "blur(4px)"
  },
  animate: { 
    opacity: 1, 
    y: 0,
    filter: "blur(0px)",
    transition: {
      duration: 0.4,
      ease: [0.23, 1, 0.32, 1]
    }
  },
  exit: { 
    opacity: 0, 
    y: -20,
    filter: "blur(4px)",
    transition: {
      duration: 0.3
    }
  }
};

export const TransitionWrapper = ({ children }) => (
  <AnimatePresence mode="wait">
    <motion.div
      key={window.location.pathname}
      variants={pageVariants}
      initial="initial"
      animate="animate"
      exit="exit"
    >
      {children}
    </motion.div>
  </AnimatePresence>
);
// components/sections/HeroParallax.tsx
import { motion, useScroll, useTransform } from 'framer-motion';
import { useRef } from 'react';

export const HeroParallax = () => {
  const containerRef = useRef(null);
  const { scrollYProgress } = useScroll({
    target: containerRef,
    offset: ["start start", "end start"]
  });

  const y1 = useTransform(scrollYProgress, [0, 1], [0, -100]);
  const y2 = useTransform(scrollYProgress, [0, 1], [0, -200]);
  const opacity = useTransform(scrollYProgress, [0, 0.5], [1, 0]);

  return (
    <div ref={containerRef} className="relative h-screen overflow-hidden">
      {/* Layer 1: Background grid */}
      <motion.div 
        style={{ y: y2 }}
        className="absolute inset-0 bg-grid-pattern opacity-10"
      />
      
      {/* Layer 2: Floating particles */}
      <motion.div style={{ y: y1 }}>
        {[...Array(20)].map((_, i) => (
          <motion.div
            key={i}
            className="absolute w-2 h-2 bg-blue-400 rounded-full"
            style={{
              left: `${Math.random() * 100}%`,
              top: `${Math.random() * 100}%`,
            }}
            animate={{
              y: [0, -30, 0],
              opacity: [0.3, 1, 0.3],
            }}
            transition={{
              duration: 3 + Math.random() * 2,
              repeat: Infinity,
              delay: Math.random() * 2,
            }}
          />
        ))}
      </motion.div>
      
      {/* Layer 3: Content */}
      <motion.div 
        style={{ opacity }}
        className="relative z-10 flex flex-col items-center justify-center h-full"
      >
        <h1 className="text-6xl font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
          Trust Stack Network
        </h1>
        <p className="mt-4 text-xl text-gray-300">
          La blockchain post-quantique construite par l'IA
        </p>
      </motion.div>
    </div>
  );
};
const shouldReduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

<motion.div
  animate={shouldReduceMotion ? {} : { scale: 1.1 }}
>
const QuantumLoader = () => (
  <div className="flex space-x-2">
    {[0, 1, 2].map((i) => (
      <motion.div
        key={i}
        className="w-3 h-3 bg-blue-500 rounded-full"
        animate={{
          scale: [1, 1.5, 1],
          opacity: [1, 0.5, 1],
        }}
        transition={{
          duration: 1.5,
          repeat: Infinity,
          delay: i * 0.2,
        }}
      />
    ))}
  </div>
);