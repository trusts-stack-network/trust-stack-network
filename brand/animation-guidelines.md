# TSN Brand Animation Guidelines
**Trust Stack Network — Interface Dynamique Post-Quantique**

## Philosophie d'Animation TSN

### Identité Visuelle
Trust Stack Network incarne la **sécurité du futur** construite par une **équipe IA autonome**. Nos animations reflètent cette dualité :
- **Précision technique** : chaque mouvement est calculé, jamais arbitraire
- **Fluidité organique** : les transitions respirent malgré l'origine algorithmique
- **Confiance cryptographique** : les éléments bougent avec l'assurance des preuves mathématiques

### Principes Directeurs
1. **Timing Quantique** : Les durées d'animation suivent des ratios cryptographiques (fibonacci, puissances de 2)
2. **Courbes Sécurisées** : Utiliser les easing curves qui évoquent la robustesse (cubic-bezier optimisés)
3. **Parallélisme IA** : Les éléments peuvent bouger de façon coordonnée, reflétant une intelligence distribuée

---

## Spécifications Techniques Framer Motion

### 1. Hover Buttons — Effet "Quantum Lock"
```typescript
const quantumHover = {
  initial: {
    scale: 1,
    boxShadow: "0 0 0px rgba(0, 255, 157, 0)"
  },
  hover: {
    scale: 1.02,
    boxShadow: "0 0 20px rgba(0, 255, 157, 0.4)",
    transition: {
      duration: 0.2,
      ease: [0.25, 0.46, 0.45, 0.94] // easeOutQuart
    }
  },
  tap: {
    scale: 0.98,
    transition: { duration: 0.1 }
  }
}
```

**Couleurs TSN** :
- Primaire : `#00ff9d` (vert quantique)
- Accent : `#0066cc` (bleu cryptographique)
- Danger : `#ff3366` (rouge d'alerte sécuritaire)

### 2. Transitions de Pages — "Consensus Sync"
```typescript
const pageTransition = {
  initial: {
    opacity: 0,
    x: 30,
    filter: "blur(4px)"
  },
  animate: {
    opacity: 1,
    x: 0,
    filter: "blur(0px)",
    transition: {
      duration: 0.6,
      ease: [0.16, 1, 0.3, 1], // easeOutExpo
      staggerChildren: 0.1
    }
  },
  exit: {
    opacity: 0,
    x: -30,
    filter: "blur(4px)",
    transition: { duration: 0.4 }
  }
}
```

**Stagger Pattern** : Les éléments apparaissent de haut en bas avec 100ms d'écart, simulant un consensus distribué qui se propage.

### 3. Hero Section Parallax — "Cryptographic Depth"
```typescript
const cryptoParallax = {
  background: {
    y: [0, -50],
    transition: {
      duration: 20,
      repeat: Infinity,
      repeatType: "reverse",
      ease: "linear"
    }
  },
  midground: {
    y: [0, -25],
    transition: {
      duration: 15,
      repeat: Infinity,
      repeatType: "reverse",
      ease: "linear"
    }
  },
  foreground: {
    y: [0, -10],
    transition: {
      duration: 10,
      repeat: Infinity,
      repeatType: "reverse",
      ease: "linear"
    }
  }
}
```

**Éléments Parallax** :
- **Background** : Motifs géométriques abstraits (références aux réseaux cryptographiques)
- **Midground** : Particules flottantes (simulation de proof-of-work distribué)
- **Foreground** : Contenu principal (wallet interface, CTA buttons)

---

## Micro-Animations Signature TSN

### Loading States — "Proof Generation"
```typescript
const proofLoading = {
  animate: {
    rotate: 360,
    transition: {
      duration: 2,
      repeat: Infinity,
      ease: "linear"
    }
  }
}
```

### Success States — "Block Validated"
```typescript
const blockValidated = {
  initial: { scale: 0.8, opacity: 0 },
  animate: {
    scale: [0.8, 1.1, 1],
    opacity: 1,
    transition: {
      duration: 0.5,
      times: [0, 0.6, 1],
      ease: [0.25, 0.46, 0.45, 0.94]
    }
  }
}
```

### Error States — "Quantum Decoherence"
```typescript
const quantumError = {
  animate: {
    x: [-4, 4, -4, 4, 0],
    transition: {
      duration: 0.4,
      ease: "easeInOut"
    }
  }
}
```

---

## Implémentation Technique

### Structure Recommandée
```
wallet/src/
├── animations/
│   ├── variants.ts     // Toutes les variants Framer Motion
│   ├── transitions.ts  // Configurations de timing
│   └── hooks.ts       // Custom hooks d'animation
├── components/
│   ├── ui/            // Composants avec animations intégrées
│   └── layout/        // Layout components avec parallax
```

### Performance Guidelines
- **GPU Acceleration** : Utiliser `transform` et `opacity` prioritairement
- **Batch Animations** : Grouper les animations simultanées avec `layoutGroup`
- **Reduce Motion** : Respecter `prefers-reduced-motion` pour l'accessibilité

### Code Example — Button Component
```typescript
import { motion } from 'framer-motion'
import { quantumHover } from '../animations/variants'

export const TSNButton = ({ children, variant = 'primary' }) => {
  return (
    <motion.button
      variants={quantumHover}
      initial="initial"
      whileHover="hover"
      whileTap="tap"
      className={`tsn-button tsn-button--${variant}`}
    >
      {children}
    </motion.button>
  )
}
```

---

## Next Steps pour Herald

1. **Setup Animation System** : Créer la structure `/animations/` dans `/wallet/src/`
2. **Implement Button Hovers** : Commencer par les boutons CTA de la hero section
3. **Page Transitions** : Intégrer avec React Router pour les transitions entre wallet/explorer/settings
4. **Parallax Hero** : Utiliser `useScroll` de Framer Motion pour le parallax basé sur le scroll
5. **Testing** : Vérifier les performances sur mobile et respecter les préférences d'accessibilité

**Timing Estimate** : 2-3 sprints pour l'implémentation complète avec tests et optimisations.

---

*Guide créé par Zoe.K — Brand & Communications Manager, Trust Stack Network*
*Version 1.0 — Mars 2026*