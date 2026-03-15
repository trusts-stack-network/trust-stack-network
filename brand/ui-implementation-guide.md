# TSN UI Implementation Guide
*Guide Technique pour la Refonte Dynamique*

## Architecture CSS - Nouvelles Variables

### Étendre le fichier `App.css`
```css
:root {
  /* === COULEURS EXISTANTES (conserver) === */
  --accent-blue: #58a6ff;
  --accent-purple: #a371f7;
  --accent-gradient: linear-gradient(135deg, #58a6ff 0%, #a371f7 100%);

  /* === NOUVELLES COULEURS TSN === */
  --quantum-cyan: #00d4ff;
  --quantum-violet: #8b5cf6;
  --quantum-emerald: #10b981;

  /* === NOUVEAUX GRADIENTS === */
  --neural-gradient: linear-gradient(120deg, #58a6ff 0%, #00d4ff 50%, #a371f7 100%);
  --quantum-glow: linear-gradient(45deg, rgba(88, 166, 255, 0.2) 0%, rgba(163, 113, 247, 0.2) 100%);

  /* === ANIMATIONS DYNAMIQUES === */
  --transition-neural: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
  --transition-quantum: all 0.6s cubic-bezier(0.25, 0.46, 0.45, 0.94);

  /* === SHADOWS AVANCÉES === */
  --shadow-quantum: 0 8px 32px rgba(88, 166, 255, 0.3), 0 2px 8px rgba(163, 113, 247, 0.2);
  --shadow-neural: 0 12px 48px rgba(0, 212, 255, 0.15), 0 4px 16px rgba(139, 92, 246, 0.1);
}
```

## Composants Prioritaires à Modifier

### 1. Landing.tsx - Hero Section
```typescript
// Ajouter ces états pour animations
const [neuralActive, setNeuralActive] = useState(false);
const [quantumParticles, setQuantumParticles] = useState<Array<{id: number, x: number, y: number}>>([]);

// Animation neural network au mount
useEffect(() => {
  const timer = setTimeout(() => setNeuralActive(true), 1000);
  return () => clearTimeout(timer);
}, []);
```

### 2. Landing.css - Hero Styles
```css
/* === NOUVEAU HERO DESIGN === */
.hero {
  position: relative;
  text-align: center;
  margin-bottom: 64px;
  overflow: hidden;
}

.hero::before {
  content: '';
  position: absolute;
  top: -50%;
  left: -50%;
  width: 200%;
  height: 200%;
  background: var(--neural-gradient);
  opacity: 0.05;
  animation: neural-pulse 8s ease-in-out infinite;
  pointer-events: none;
}

@keyframes neural-pulse {
  0%, 100% { transform: scale(1) rotate(0deg); opacity: 0.05; }
  50% { transform: scale(1.1) rotate(180deg); opacity: 0.08; }
}

.title {
  font-size: 4rem; /* augmenté de 3.5rem */
  font-weight: 800;
  background: var(--neural-gradient);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  margin-bottom: 16px;
  letter-spacing: -0.03em;
  animation: title-glow 3s ease-in-out infinite;
}

@keyframes title-glow {
  0%, 100% { filter: drop-shadow(0 0 8px rgba(88, 166, 255, 0.3)); }
  50% { filter: drop-shadow(0 0 16px rgba(163, 113, 247, 0.4)); }
}

.subtitle {
  font-size: 1.1rem;
  color: var(--quantum-cyan);
  font-weight: 500;
  margin-top: 12px;
  opacity: 0;
  animation: subtitle-appear 1s ease-out 0.5s forwards;
}

@keyframes subtitle-appear {
  from { opacity: 0; transform: translateY(20px); }
  to { opacity: 0.9; transform: translateY(0); }
}
```

### 3. Demo Cards - Effets Quantiques
```css
/* === DEMO CARDS ÉVOLUÉES === */
.demo-card {
  background: var(--bg-secondary);
  border: 2px solid transparent;
  border-radius: 16px;
  overflow: hidden;
  position: relative;
  transition: var(--transition-quantum);
}

.demo-card::before {
  content: '';
  position: absolute;
  top: -2px; left: -2px; right: -2px; bottom: -2px;
  background: var(--quantum-glow);
  border-radius: 16px;
  opacity: 0;
  transition: var(--transition-neural);
  z-index: -1;
}

.demo-card:hover::before {
  opacity: 1;
  animation: border-flow 2s ease-in-out infinite;
}

@keyframes border-flow {
  0%, 100% { background: linear-gradient(45deg, #58a6ff, #a371f7); }
  50% { background: linear-gradient(45deg, #a371f7, #00d4ff); }
}

.demo-card.quantum-active {
  box-shadow: var(--shadow-quantum);
  transform: translateY(-4px) scale(1.02);
}

/* Particles pour démo ML-DSA */
.quantum-particles {
  position: absolute;
  top: 0; left: 0; right: 0; bottom: 0;
  pointer-events: none;
  overflow: hidden;
}

.quantum-particle {
  position: absolute;
  width: 3px;
  height: 3px;
  background: var(--quantum-cyan);
  border-radius: 50%;
  animation: particle-float 3s ease-in-out infinite;
}

@keyframes particle-float {
  0%, 100% {
    opacity: 0.3;
    transform: translateY(0) scale(0.5);
  }
  50% {
    opacity: 1;
    transform: translateY(-20px) scale(1);
  }
}
```

### 4. Boutons Interactifs
```css
/* === BOUTONS NOUVELLE GÉNÉRATION === */
.demo-button.quantum {
  background: var(--neural-gradient);
  color: white;
  border: none;
  padding: 16px 40px;
  border-radius: 12px;
  font-size: 1.1rem;
  font-weight: 700;
  cursor: pointer;
  transition: var(--transition-quantum);
  position: relative;
  overflow: hidden;
}

.demo-button.quantum::before {
  content: '';
  position: absolute;
  top: 50%; left: 50%;
  width: 0; height: 0;
  background: radial-gradient(circle, rgba(255,255,255,0.3) 0%, transparent 70%);
  transition: var(--transition-neural);
  transform: translate(-50%, -50%);
}

.demo-button.quantum:hover::before {
  width: 200%; height: 200%;
}

.demo-button.quantum:hover {
  transform: translateY(-3px) scale(1.05);
  box-shadow: var(--shadow-neural);
}

.demo-button.quantum.computing {
  animation: button-compute 1.5s ease-in-out infinite;
}

@keyframes button-compute {
  0%, 100% { background: var(--neural-gradient); }
  50% { background: linear-gradient(120deg, #00d4ff 0%, #58a6ff 50%, #8b5cf6 100%); }
}
```

## Animations JavaScript

### 1. Neural Network Background
```typescript
// composants/NeuralBackground.tsx
interface Node {
  id: number;
  x: number;
  y: number;
  vx: number;
  vy: number;
}

const NeuralBackground: React.FC = () => {
  const [nodes, setNodes] = useState<Node[]>([]);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    // Initialiser 20 nœuds
    const initialNodes: Node[] = Array.from({ length: 20 }, (_, i) => ({
      id: i,
      x: Math.random() * window.innerWidth,
      y: Math.random() * window.innerHeight,
      vx: (Math.random() - 0.5) * 0.5,
      vy: (Math.random() - 0.5) * 0.5,
    }));
    setNodes(initialNodes);

    // Animation loop
    const animate = () => {
      setNodes(prev => prev.map(node => ({
        ...node,
        x: (node.x + node.vx + window.innerWidth) % window.innerWidth,
        y: (node.y + node.vy + window.innerHeight) % window.innerHeight,
      })));
    };

    const interval = setInterval(animate, 50);
    return () => clearInterval(interval);
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="neural-background"
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        zIndex: -1,
        opacity: 0.4
      }}
    />
  );
};
```

### 2. Quantum Particles pour ML-DSA Demo
```typescript
// Dans Landing.tsx - fonction pour générer particles
const generateQuantumParticles = () => {
  const particles = Array.from({ length: 8 }, (_, i) => ({
    id: i,
    x: Math.random() * 100,
    y: Math.random() * 100,
    delay: Math.random() * 2
  }));
  setQuantumParticles(particles);

  // Clear après 3 secondes
  setTimeout(() => setQuantumParticles([]), 3000);
};

// Déclencher lors du succès ML-DSA
const onSignatureSuccess = () => {
  generateQuantumParticles();
  setDemoState(prev => ({ ...prev, status: 'success' }));
};
```

## Tests d'Intégration UI

### Checklist de Validation
```typescript
// tests/ui-redesign.test.ts
describe('TSN UI Redesign', () => {
  test('Neural gradient loads correctly', () => {
    const styles = getComputedStyle(document.documentElement);
    expect(styles.getPropertyValue('--neural-gradient')).toBeTruthy();
  });

  test('Hero animation triggers on mount', () => {
    render(<Landing />);
    expect(screen.getByClass('title')).toHaveStyle('animation: title-glow 3s ease-in-out infinite');
  });

  test('Demo card hover effects work', () => {
    render(<Landing />);
    const demoCard = screen.getByTestId('ml-dsa-demo');
    fireEvent.mouseEnter(demoCard);
    expect(demoCard).toHaveClass('demo-card:hover::before');
  });
});
```

## Migration Progressive

### Semaine 1 - Core Styles
1. ✅ Ajouter nouvelles variables CSS
2. ✅ Modifier `.title` et `.hero`
3. ✅ Implémenter hover effects boutons

### Semaine 2 - Animations
1. 🎯 Neural background component
2. 🎯 Quantum particles system
3. 🎯 Demo cards interactions

### Semaine 3 - Polish
1. 🎯 Performance optimizations
2. 🎯 Mobile responsive updates
3. 🎯 A/B testing setup

---

**Objectif** : Landing page redesignée prête pour démo publique d'ici fin mars 2026.

*Chaque changement doit préserver l'excellence technique TSN tout en amplifiant son impact visuel.*