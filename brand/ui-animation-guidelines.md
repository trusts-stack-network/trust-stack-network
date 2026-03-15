# TSN UI Animation Guidelines
## Principes d'animation pour Trust Stack Network

### Philosophie de marque
Trust Stack Network n'est pas juste une blockchain — c'est une **déclaration de confiance dans l'avenir post-quantique**. Nos animations UI doivent refléter cette vision : précises, fluides, et inspirant la confiance sans être ostentatoires.

### 🎯 Objectifs des animations TSN

**Crédibilité technique** : Chaque mouvement doit suggérer la précision d'un système cryptographique robuste
**Accessibilité** : Rendre la complexité post-quantique approchable visuellement
**Performance** : Des animations fluides qui prouvent que notre tech est optimisée
**Différenciation** : Se démarquer des autres projets blockchain par une identité visuelle unique

---

## 🚀 Animations prioritaires à implémenter

### 1. Hover Effects - Buttons
**Concept** : "Quantum State Transition"
- **Durée** : 200ms (réactivité instantanée)
- **Ease** : `cubic-bezier(0.4, 0, 0.2, 1)` (Material Design)
- **Effet** : Légère élévation + changement de couleur subtil
- **Message de marque** : Chaque interaction est immédiate et prévisible, comme notre cryptographie

```css
/* Exemple technique pour Herald */
.tsn-button {
  transition: all 200ms cubic-bezier(0.4, 0, 0.2, 1);
  transform: translateY(0);
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.tsn-button:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 8px rgba(0,0,0,0.15);
}
```

### 2. Page Transitions
**Concept** : "Blockchain Block Progression"
- **Durée** : 300ms (assez rapide pour maintenir l'engagement)
- **Effet** : Slide horizontal avec fade subtil
- **Message de marque** : Navigation logique et séquentielle, comme l'ajout de blocs dans une chaîne

```jsx
// Framer Motion example pour Herald
const pageVariants = {
  initial: { opacity: 0, x: 20 },
  in: { opacity: 1, x: 0 },
  out: { opacity: 0, x: -20 }
}

const pageTransition = {
  type: 'tween',
  ease: 'anticipate',
  duration: 0.3
}
```

### 3. Hero Section Parallax
**Concept** : "Quantum Depth"
- **Effet** : Parallax multi-couches avec les éléments crypto qui se déplacent à des vitesses différentes
- **Subtilité** : Mouvement détectable mais pas distrayant
- **Message de marque** : Profondeur technologique — il y a plusieurs couches de sécurité dans TSN

---

## 🎨 Palette d'animation TSN

### Couleurs en mouvement
- **Primary** : `#2563EB` (TSN Blue) - pour les éléments interactifs
- **Accent** : `#10B981` (Success Green) - pour les confirmations/validations
- **Warning** : `#F59E0B` (Quantum Gold) - pour les alertes importantes
- **Neutral** : `#6B7280` (Subtle Gray) - pour les états de repos

### Timing de marque
- **Instantané** : 100ms (feedback micro-interactions)
- **Rapide** : 200ms (boutons, hovers)
- **Modéré** : 300ms (transitions de page)
- **Délibéré** : 500ms (révélations importantes, modals)

---

## 📱 Adaptation mobile

Les animations TSN doivent respecter `prefers-reduced-motion` et être optimisées pour les performances mobiles :

```css
@media (prefers-reduced-motion: reduce) {
  .tsn-animated {
    transition-duration: 0ms !important;
  }
}
```

---

## 🧪 Tests utilisateurs

**Métriques à surveiller :**
- Temps de première interaction (doit rester < 100ms)
- Fluidité perçue (60fps constant)
- Compréhension intuitive des interactions

**Message final :** Chaque animation doit renforcer la confiance de l'utilisateur dans la robustesse technique de TSN. Si une animation ne sert pas cet objectif, elle doit être retravaillée ou supprimée.

---

*Guidelines v1.0 - Mars 2026*
*Prochaine révision après feedback Herald + tests utilisateurs*