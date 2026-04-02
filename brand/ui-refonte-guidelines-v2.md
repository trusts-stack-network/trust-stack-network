# TSN UI Refonte — Guidelines Brand & Design v2.0

**Demande CEO (06/03)** : Design moderne dynamique avec effets  
**Target** : /opt/tsn/wallet/ (frontend TypeScript/Vite)  
**Status** : Prêt pour implémentation

---

## 🎯 Vision Brand pour la Nouvelle UI

**Trust Stack Network n'est pas une énième blockchain.** C'est la première blockchain post-quantique construite par une équipe IA — une technologie du futur qui protège déjà le présent.

L'interface doit refléter cette dualité :
- **Modernité technologique** sans tomber dans le cyberpunk cliché
- **Confiance et sécurité** sans paraître froide ou intimidante  
- **Innovation IA** assumée avec élégance, pas avec defensivité

---

## 🎨 Palette Couleurs (Post-Quantum Theme)

### Couleurs Primaires
- **Quantum Purple** : `#6C5CE7` (principal CTA, éléments actifs)
- **Deep Space** : `#2D3436` (backgrounds, headers)
- **Neural Blue** : `#0984E3` (liens, infos, accents)

### Couleurs Secondaires  
- **Secure Green** : `#00B894` (validations, succès, confirmations)
- **Warning Amber** : `#FDCB6E` (alertes, états pending)
- **Error Crimson** : `#E17055` (erreurs, rejections)

### Neutres
- **Ghost White** : `#FFEAA7` (backgrounds clairs)
- **Charcoal** : `#636E72` (textes secondaires)  
- **Pure White** : `#FFFFFF` (textes principaux sur dark)

---

## ✨ Effets & Animations (Guidelines)

### Micro-interactions
- **Hover states** : Transition smooth 200ms, légère élévation (2-4px shadow)
- **Button press** : Scale 98% avec haptic feedback mental
- **Loading states** : Pulse subtil, pas de spinners agressifs

### Animations de Page
- **Page transitions** : Slide latéral 300ms ease-out
- **Element entrance** : Fade-in + translateY(-10px) staggered  
- **Data updates** : Highlight background flash 600ms

### Effets Post-Quantum Signature
- **Gradient overlays** subtils sur les cartes importantes
- **Particules flottantes** discrètes en background (CSS particles ou Canvas)
- **Typography weights** dynamiques selon l'importance de l'info

---

## 📱 Composants Signatures TSN

### TrustCard Component
- Border gradient subtil Quantum Purple → Neural Blue
- Shadow douce avec glow au hover  
- Badge "Post-Quantum Secured" toujours visible

### TransactionFlow Component
- Timeline verticale avec checkmarks animés
- États : Pending → Verified → Post-Quantum Signed → Confirmed
- Progress bar avec particules qui "voyagent"

### NetworkStatus Widget  
- Indicateur visuel du consensus network
- "Block height" avec counter animé
- "Quantum-safe connections" avec pulse vert

---

## 🚀 Ton & Voice dans l'UI

### Copy Guidelines
- **Headers** : Confiant et clair ("Your Quantum-Safe Wallet", "Secure Transfer")
- **Descriptions** : Technique mais accessible ("Post-quantum signatures protect against future attacks")  
- **CTAs** : Action-oriented ("Sign with Quantum-Safe Key", "Verify Transaction")
- **Errors** : Helpful, pas dramatique ("Connection failed. Retrying in 3s...")

### Terminologie Approuvée
✅ **Utiliser** : Post-Quantum, Quantum-Safe, Future-Proof, ML-DSA Signature  
❌ **Éviter** : "Unbreakable", "100% secure", "Revolutionary" (trop marketing)

---

## 🔧 Implémentation Technique (pour Dev Team)

### Librairies Recommandées
- **Animations** : Framer Motion (React) ou transition CSS natives
- **Icons** : Lucide React (cohérence avec l'écosystème moderne)
- **Typography** : Inter (lisibilité) + JetBrains Mono (code/addresses)

### Performance Guidelines  
- Animations à 60fps max (prefer CSS transforms)
- Lazy loading pour les composants complexes
- Debounce sur les inputs de recherche (300ms)

### Responsive Breakpoints
- Mobile: 320-768px (priority sur navigation simple)
- Tablet: 768-1024px (sidebar collapsible)  
- Desktop: 1024px+ (full feature set)

---

## 📊 Métriques UX à Tracker

### Performance Interface
- Time to Interactive (TTI) < 3s sur mobile
- Smooth 60fps animations
- Zero layout shifts pendant les transitions

### Engagement Utilisateur  
- Temps moyen dans l'interface
- Taux de complétion des transactions
- Feedback satisfaction post-utilisation

### Adoption Features Post-Quantum
- Utilisation des outils éducatifs intégrés
- Compréhension des indicateurs de sécurité
- Préférence interface vs interfaces traditionnelles

---

## 📋 Checklist Validation Brand

Avant deploy, vérifier que l'UI respecte :
- [ ] Palette couleurs TSN cohérente sur tous les écrans
- [ ] "Post-Quantum" mentionné dans les éléments clés
- [ ] Animations fluides et non agressives
- [ ] Copy technique mais accessible  
- [ ] Responsive sur les 3 breakpoints
- [ ] États de loading/error user-friendly
- [ ] Branding TSN visible mais pas intrusif
- [ ] Tests A/B prêts pour le rollout graduel

---

## 🎬 Phase de Rollout Recommandée

**Semaine 1** : Déploiement équipe interne + core contributors  
**Semaine 2** : Beta testeurs Discord (50 utilisateurs)  
**Semaine 3** : Rollout graduel communauté (25% puis 75%)  
**Semaine 4** : Full deploy + annonces publiques  

---

*Zoe.K — Brand & Communications Manager*  
*Trust Stack Network — Post-Quantum Blockchain for the Real World*