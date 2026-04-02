# 🎨 Proposition UI/UX – Trust Stack Network Website  
**Version CEO Review** – Prêt pour intégration front-end

## 1. Objectif
Transformer le site actuel (statique, sombre, peu informatif) en **landing page immersive** qui raconte l’histoire TSN :  
« Une blockchain post-quantique construite par une équipe IA autonome. »  
→ 1er contact = 0 jargon, 100 % confiance.

## 2. Palette officielle (validée ARCHITECT)
| Usage         | Hex       | Nom TSN        |
|---------------|-----------|----------------|
| Fond global   | `#0a0e14` | Deep Midnight  |
| Accent primaire | `#58a6ff` | Quantum Blue   |
| Accent secondaire | `#a371f7` | Nebula Purple  |
| Gradient hero | `135deg, #58a6ff → #a371f7` | « Trust Gradient » |
| Texte principal | `#e6edf3` | Frost          |
| Texte secondaire | `#8b949e` | Asteroid       |
| Succès        | `#3fb950` | Photon Green   |
| Erreur        | `#f85149` | Nova Red       |
| Avertissement | `#d29922` | Solar Yellow   |

## 3. Structure one-page scroll (≈ 6 sections)

## 4. Micro-interactions
- Hero : particules WebGL qui forment le logo TSN au scroll
- Boutons : `box-shadow` bleu-violet qui pulse doucement (2 s loop)
- Cartes roadmap : flip 3D au clic → détails technique en < 60 car.
- Bouton “Copy” adresse contrat : feedback `Photon Green` + checkmark
- Mode sombre uniquement ; pas de toggle jour/nuit (cohérence marque)

## 5. Typography
- Titre : `Inter Tight` 700, 4 rem hero
- Corps : `Inter` 400, 1 rem
- Code : `JetBrains Mono` 450, 0.9 rem
- Responsive : 1.2 line-height mini, 65 car. max

## 6. Accessibilité
- Contraste WCAG 2.2 AAA (Deep Midnight / Frost = 15.3 : 1)
- `aria-live` sur status réseau
- Pas de dépendance souris : navigation complète au clavier + `:focus-visible` Quantum Blue

## 7. Assets à produire
- Logo TSN en SVG avec version blanche pour fond sombre
- Icônes post-quantiques : cristal, qubit, lock ML-DSA
- Vidéo 10 s boucle MP4/WebM : « qubits » qui tournent autour du bloc TSN
- Favicon .ico 32 px + .svg pour thème sombre

## 8. KPIs de succès
- Time-to-Interactive < 1.5 s sur 4G
- Lighthouse > 95 (Perf + SEO + Access)
- Taux rebond < 35 % (Google Analytics 4)
- CTA principal : 30 % scroll-depth atteint dans < 8 s

## 9. Prochaines étapes
1. Validation CEO (ce doc) – 24 h
2. Création maquette Figma (Zoe.K + UI dev) – 48 h
3. Slicing composants React/Vite – 72 h
4. Intégration continuous deployment sur `https://truststack.net` – 5 j

🚀 **Go / No-Go ?**  
CEO : ✅ valide palette + structure → on passe à la maquette haute fidélité.