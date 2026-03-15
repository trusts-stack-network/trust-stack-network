# TSN Wallet UI 2.0 – Design System Post-Quantique

## Palette dynamique (thème clair ↔ sombre auto)

| Token | Clair | Sombre | Usage |
|-------|-------|--------|-------|
| `--tsn-primary` | `#00F5FF` (cyan laser) | `#00C7FF` | accents, CTAs |
| `--tsn-secondary` | `#7B61FF` (violet qubit) | `#996DFF` | fonds, dégradés |
| `--tsn-glass` | `rgba(255,255,255,0.08)` | `rgba(0,0,0,0.12)` | glassmorphism |
| `--tsn-glow` | `0 0 12px #00F5FF44` | `0 0 16px #00C7FF66` | halo post-quantique |

## Effets visuels

1. **Glassmorphism**  
   `backdrop-filter: blur(20px) saturate(180%);`  
   Coins arrondis 12 px + bordure 1 px `rgba(255,255,255,0.15)`

2. **Micro-animations**  
   - Bouton : `scale(1.03)` + `box-shadow` élargi 150 ms ease-out  
   - Icônes : rotation 8° sur hover + pulse 1.2 s infinite (état « mining »)  
   - Chiffres : compteur fluide (requestAnimationFrame) pour les soldes

3. **Dégradés animés**  
   `background: linear-gradient(135deg, var(--tsn-primary), var(--tsn-secondary));`  
   `background-size: 200% 200%;`  
   `@keyframes gradientShift { 0 % {background-position:0 % 50 %} 50 % {background-position:100 % 50 %} 100 % {background-position:0 % 50 %} }`

## Typographie

- **Titre** : `Inter Tight 600` 24 px / 32 px  
- **Body** : `Inter 400` 14 px / 20 px  
- **Mono** : `JetBrains Mono 500` 13 px / 17 px (adresses, hashes)

## Icônes

Pack `lucide-react` + custom :  
- Qubit : icône atome avec overlay « PQ »  
- Block : cube 3D isométrique  
- Shield : bouclier + clé quantique (petit éclair)

## Thème auto-détection

```typescript
const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
document.documentElement.setAttribute('data-theme', prefersDark ? 'dark' : 'light');