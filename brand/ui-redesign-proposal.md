# TSN Wallet UI Redesign – Post-Quantum Visual Language

## Palette Dynamique (auto-switching light/dark)

### Dark Mode (default)
- Background: `#0A0A0F` (near-black with quantum-blue tint)
- Surface: `rgba(23, 25, 35, 0.75)` (glassmorphic base)
- Primary: `#00F5D4` (TSN Cyan – trust & innovation)
- Secondary: `#9B5DE6` (Quantum Violet – security layer)
- Accent: `#F15BB5` (Neon Pink – micro-interactions)
- Success: `#06FFA5` (Quantum-safe green)
- Error: `#FE4450` (Post-quantum alert red)
- Text: `#E6E6FA` → `#B0B0CC` (accessibility gradient)

### Light Mode (auto-triggered)
- Background: `#F8F9FA` (quantum-white)
- Surface: `rgba(255, 255, 255, 0.85)` (frosted glass)
- Primary: `#00C5B0` (deeper cyan for light contrast)
- All other hues shift ±12% luminance for WCAG-AAA

## Glassmorphism System
```css
.glass-card {
  background: rgba(255, 255, 255, 0.08);
  backdrop-filter: blur(24px) saturate(180%);
  border: 1px solid rgba(0, 245, 212, 0.2);
  box-shadow: 0 8px 32px rgba(0, 245, 212, 0.12);
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}