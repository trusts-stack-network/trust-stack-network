# Animations UI — TSN Experience

> *« La confiance ne s’affiche pas — elle s’incarne. »*

Chez TSN, chaque interaction visuelle doit refléter notre promesse : **sécurité fluide, transparence dynamique, et robustesse post-quantique**.

Nous avons déployé trois animations clés dans l’interface (via Framer Motion), conçues pour **renforcer l’intuition sans sacrifier la précision technique**.

---

## 1. `Hover Buttons` — Feedback immédiat, sans précipitation

```tsx
<motion.button
  whileHover={{ scale: 1.05, boxShadow: "0 8px 24px rgba(0, 238, 255, 0.15)" }}
  whileTap={{ scale: 0.98 }}
  transition={{ type: "spring", stiffness: 400, damping: 17 }}
  className="btn-primary"
>
  Connecter le portefeuille
</motion.button>
<motion.div
  initial={{ opacity: 0, y: 12 }}
  animate={{ opacity: 1, y: 0 }}
  exit={{ opacity: 0, y: -12 }}
  transition={{ duration: 0.4, ease: "easeInOut" }}
>
  <PageContent />
</motion.div>
<motion.div
  style={{ y: useTransform(scrollY, [0, 500], [0, -80]) }}
  className="hero-bg"
>
  <Particles count={24} color="#00EEFF" />
</motion.div>

<motion.h1
  style={{ y: useTransform(scrollY, [0, 300], [0, -40]) }}
  className="hero-title"
>
  La blockchain qui résiste aux ordinateurs quantiques
</motion.h1>