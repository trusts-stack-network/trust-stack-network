# Modèle de menaces - Module cryptographique TSN

## Vue d'ensemble
Ce document décrit le modèle de menaces pour le module cryptographique de Trust Stack Network.

## Acteurs
- **Utilisateur légitime**: Possède des clés valides
- **Attaquant passif**: Peut observer le traffic
- **Attaquant actif**: Peut modifier messages et timing
- **Attaquant physique**: Accès limité à l'appareil

## Surfaces d'attaque

### 1. Timing side channels
**Menace**: Attaquant mesure le temps d'exécution pour extraire des clés
**Impact**: Compromission complète des clés privées
**Mitigation**: 
  - Comparaisons constant-time
  - Blindage des opérations critiques

### 2. Invalid curve attacks
**Menace**: Envoi de points non valides sur la courbe
**Impact**: Clés privées compromises
**Mitigation**:
  - Validation rigoureuse des points
  - Rejet des points à l'infini

### 3. Entropy failures
**Menace**: RNG prévisible
**Impact**: Clés devinables
**Mitigation**:
  - RNG système + mélangeur cryptographique
  - Tests d'entropie continus

## Propriétés de sécurité requises

1. **Confidentialité**: Clés privées jamais exposées
2. **Intégrité**: Aucune modification non détectée
3. **Authenticité**: Signatures vérifiables
4. **Non-répudiation**: Signature = preuve
5. **Résistance post-quantique**: Sécurité même contre QC

## Vecteurs d'attaque spécifiques

### Attaques sur ML-DSA-65
- **Key reuse**: Jamais signer deux messages différents
- **Side channel**: Timing sur la génération de nonce
- **Fault injection**: Défaillance lors de la signature

### Attaques sur Plonky2
- **Invalid proofs**: Vérification incomplète
- **Soundness gap**: Paramètres mal configurés
- **Side channel**: Timing sur FFT

## Checklist de sécurité
- [ ] Pas de comparaisons directes sur des secrets
- [ ] Validation des entrées cryptographiques
- [ ] Nettoyage de la mémoire sensible
- [ ] Protection contre les attaques par faute
- [ ] Tests d'intégrité continus