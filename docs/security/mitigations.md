# Guide des Mitigations Cryptographiques

## 1. Comparisons Constant-Time

**Problème**: `if secret == user_input` fuite la position du premier byte différent.

**Solution**: Utiliser `subtle::ConstantTimeEq`


## 2. Gestion des Nonces

**Règles**:
- AES-GCM: Nonce jamais réutilisé avec la même clé
- ChaCha20: Compteur 32-bit, ne pas dépasser 2^32 blocs
- Génération: Counter monotone ou RNG cryptographique (96-bit pour GCM)

**Pattern sécurisé**:

## 3. Dérivation de Clés

**Exigences**:
- Argon2id pour mots de passe (memory-hard)
- HKDF pour clés existantes (extract-then-expand)
- Jamais SHA-256 direct sur password

## 4. Zeroization

**Obligatoire pour**:
- Clés privées éphémères
- Matériel de dérivation
- Clés de session


## 5. Validation de Certificats

- Vérifier chaine complète jusqu'à trust anchor
- Vérifier expiration et revocation (OCSP)
- Pinning pour applications mobiles