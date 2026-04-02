# Audit des Primitives Cryptographiques

## Évaluation des Algorithmes

### AEAD: AES-256-GCM & ChaCha20-Poly1305
**Status**: ACCEPTABLE avec réserves  
**Risques**:
- AES-GCM: Fragile en cas de nonce reuse (catastrophique)
- Limite ~64GB par clé/nonce pour AES-GCM (2^32 blocks)
- ChaCha20: Plus robuste au nonce reuse (seulement contenu révélé, pas clé)

**Recommandations**:
1. Préférer ChaCha20-Poly1305 pour nouveaux développements
2. Implémenter counter thread-safe pour nonces
3. Refuser encryption si nonce déjà utilisé (stateful)

### KDF: Argon2id / HKDF-SHA256
**Status**: ACCEPTABLE  
**Paramètres**:
- Argon2id: m=65536, t=3, p=4 (OWASP recommandation actuelle)
- HKDF: Salt obligatoire, info string unique par contexte

**Vulnérabilités potentielles**:
- Paramètres trop faibles pour passwords (DoS vs Security tradeoff)
- Salt prévisible réduit la sécurité

### Hashing: SHA-3-256 / BLAKE3
**Status**: ACCEPTABLE  
**Notes**:
- SHA-3 résistant aux length extension (pas besoin de HMAC)
- BLAKE3 plus rapide mais moins audité que BLAKE2b

### RNG: ChaCha20Rng (seeded from getrandom)
**Status**: ACCEPTABLE  
**Exigences**:
- Reseeding périodique obligatoire
- Pas de fork-safety issue (vérifier `rand::rngs::OsRng`)

## Anti-patterns Détectés à Proscrire

1. **ECB Mode**: Jamais utilisé, même pour testing
2. **CBC sans HMAC**: Vulnérable aux padding oracles
3. **MD5/SHA1**: Collision trouvées, rejeté explicitement
4. **Static IV**: Même pour testing, utiliser IV aléatoires
5. **Key derivation via simple hash**: Toujours utiliser PBKDF2/Argon2