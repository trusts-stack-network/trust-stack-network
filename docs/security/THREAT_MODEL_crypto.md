# Threat Model – Module crypto de TSN
Dernière révision : 2024-06-xx

## Actifs protégés
- Clés privées utilisateur et validateur (seed 32 bytes)
- Signature post-quantique (FIPS-204 ML-DSA-65)
- Preuves ZK (Plonky2 STARK, Groth16 BN254 legacy)
- Commitments et nullifiers (Poseidon2)
- Données sensibles en mémoire (secret keys, randomness)

## Modèle d’adversaire
- Capacité réseau : peut observer tout traffic P2P / RPC
- Capacité CPU : peut exécuter du code sur la même machine (cache-timing)
- Objectif : extraction de clé, forgery de signature, violation d’anonymat
- Pas d’accès physique (cold-storage) mais accès aux APIs publiques

## Surfaces d’attaque
1. Dérivation de clé depuis seed (brut-force + timing)
2. Signature / vérification ML-DSA-65 (side-channel sur secret vector « s »)
3. Comparaison de hash/commitment non constant-time
4. Merkle proof verification (path length forgery)
5. Désérialisation de clés depuis réseau (panic via unwrap)
6. RNG : faute d’initialisation => clés prévisibles
7. Nullifier collision : deux notes différentes produisent même nullifier

## STRIDE
- Spoofing : clés usurpées si RNG faible
- Tampering : bloc invalide accepté si check de root non constant-time
- Repudiation : pas de non-répudiation si signature non auditée
- Information disclosure : timing sur comparaison de root
- DoS : panic sur slice[index] dans merkle_proof.verify()
- Elevation : double-spend possible si nullifier pas vérifié avant confirmation

## Mitigations implémentées
- ChaCha20Poly1305 pour le stockage au repos (AEAD)
- Constant-time comparison pour toutes les primitives > 32 bytes
- Zeroize automatique sur Drop des clés
- Fuzzing corpus pour chaque parser externe
- Proptest : vérification des invariants de transition de state