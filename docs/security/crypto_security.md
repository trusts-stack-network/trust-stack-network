# Sécurité des primitives cryptographiques

## Menaces

* Timing attacks : les attaques par temps de calcul peuvent permettre à un attaquant de récupérer des informations sensibles sur les clés privées.
* Side channels : les canaux latéraux peuvent permettre à un attaquant de récupérer des informations sensibles sur les clés privées.
* Mauvais usage des primitives : un mauvais usage des primitives cryptographiques peut permettre à un attaquant d'exploiter des vulnérabilités.

## Mitigations

* Utilisation de primitives cryptographiques sécurisées : nous utilisons des primitives cryptographiques éprouvées et sécurisées telles que les signatures ED25519 et les hachages SHA-256.
* Protection contre les timing attacks : nous utilisons des mécanismes de protection contre les timing attacks tels que les comparaisons constant-time.
* Protection contre les side channels : nous utilisons des mécanismes de protection contre les side channels tels que les masques de sécurité.