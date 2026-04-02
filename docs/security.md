# Sécurité

Le module `crypto` est sensible à plusieurs menaces, notamment :

* Les attaques par timing : les fonctions de cryptographie peuvent être vulnérables aux attaques par timing si elles ne sont pas correctement sécurisées.
* Les fuites de données : les clés privées et les données sensibles doivent être protégées contre les fuites de données.

Pour mitigations ces menaces, nous utilisons :

* Des fonctions de cryptographie sécurisées contre les attaques par timing.
* Des mécanismes de protection des données pour empêcher les fuites de données.

## Menaces et mitigations

| Menace | Mitigation |
| --- | --- |
| Attaques par timing | Fonctions de cryptographie sécurisées contre les attaques par timing |
| Fuites de données | Mécanismes de protection des données pour empêcher les fuites de données |

## Tests de sécurité

Les tests de sécurité sont effectués régulièrement pour garantir que le module `crypto` est sécurisé. Les tests incluent :

* Des tests de propriétés pour les signatures, les preuves et les engagements.
* Des tests de régression pour chaque vulnérabilité.
* Des fuzzers pour les entrées externes.

## Politique de divulgation responsable

Nous suivons une politique de divulgation responsable pour les vulnérabilités de sécurité. Si vous découvrez une vulnérabilité de sécurité, veuillez nous contacter à l'adresse [security@example.com](mailto:security@example.com).