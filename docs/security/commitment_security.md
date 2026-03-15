# Sécurité des Commitments

## Introduction

Les commitments sont une partie essentielle de la cryptographie utilisée dans notre projet. Ils permettent de garantir l'intégrité et la confidentialité des données. Dans ce document, nous allons présenter les menaces et les mitigations liées aux commitments.

## Menaces

* Attaques de timing : les attaques de timing peuvent permettre à un attaquant de déduire des informations sur les données sensibles en analysant le temps mis par les opérations cryptographiques.
* Overflow : les overflow peuvent permettre à un attaquant de corrompre les données ou de créer des conditions de concurrence.
* Utilisation incorrecte de zeroize : l'utilisation incorrecte de zeroize peut permettre à un attaquant de récupérer des informations sensibles.

## Mitigations

* Utilisation de comparaisons constantes pour éviter les attaques de timing.
* Utilisation de calculs sécurisés pour éviter les overflow.
* Utilisation correcte de zeroize pour les secrets.

## Tests et Fuzzers

* Les tests de propriété sont utilisés pour vérifier que les commitments sont binding.
* Les tests de régression sont utilisés pour vérifier que les overflow sont gérés correctement et que les secrets sont correctement zeroisés.
* Les fuzzers sont utilisés pour tester les entrées externes et garantir que les commitments sont robustes.