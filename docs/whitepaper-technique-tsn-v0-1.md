# Whitepaper Technique TSN v0.1
## Table des matières
1. [Introduction](#introduction)
2. [Architecture Globale](#architecture-globale)
3. [Cryptographie Post-Quantique](#cryptographie-post-quantique)
    * [SLH-DSA](#slh-dsa)
    * [Halo2](#halo2)
    * [Poseidon2](#poseidon2)
4. [Consensus et Réseau P2P](#consensus-et-réseau-p2p)
5. [MIK et Sécurité](#mik-et-sécurité)
6. [Références et Specs](#références-et-specs)

## Introduction
Le Trust Stack Network (TSN) est une blockchain post-quantique conçue pour offrir une sécurité et une évolvabilité exceptionnelles. Ce whitepaper technique présente les éléments clés de l'architecture TSN, y compris les choix cryptographiques, le consensus et le réseau peer-to-peer (P2P).

## Architecture Globale
L'architecture TSN est divisée en plusieurs couches :
```mermaid
graph LR
    A[Application] -->|utilise|> B[API/RPC]
    B -->|communique avec|> C[Network P2P]
    C -->|stocke les données|> D[Storage]
    D -->|utilise pour le consensus|> E[Consensus]
    E -->|sécurisé par|> F[Cryptographie]
Chacune de ces couches est conçue pour être modulaire et extensible, permettant ainsi une évolution continue du réseau.

## Cryptographie Post-Quantique
TSN utilise une variété de primitives cryptographiques post-quantiques pour assurer la sécurité des transactions et des données.

### SLH-DSA
Le SLH-DSA (Signature Scheme with Large Hash) est utilisé pour les signatures numériques. Il offre une sécurité contre les attaques quantiques et classiques.

### Halo2
Halo2 est un système de preuve à connaissance nulle (ZKP) qui permet aux utilisateurs de prouver la validité d'une transaction sans révéler les détails de la transaction.

### Poseidon2
Poseidon2 est un hachage cryptographique conçu pour être résistant aux attaques quantiques. Il est utilisé pour la construction d'arbres de Merkle et pour hacher les transactions.

## Consensus et Réseau P2P
TSN utilise un algorithme de consensus de type Proof of Work (PoW) pour valider les transactions et créer de nouveaux blocs. Le réseau P2P est utilisé pour la communication entre les nœuds du réseau.

## MIK et Sécurité
Le MIK (Merkle Interval Key) est utilisé pour assurer la sécurité des transactions et des données. Il permet de vérifier l'intégrité des données sans avoir à les télécharger entièrement.

## Références et Specs
Pour plus d'informations, veuillez consulter les specs suivantes :
- [TSN-0001: Architecture Globale](../specs/tsn-0001.md)
- [TSN-0002: Cryptographie Post-Quantique](../specs/tsn-0002.md)
- [TSN-0003: Consensus et Réseau P2P](../specs/tsn-0003.md)
Ce whitepaper technique offre une vue d'ensemble complète de l'architecture TSN et de ses composants clés. Il est destiné aux développeurs et aux chercheurs intéressés par les détails techniques de la blockchain TSN.