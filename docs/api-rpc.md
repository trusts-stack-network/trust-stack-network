# API RPC du Noeud TSN
## Table des matières
1. [Introduction](#introduction)
2. [Endpoints](#endpoints)
    * [1. `get_block`](#1-get_block)
    * [2. `get_transaction`](#2-get_transaction)
    * [3. `send_transaction`](#3-send_transaction)
    * [4. `get_account`](#4-get_account)
    * [5. `get_network_info`](#5-get_network_info)
3. [Exemples d'utilisation](#exemples-dutilisation)
4. [Références](#références)

## Introduction
L'API RPC du noeud TSN permet aux utilisateurs d'interagir avec le réseau TSN de manière programmatique. Cette documentation présente les différentes méthodes JSON-RPC exposées par le noeud TSN, ainsi que leurs paramètres, retours et exemples d'utilisation.

## Endpoints
### 1. `get_block`
* **Description** : Récupère un bloc spécifique du réseau TSN.
* **Paramètres** :
    + `block_hash` (string) : Le hash du bloc à récupérer.
    + `block_number` (integer) : Le numéro du bloc à récupérer.
* **Retour** :
    + `block` (object) : Le bloc récupéré.
* **Exemple** :
```bash
curl -X POST \
  http://localhost:8080/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"get_block","params":["0x1234567890abcdef"],"id":1}'

### 2. `get_transaction`
* **Description** : Récupère une transaction spécifique du réseau TSN.
* **Paramètres** :
    + `transaction_hash` (string) : Le hash de la transaction à récupérer.
* **Retour** :
    + `transaction` (object) : La transaction récupérée.
* **Exemple** :
curl -X POST \
  http://localhost:8080/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"get_transaction","params":["0x1234567890abcdef"],"id":1}'

### 3. `send_transaction`
* **Description** : Envoie une transaction sur le réseau TSN.
* **Paramètres** :
    + `transaction` (object) : La transaction à envoyer.
* **Retour** :
    + `transaction_hash` (string) : Le hash de la transaction envoyée.
* **Exemple** :
curl -X POST \
  http://localhost:8080/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"send_transaction","params":[{"from":"0x1234567890abcdef","to":"0x1234567890abcdef","value":10}],"id":1}'

### 4. `get_account`
* **Description** : Récupère les informations d'un compte spécifique du réseau TSN.
* **Paramètres** :
    + `account_address` (string) : L'adresse du compte à récupérer.
* **Retour** :
    + `account` (object) : Le compte récupéré.
* **Exemple** :
curl -X POST \
  http://localhost:8080/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"get_account","params":["0x1234567890abcdef"],"id":1}'

### 5. `get_network_info`
* **Description** : Récupère les informations du réseau TSN.
* **Paramètres** : Aucun
* **Retour** :
    + `network_info` (object) : Les informations du réseau TSN.
* **Exemple** :
curl -X POST \
  http://localhost:8080/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"get_network_info","id":1}'

## Exemples d'utilisation
Les exemples ci-dessus montrent comment utiliser les méthodes JSON-RPC pour interagir avec le réseau TSN. Il est possible de les utiliser pour créer des applications personnalisées qui interagissent avec le réseau TSN.

## Références
* [TSN-001: Spécification du protocole de communication](specs/TSN-001.md)
* [TSN-002: Spécification du format de données](specs/TSN-002.md)