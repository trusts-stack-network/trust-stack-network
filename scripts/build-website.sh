#!/bin/bash
# ===== TSN WEBSITE BUILD SCRIPT =====
# Trust Stack Network - Build automatisé du site web + PDF whitepaper
# Auteur: Yuki.T (Release & DevOps Engineer)

set -euo pipefail

# ===== CONFIGURATION =====
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly BUILD_DIR="${PROJECT_ROOT}/build"
readonly WEBSITE_DIR="${PROJECT_ROOT}/website"
readonly DOCS_DIR="${PROJECT_ROOT}/docs"
readonly OUTPUT_WEBSITE="${BUILD_DIR}/website"
readonly OUTPUT_DOCS="${BUILD_DIR}/docs"

# Couleurs pour les logs
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# ===== FONCTIONS UTILITAIRES =====

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    log_info "Vérification des dépendances..."
    
    local missing_deps=()
    
    # Vérifier pandoc pour le PDF
    if ! command -v pandoc &> /dev/null; then
        missing_deps+=("pandoc")
    fi
    
    # Vérifier wkhtmltopdf pour le PDF
    if ! command -v wkhtmltopdf &> /dev/null; then
        missing_deps+=("wkhtmltopdf")
    fi
    
    # Vérifier python3 pour les scripts
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Dépendances manquantes: ${missing_deps[*]}"
        log_info "Installez avec: sudo apt-get install pandoc wkhtmltopdf python3 python3-pip"
        log_info "Ou utilisez: make website-deps"
        exit 1
    fi
    
    log_success "Toutes les dépendances sont présentes"
}

create_build_dirs() {
    log_info "Création des répertoires de build..."
    mkdir -p "${OUTPUT_WEBSITE}"
    mkdir -p "${OUTPUT_DOCS}"
    log_success "Répertoires créés"
}

build_website() {
    log_info "Build du site web TSN..."
    
    # Copier les fichiers statiques
    cp -r "${WEBSITE_DIR}"/* "${OUTPUT_WEBSITE}/"
    
    # Injecter la version et la date de build
    local version
    version=$(grep '^version = ' "${PROJECT_ROOT}/Cargo.toml" | sed 's/version = "\(.*\)"/\1/')
    local build_date
    build_date=$(date '+%Y-%m-%d %H:%M:%S UTC')
    
    # Remplacer les placeholders dans index.html
    sed -i "s/{{VERSION}}/${version}/g" "${OUTPUT_WEBSITE}/index.html"
    sed -i "s/{{BUILD_DATE}}/${build_date}/g" "${OUTPUT_WEBSITE}/index.html"
    
    # Ajouter le lien vers le whitepaper PDF si il existe
    if [ -f "${OUTPUT_DOCS}/whitepaper_tsn_v0.1.pdf" ]; then
        log_info "Ajout du lien vers le whitepaper PDF..."
        # Injecter le lien PDF dans la section documentation
        local pdf_link='<a href="docs/whitepaper_tsn_v0.1.pdf" class="btn btn-primary" target="_blank">📄 Télécharger le Whitepaper (PDF)</a>'
        sed -i "s|<!-- PDF_WHITEPAPER_LINK -->|${pdf_link}|g" "${OUTPUT_WEBSITE}/index.html"
    fi
    
    log_success "Site web buildé dans ${OUTPUT_WEBSITE}"
}

generate_whitepaper_pdf() {
    log_info "Génération du whitepaper PDF..."
    
    local whitepaper_md="${DOCS_DIR}/whitepaper.md"
    local whitepaper_pdf="${OUTPUT_DOCS}/whitepaper_tsn_v0.1.pdf"
    
    if [ ! -f "${whitepaper_md}" ]; then
        log_warning "Fichier whitepaper.md non trouvé, création d'un template..."
        create_whitepaper_template
    fi
    
    # Générer le PDF avec pandoc
    pandoc "${whitepaper_md}" \
        -o "${whitepaper_pdf}" \
        --pdf-engine=xelatex \
        --variable geometry:margin=2cm \
        --variable fontsize=11pt \
        --variable documentclass=article \
        --variable colorlinks=true \
        --variable linkcolor=blue \
        --variable urlcolor=blue \
        --toc \
        --toc-depth=3 \
        --number-sections \
        --highlight-style=github \
        2>/dev/null || {
            log_warning "Échec de pandoc, tentative avec wkhtmltopdf..."
            
            # Fallback: convertir MD en HTML puis PDF
            local temp_html="${BUILD_DIR}/temp_whitepaper.html"
            pandoc "${whitepaper_md}" -o "${temp_html}" --standalone --css="${WEBSITE_DIR}/style.css"
            wkhtmltopdf "${temp_html}" "${whitepaper_pdf}"
            rm -f "${temp_html}"
        }
    
    if [ -f "${whitepaper_pdf}" ]; then
        local pdf_size
        pdf_size=$(du -h "${whitepaper_pdf}" | cut -f1)
        log_success "Whitepaper PDF généré: ${whitepaper_pdf} (${pdf_size})"
    else
        log_error "Échec de la génération du PDF"
        return 1
    fi
}

create_whitepaper_template() {
    local whitepaper_md="${DOCS_DIR}/whitepaper.md"
    mkdir -p "${DOCS_DIR}"
    
    cat > "${whitepaper_md}" << 'EOF'
---
title: "Trust Stack Network (TSN) - Whitepaper"
subtitle: "Blockchain Post-Quantique avec Preuves à Divulgation Nulle"
author: "Équipe Trust Stack Network"
date: "Version 0.1 - Décembre 2024"
---

# Trust Stack Network (TSN)
## Blockchain Post-Quantique avec Preuves à Divulgation Nulle

### Résumé Exécutif

Trust Stack Network (TSN) est une blockchain de nouvelle génération conçue pour résister aux attaques des ordinateurs quantiques tout en préservant la confidentialité des transactions grâce aux preuves à divulgation nulle (Zero-Knowledge Proofs).

### 1. Introduction

L'avènement de l'informatique quantique représente une menace existentielle pour les cryptosystèmes actuels. TSN anticipe cette révolution en implémentant dès aujourd'hui des algorithmes cryptographiques post-quantiques.

#### 1.1 Problématique

- **Menace quantique** : Les algorithmes RSA et ECDSA seront cassés par les ordinateurs quantiques
- **Confidentialité** : Les blockchains actuelles exposent toutes les transactions publiquement
- **Scalabilité** : Les solutions actuelles ne passent pas à l'échelle

#### 1.2 Solution TSN

TSN résout ces problèmes en combinant :
- **Cryptographie post-quantique** : FIPS204 ML-DSA-65 pour les signatures
- **Preuves ZK quantum-safe** : Plonky2 STARKs pour la confidentialité
- **Architecture optimisée** : Consensus PoW avec ajustement de difficulté

### 2. Architecture Technique

#### 2.1 Couche Cryptographique

**Signatures Post-Quantiques :**
- FIPS204 ML-DSA-65 (Module-Lattice-Based Digital Signature Algorithm)
- Résistant aux attaques quantiques (algorithme de Shor)
- Taille de signature : ~3KB (vs ~64B pour ECDSA)

**Preuves à Divulgation Nulle :**
- Plonky2 STARKs pour la confidentialité quantum-safe
- Groth16 BN254 pour la compatibilité legacy
- Fonction de hachage Poseidon2 optimisée

**Chiffrement :**
- ChaCha20Poly1305 pour le chiffrement symétrique
- Échange de clés post-quantique en développement

#### 2.2 Couche Consensus

**Proof of Work (PoW) :**
- Algorithme de hachage : SHA-256 (compatible Bitcoin)
- Ajustement de difficulté : toutes les 2016 blocs
- Temps de bloc cible : 10 minutes

**Validation des Transactions :**
- Vérification des signatures ML-DSA-65
- Validation des preuves ZK
- Contrôle des double-dépenses

#### 2.3 Couche Réseau

**Protocole P2P :**
- Discovery automatique des nœuds
- Synchronisation des blocs
- Propagation des transactions

**API REST :**
- Interface HTTP pour les wallets
- Endpoints pour l'explorateur de blocs
- Métriques de performance

### 3. Implémentation

#### 3.1 Technologies Utilisées

- **Langage** : Rust (sécurité mémoire, performance)
- **Runtime** : Tokio (programmation asynchrone)
- **Stockage** : Sled (base de données embarquée)
- **Réseau** : Axum (serveur HTTP haute performance)

#### 3.2 Structure du Code

```
src/
├── core/           # Blockchain, blocs, transactions
├── crypto/         # Cryptographie post-quantique
├── network/        # P2P, API, synchronisation
├── consensus/      # Proof of Work, difficulté
├── storage/        # Persistance des données
├── explorer/       # Explorateur de blocs
└── wallet/         # Wallet de base
```

#### 3.3 Métriques de Performance

- **Débit** : ~7 transactions/seconde (Bitcoin-like)
- **Latence** : 10 minutes par bloc
- **Taille des blocs** : 1MB maximum
- **Taille des signatures** : ~3KB (ML-DSA-65)

### 4. Sécurité

#### 4.1 Modèle de Menace

TSN est conçu pour résister à :
- Attaques quantiques (algorithme de Shor, Grover)
- Attaques classiques (51%, double-dépense)
- Attaques sur la confidentialité (analyse de trafic)

#### 4.2 Audit de Sécurité

- Audit automatisé avec `cargo audit`
- Vérification des dépendances avec `cargo deny`
- Tests de fuzzing en développement

### 5. Roadmap

#### Phase 1 (Q1 2025) - MVP
- [x] Blockchain de base avec PoW
- [x] Signatures post-quantiques ML-DSA-65
- [x] API REST et explorateur
- [ ] Wallet complet
- [ ] Tests de charge

#### Phase 2 (Q2 2025) - Confidentialité
- [ ] Preuves ZK Plonky2 intégrées
- [ ] Transactions confidentielles
- [ ] Audit de sécurité externe

#### Phase 3 (Q3 2025) - Scalabilité
- [ ] Optimisations de performance
- [ ] Sharding expérimental
- [ ] Mainnet beta

#### Phase 4 (Q4 2025) - Production
- [ ] Mainnet production
- [ ] Écosystème DApps
- [ ] Partenariats institutionnels

### 6. Économie du Token

#### 6.1 Tokenomics

- **Nom** : TSN Token
- **Supply total** : 21 millions (comme Bitcoin)
- **Récompense de bloc** : 50 TSN (divisée par 2 tous les 210,000 blocs)
- **Frais de transaction** : Variables selon la congestion

#### 6.2 Distribution

- **Mining** : 80% (16.8M TSN)
- **Équipe** : 10% (2.1M TSN, vesting 4 ans)
- **Réserve** : 10% (2.1M TSN, développement)

### 7. Conclusion

Trust Stack Network représente l'évolution naturelle de la blockchain vers l'ère post-quantique. En combinant sécurité quantique, confidentialité et performance, TSN pose les bases d'un écosystème financier décentralisé résistant aux futures menaces technologiques.

L'implémentation en Rust garantit la sécurité mémoire et les performances nécessaires pour une blockchain de production. L'architecture modulaire permet une évolution continue vers de nouveaux algorithmes cryptographiques au fur et à mesure de leur standardisation.

---

**Contact :**
- Site web : https://truststacknetwork.com
- GitHub : https://github.com/trust-stack-network/tsn
- Email : contact@truststacknetwork.com

**Disclaimer :** Ce document est en version préliminaire et peut évoluer. TSN est un projet expérimental en développement actif.
EOF

    log_info "Template whitepaper créé dans ${whitepaper_md}"
}

serve_website() {
    log_info "Démarrage du serveur local..."
    
    cd "${OUTPUT_WEBSITE}"
    
    # Essayer python3 d'abord, puis python
    if command -v python3 &> /dev/null; then
        log_info "Serveur démarré sur http://localhost:8000"
        log_info "Appuyez sur Ctrl+C pour arrêter"
        python3 -m http.server 8000
    elif command -v python &> /dev/null; then
        log_info "Serveur démarré sur http://localhost:8000"
        log_info "Appuyez sur Ctrl+C pour arrêter"
        python -m http.server 8000
    else
        log_error "Python non trouvé, impossible de démarrer le serveur"
        log_info "Fichiers disponibles dans: ${OUTPUT_WEBSITE}"
        return 1
    fi
}

clean_build() {
    log_info "Nettoyage des fichiers de build..."
    rm -rf "${BUILD_DIR}"
    log_success "Build nettoyé"
}

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Build automatisé du site web Trust Stack Network + PDF whitepaper

OPTIONS:
    --website-only    Builder uniquement le site web (sans PDF)
    --pdf-only        Générer uniquement le PDF whitepaper
    --serve           Builder et servir localement sur http://localhost:8000
    --clean           Nettoyer avant de builder
    --help, -h        Afficher cette aide

EXEMPLES:
    $0                      # Build complet (site + PDF)
    $0 --serve              # Build + serveur local
    $0 --clean --serve      # Nettoyage + build + serveur
    $0 --website-only       # Site web seulement
    $0 --pdf-only           # PDF seulement

DÉPENDANCES:
    pandoc, wkhtmltopdf, python3
    Installation: sudo apt-get install pandoc wkhtmltopdf python3
    Ou: make website-deps

EOF
}

# ===== MAIN =====

main() {
    local build_website=true
    local build_pdf=true
    local serve=false
    local clean=false
    
    # Parser les arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --website-only)
                build_pdf=false
                shift
                ;;
            --pdf-only)
                build_website=false
                shift
                ;;
            --serve)
                serve=true
                shift
                ;;
            --clean)
                clean=true
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                log_error "Option inconnue: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    log_info "=== TSN Website Build Script ==="
    log_info "Build website: ${build_website}"
    log_info "Build PDF: ${build_pdf}"
    log_info "Serve: ${serve}"
    log_info "Clean: ${clean}"
    echo
    
    # Nettoyage si demandé
    if [ "$clean" = true ]; then
        clean_build
    fi
    
    # Vérifier les dépendances
    check_dependencies
    
    # Créer les répertoires
    create_build_dirs
    
    # Build du site web
    if [ "$build_website" = true ]; then
        build_website
    fi
    
    # Génération du PDF
    if [ "$build_pdf" = true ]; then
        generate_whitepaper_pdf
    fi
    
    # Servir localement si demandé
    if [ "$serve" = true ]; then
        if [ "$build_website" = true ]; then
            serve_website
        else
            log_error "Impossible de servir : site web non buildé"
            exit 1
        fi
    fi
    
    log_success "=== Build terminé avec succès ==="
    
    if [ "$build_website" = true ]; then
        log_info "Site web: ${OUTPUT_WEBSITE}/index.html"
    fi
    
    if [ "$build_pdf" = true ] && [ -f "${OUTPUT_DOCS}/whitepaper_tsn_v0.1.pdf" ]; then
        log_info "Whitepaper PDF: ${OUTPUT_DOCS}/whitepaper_tsn_v0.1.pdf"
    fi
}

# Exécuter le script
main "$@"