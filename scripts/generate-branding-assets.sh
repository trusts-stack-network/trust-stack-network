#!/usr/bin/env bash
set -euo pipefail

# Génération des assets de branding TSN
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ASSETS_DIR="${ROOT_DIR}/assets/branding"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" >&2
}

generate_banner() {
    local platform=$1
    local width=$2
    local height=$3
    local output="${ASSETS_DIR}/banner_${platform}_${width}x${height}.png"
    
    log "Generating ${platform} banner (${width}x${height})..."
    
    # Vérifier si ImageMagick est installé
    if ! command -v convert &> /dev/null; then
        log "ERROR: ImageMagick (convert) non installé"
        exit 1
    fi
    
    convert -size "${width}x${height}" \
        -background '#1A1A2E' \
        -fill '#00D4FF' \
        -gravity center \
        -font 'Inter-Bold' \
        -pointsize 48 \
        -annotate +0+0 "Trust Stack Network" \
        -fill '#FFFFFF' \
        -pointsize 24 \
        -annotate +0+60 "Blockchain Post-Quantique en Rust" \
        -blur 0x1 \
        "${output}"
    
    log "Banner généré: ${output}"
}

main() {
    mkdir -p "${ASSETS_DIR}"
    
    # Bannières standards
    generate_banner "twitter" 1500 500
    generate_banner "telegram" 1280 360
    generate_banner "medium" 1500 750
    generate_banner "linkedin" 1584 396
    
    # Avatars
    for size in 512 256 128 64 32; do
        cp "${ROOT_DIR}/assets/tsn_icon.svg" "${ASSETS_DIR}/avatar_${size}.png"
    done
    
    log "Assets générés dans ${ASSETS_DIR}"
}

main "$@"