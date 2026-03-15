#!/bin/bash
# Script d'audit des unwraps/expects/panics pour TSN
# Usage: ./scripts/audit_unwraps.sh [--strict]

set -e

STRICT_MODE=false
if [ "$1" == "--strict" ]; then
    STRICT_MODE=true
fi

echo "=========================================="
echo "TSN Unwrap/Panic Audit Script"
echo "=========================================="
echo ""

# Couleurs pour la sortie
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Compteurs
TOTAL_UNWRAPS=0
TOTAL_EXPECTS=0
TOTAL_PANICS=0
CRITICAL_FILES=0

# Fonction pour compter les occurrences
count_occurrences() {
    local pattern=$1
    local path=$2
    local count=$(grep -r "$pattern" "$path" --include="*.rs" 2>/dev/null | wc -l)
    echo $count
}

# Fonction pour lister les occurrences avec contexte
list_occurrences() {
    local pattern=$1
    local path=$2
    local label=$3
    local color=$4
    
    echo -e "${color}=== $label ===${NC}"
    grep -rn "$pattern" "$path" --include="*.rs" 2>/dev/null | while read -r line; do
        # Exclure les lignes de tests et les commentaires
        if ! echo "$line" | grep -q "//.*unwrap\|#\[cfg(test)\]"; then
            echo "  $line"
        fi
    done
    echo ""
}

echo "Scanning codebase for unwraps/expects/panics..."
echo ""

# Modules critiques à scanner
CRITICAL_MODULES=("src/core" "src/consensus" "src/crypto" "src/network")

echo "Critical modules analysis:"
echo "--------------------------"

for module in "${CRITICAL_MODULES[@]}"; do
    if [ -d "$module" ]; then
        unwraps=$(count_occurrences "\.unwrap()" "$module")
        expects=$(count_occurrences "\.expect(" "$module")
        panics=$(count_occurrences "panic!" "$module")
        
        TOTAL_UNWRAPS=$((TOTAL_UNWRAPS + unwraps))
        TOTAL_EXPECTS=$((TOTAL_EXPECTS + expects))
        TOTAL_PANICS=$((TOTAL_PANICS + panics))
        
        if [ $unwraps -gt 0 ] || [ $expects -gt 0 ] || [ $panics -gt 0 ]; then
            CRITICAL_FILES=$((CRITICAL_FILES + 1))
            echo -e "  $module: ${YELLOW}unwraps=$unwraps expects=$expects panics=$panics${NC}"
        else
            echo -e "  $module: ${GREEN}✓ Clean${NC}"
        fi
    fi
done

echo ""
echo "Summary:"
echo "--------"
echo -e "  Total unwraps: $TOTAL_UNWRAPS"
echo -e "  Total expects: $TOTAL_EXPECTS"
echo -e "  Total panics: $TOTAL_PANICS"
echo -e "  Modules with issues: $CRITICAL_FILES"
echo ""

# Mode strict: échouer si des unwraps sont trouvés dans les modules critiques
if [ "$STRICT_MODE" = true ]; then
    if [ $TOTAL_UNWRAPS -gt 0 ] || [ $TOTAL_EXPECTS -gt 0 ] || [ $TOTAL_PANICS -gt 0 ]; then
        echo -e "${RED}ERROR: Found unwraps/expects/panics in critical modules!${NC}"
        echo ""
        echo "Details:"
        for module in "${CRITICAL_MODULES[@]}"; do
            if [ -d "$module" ]; then
                list_occurrences "\.unwrap()" "$module" "Unwraps in $module" "$YELLOW"
                list_occurrences "\.expect(" "$module" "Expects in $module" "$RED"
                list_occurrences "panic!" "$module" "Panics in $module" "$RED"
            fi
        done
        exit 1
    else
        echo -e "${GREEN}✓ No unwraps/expects/panics found in critical modules${NC}"
        exit 0
    fi
fi

# Mode normal: avertissement seulement
if [ $TOTAL_UNWRAPS -gt 0 ] || [ $TOTAL_EXPECTS -gt 0 ] || [ $TOTAL_PANICS -gt 0 ]; then
    echo -e "${YELLOW}WARNING: $TOTAL_UNWRAPS unwraps, $TOTAL_EXPECTS expects, $TOTAL_PANICS panics found${NC}"
    echo "Run with --strict to see details and fail on errors"
    exit 0
else
    echo -e "${GREEN}✓ All clear!${NC}"
    exit 0
fi
