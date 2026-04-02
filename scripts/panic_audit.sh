#!/bin/bash
# Script d'audit automatisé pour détecter les panics non justifiés
# Usage: ./scripts/panic_audit.sh

set -e

echo "=========================================="
echo "TSN Panic Audit Script"
echo "=========================================="
echo ""

# Couleurs pour les sorties
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Compteurs
TOTAL_UNWRAPS=0
TOTAL_EXPECTS=0
TOTAL_PANICS=0
CRITICAL_UNWRAPS=0
CRITICAL_EXPECTS=0
CRITICAL_PANICS=0

# Fonction pour vérifier si un fichier est critique
is_critical_file() {
    local file="$1"
    if [[ "$file" == *"/crypto/"* ]] || [[ "$file" == *"/consensus/"* ]] || [[ "$file" == *"/core/"* ]]; then
        return 0
    fi
    return 1
}

echo "[1/5] Recherche des unwrap()..."
echo "----------------------------------------"
while IFS= read -r line; do
    file=$(echo "$line" | cut -d: -f1)
    lineno=$(echo "$line" | cut -d: -f2)
    code=$(echo "$line" | cut -d: -f3-)
    
    TOTAL_UNWRAPS=$((TOTAL_UNWRAPS + 1))
    
    if is_critical_file "$file"; then
        CRITICAL_UNWRAPS=$((CRITICAL_UNWRAPS + 1))
        echo -e "${RED}[CRITIQUE]${NC} $file:$lineno"
        echo "    $code"
    fi
done < <(grep -rn "\.unwrap()" --include="*.rs" src/ 2>/dev/null || true)

echo ""
echo "[2/5] Recherche des expect()..."
echo "----------------------------------------"
while IFS= read -r line; do
    file=$(echo "$line" | cut -d: -f1)
    lineno=$(echo "$line" | cut -d: -f2)
    code=$(echo "$line" | cut -d: -f3-)
    
    TOTAL_EXPECTS=$((TOTAL_EXPECTS + 1))
    
    if is_critical_file "$file"; then
        CRITICAL_EXPECTS=$((CRITICAL_EXPECTS + 1))
        echo -e "${RED}[CRITIQUE]${NC} $file:$lineno"
        echo "    $code"
    fi
done < <(grep -rn "\.expect(" --include="*.rs" src/ 2>/dev/null || true)

echo ""
echo "[3/5] Recherche des panic!()..."
echo "----------------------------------------"
while IFS= read -r line; do
    file=$(echo "$line" | cut -d: -f1)
    lineno=$(echo "$line" | cut -d: -f2)
    code=$(echo "$line" | cut -d: -f3-)
    
    TOTAL_PANICS=$((TOTAL_PANICS + 1))
    
    if is_critical_file "$file"; then
        CRITICAL_PANICS=$((CRITICAL_PANICS + 1))
        echo -e "${RED}[CRITIQUE]${NC} $file:$lineno"
        echo "    $code"
    fi
done < <(grep -rn "panic!(" --include="*.rs" src/ 2>/dev/null || true)

echo ""
echo "[4/5] Vérification des indexations potentiellement dangereuses..."
echo "----------------------------------------"
grep -rn "\[\d\+\]" --include="*.rs" src/crypto/ src/consensus/ src/core/ 2>/dev/null | while read -r line; do
    echo -e "${YELLOW}[ATTENTION]${NC} Indexation directe: $line"
done || true

echo ""
echo "[5/5] Vérification des unwrap_or_default dans les contextes sensibles..."
echo "----------------------------------------"
grep -rn "unwrap_or_default" --include="*.rs" src/crypto/ src/consensus/ 2>/dev/null | while read -r line; do
    echo -e "${YELLOW}[ATTENTION]${NC} unwrap_or_default: $line"
done || true

echo ""
echo "=========================================="
echo "RÉSUMÉ DE L'AUDIT"
echo "=========================================="
echo ""
echo -e "unwrap() trouvés: ${YELLOW}$TOTAL_UNWRAPS${NC} (${RED}$CRITICAL_UNWRAPS critiques${NC})"
echo -e "expect() trouvés: ${YELLOW}$TOTAL_EXPECTS${NC} (${RED}$CRITICAL_EXPECTS critiques${NC})"
echo -e "panic!() trouvés: ${YELLOW}$TOTAL_PANICS${NC} (${RED}$CRITICAL_PANICS critiques${NC})"
echo ""

# Seuils de tolérance
UNWRAP_THRESHOLD=50
EXPECT_THRESHOLD=20
PANIC_THRESHOLD=10

if [ $CRITICAL_UNWRAPS -gt $UNWRAP_THRESHOLD ]; then
    echo -e "${RED}ALERTE: Trop d'unwrap() critiques ($CRITICAL_UNWRAPS > $UNWRAP_THRESHOLD)${NC}"
    exit 1
fi

if [ $CRITICAL_EXPECTS -gt $EXPECT_THRESHOLD ]; then
    echo -e "${RED}ALERTE: Trop d'expect() critiques ($CRITICAL_EXPECTS > $EXPECT_THRESHOLD)${NC}"
    exit 1
fi

if [ $CRITICAL_PANICS -gt $PANIC_THRESHOLD ]; then
    echo -e "${RED}ALERTE: Trop de panic!() critiques ($CRITICAL_PANICS > $PANIC_THRESHOLD)${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Audit terminé - Seuils respectés${NC}"
echo ""
echo "Recommandations:"
echo "  1. Remplacer les unwrap() par des match ou unwrap_or()"
echo "  2. Documenter chaque expect() avec une raison valable"
echo "  3. Utiliser checked_* pour les opérations arithmétiques"
echo "  4. Privilégier parking_lot pour les locks"
echo ""
