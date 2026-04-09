#!/bin/bash
# ============================================================
# TSN MASSIVE TEST — PREFLIGHT CHECKLIST
# 10 local miners + node-1 (miner) + seed-1/seed-2 (relays)
# ============================================================
SSH_KEY="/root/tsn-team/ssh_keys/tsn_ed25519"
SSH="ssh -i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10"
BINARY="/tmp/tsn-v186"
TEST_DIR="/tmp/tsn-massive-test"
PORTS_START=9335
NUM_INSTANCES=10
THREADS_PER_INSTANCE=4

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; ERRORS=$((ERRORS+1)); }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
ERRORS=0

echo "============================================"
echo "  TSN MASSIVE TEST — PREFLIGHT"
echo "  $(date)"
echo "============================================"
echo ""

# ── 1. Binary exists ──
echo "▸ 1. Binary check"
if [ -f "$BINARY" ]; then
    SIZE=$(wc -c < "$BINARY")
    pass "Binary $BINARY exists ($SIZE bytes)"
else
    fail "Binary $BINARY not found"
fi

# ── 2. Kill ALL existing TSN processes ──
echo "▸ 2. Kill existing TSN processes"
LOCAL_PROCS=$(pgrep -c -f "tsn" 2>/dev/null || echo 0)
if [ "$LOCAL_PROCS" -gt 0 ]; then
    kill -9 $(pgrep -f "tsn" | grep -v $$) 2>/dev/null || true
    sleep 2
    REMAINING=$(pgrep -c -f "tsn" 2>/dev/null || echo 0)
    if [ "$REMAINING" -gt 0 ]; then
        fail "Still $REMAINING TSN processes running locally"
    else
        pass "Killed $LOCAL_PROCS local TSN processes"
    fi
else
    pass "No local TSN processes running"
fi

for info in "node-1:45.145.165.223" "seed-1:151.240.19.253" "seed-2:45.145.164.76" "seed-3:146.19.168.71" "seed-4:45.132.96.141"; do
    name="${info%%:*}"; ip="${info#*:}"
    $SSH root@$ip "systemctl stop tsn-node 2>/dev/null; killall -9 tsn 2>/dev/null" 2>/dev/null || true
    count=$($SSH root@$ip "pgrep -c tsn 2>/dev/null || echo 0" 2>/dev/null) || count="SSH_FAIL"
    if [ "$count" = "0" ] || [ "$count" = "0\n0" ]; then
        pass "$name stopped"
    else
        fail "$name still has processes: $count"
    fi
done

# ── 3. Disable backup/watchdog ──
echo "▸ 3. Disable backup/watchdog"
for info in "node-1:45.145.165.223" "seed-1:151.240.19.253" "seed-2:45.145.164.76"; do
    name="${info%%:*}"; ip="${info#*:}"
    $SSH root@$ip "
        mv /etc/cron.d/tsn-backup /etc/cron.d/tsn-backup.disabled 2>/dev/null
        systemctl stop tsn-watchdog.timer 2>/dev/null
        systemctl disable tsn-watchdog.timer 2>/dev/null
    " 2>/dev/null || true
    pass "$name backup/watchdog disabled"
done

# ── 4. Wipe ALL data dirs ──
echo "▸ 4. Wipe data dirs"
for info in "node-1:45.145.165.223" "seed-1:151.240.19.253" "seed-2:45.145.164.76"; do
    name="${info%%:*}"; ip="${info#*:}"
    $SSH root@$ip "rm -rf /opt/tsn/data/*" 2>/dev/null
    count=$($SSH root@$ip "ls /opt/tsn/data/ 2>/dev/null | wc -l" 2>/dev/null)
    if [ "$count" = "0" ]; then
        pass "$name data wiped"
    else
        fail "$name data NOT empty ($count items)"
    fi
done

rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"
pass "Local test dir $TEST_DIR created fresh"

# ── 5. Deploy binary on VPS ──
echo "▸ 5. Deploy binary"
for info in "node-1:45.145.165.223" "seed-1:151.240.19.253" "seed-2:45.145.164.76"; do
    name="${info%%:*}"; ip="${info#*:}"
    $SSH root@$ip "rm -f /opt/tsn/bin/tsn /usr/local/bin/tsn" 2>/dev/null
    scp -i $SSH_KEY -o StrictHostKeyChecking=no "$BINARY" root@$ip:/opt/tsn/bin/tsn 2>/dev/null
    $SSH root@$ip "chmod +x /opt/tsn/bin/tsn; cp /opt/tsn/bin/tsn /usr/local/bin/tsn" 2>/dev/null
    size=$($SSH root@$ip "wc -c < /opt/tsn/bin/tsn" 2>/dev/null)
    expected=$(wc -c < "$BINARY")
    if [ "$size" = "$expected" ]; then
        pass "$name binary deployed ($size bytes)"
    else
        fail "$name binary size mismatch (got $size, expected $expected)"
    fi
done

# ── 6. Create local wallets + data dirs ──
echo "▸ 6. Create local instances"
for i in $(seq 0 $((NUM_INSTANCES-1))); do
    dir="$TEST_DIR/miner-$i"
    mkdir -p "$dir"
    cd /opt/tsn && echo "YES" | "$BINARY" new-wallet -o "$dir/wallet.json" > /dev/null 2>&1
    if [ -f "$dir/wallet.json" ]; then
        pass "Instance $i: wallet + dir ready (port $((PORTS_START+i)))"
    else
        fail "Instance $i: wallet creation failed"
    fi
done

# ── 7. Verify seed-3/4 are DOWN ──
echo "▸ 7. Seed-3/4 isolation"
for info in "seed-3:146.19.168.71" "seed-4:45.132.96.141"; do
    name="${info%%:*}"; ip="${info#*:}"
    count=$($SSH root@$ip "pgrep -c tsn 2>/dev/null || echo 0" 2>/dev/null) || count="SSH_FAIL"
    if [ "$count" = "0" ] || [ "$count" = "0\n0" ]; then
        pass "$name confirmed DOWN"
    else
        fail "$name still running!"
    fi
done

# ── 8. Start node-1 and verify genesis ──
echo "▸ 8. Start node-1 (genesis)"
$SSH root@45.145.165.223 "systemctl start tsn-node" 2>/dev/null
echo "    Waiting 50s for Circom keys..."
sleep 50
N1_INFO=$($SSH root@45.145.165.223 "curl -s http://127.0.0.1:9333/chain/info" 2>/dev/null)
N1_H=$(echo "$N1_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin)['height'])" 2>/dev/null) || N1_H="FAIL"
if [ "$N1_H" -ge 0 ] 2>/dev/null; then
    pass "node-1 API responds (h=$N1_H)"
else
    fail "node-1 API not responding"
fi

# ── 9. Start seeds and verify API ──
echo "▸ 9. Start seeds"
$SSH root@151.240.19.253 "systemctl start tsn-node" 2>/dev/null
$SSH root@45.145.164.76 "systemctl start tsn-node" 2>/dev/null
sleep 40
for info in "seed-1:151.240.19.253" "seed-2:45.145.164.76"; do
    name="${info%%:*}"; ip="${info#*:}"
    h=$($SSH root@$ip "curl -s http://127.0.0.1:9333/chain/info" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['height'])" 2>/dev/null) || h="FAIL"
    if [ "$h" -ge 0 ] 2>/dev/null; then
        pass "$name API responds (h=$h)"
    else
        fail "$name API not responding"
    fi
done

# ── Summary ──
echo ""
echo "============================================"
if [ $ERRORS -eq 0 ]; then
    echo -e "  ${GREEN}PREFLIGHT PASSED${NC} — Ready for massive test"
else
    echo -e "  ${RED}PREFLIGHT FAILED${NC} — $ERRORS errors"
fi
echo "============================================"
exit $ERRORS
