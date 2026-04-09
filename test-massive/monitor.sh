#!/bin/bash
# ============================================================
# TSN MASSIVE TEST — 1 HOUR MONITORING
# Checks every 5 minutes, produces final report
# ============================================================

TEST_DIR="/tmp/tsn-massive-test"
PORTS_START=9340
PORT_STEP=2
NUM_INSTANCES=10
DURATION_MIN=60
CHECK_INTERVAL=300  # 5 min
REPORT="$TEST_DIR/REPORT.txt"
SSH_KEY="/root/tsn-team/ssh_keys/tsn_ed25519"
SSH="ssh -i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10"

CHECKS=$((DURATION_MIN * 60 / CHECK_INTERVAL))

echo "============================================" | tee "$REPORT"
echo "  TSN MASSIVE TEST — MONITORING" | tee -a "$REPORT"
echo "  Start: $(date)" | tee -a "$REPORT"
echo "  Duration: ${DURATION_MIN}min" | tee -a "$REPORT"
echo "  Instances: $NUM_INSTANCES local + node-1 + seed-1 + seed-2" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# ── Periodic checks ──
for check in $(seq 0 $CHECKS); do
    elapsed=$((check * CHECK_INTERVAL / 60))

    if [ $check -gt 0 ]; then
        sleep $CHECK_INTERVAL
    fi

    echo "=== T=${elapsed}min $(date) ===" | tee -a "$REPORT"

    # Collect heights and hashes
    HEIGHTS=()
    HASHES=()
    WORKS=()

    for i in $(seq 0 $((NUM_INSTANCES-1))); do
        port=$((PORTS_START + i*PORT_STEP))
        info=$(curl -s --connect-timeout 3 http://127.0.0.1:$port/chain/info 2>/dev/null)
        if [ -n "$info" ]; then
            h=$(echo "$info" | python3 -c "import sys,json; print(json.load(sys.stdin)['height'])" 2>/dev/null) || h="?"
            hash=$(echo "$info" | python3 -c "import sys,json; print(json.load(sys.stdin)['latest_hash'][:12])" 2>/dev/null) || hash="?"
            work=$(echo "$info" | python3 -c "import sys,json; print(json.load(sys.stdin).get('cumulative_work','?'))" 2>/dev/null) || work="?"
        else
            h="DOWN"; hash="?"; work="?"
        fi
        printf "  miner-%-2d  h=%-5s hash=%s work=%s\n" $i "$h" "$hash" "$work" | tee -a "$REPORT"
        HEIGHTS+=("$h")
        HASHES+=("$hash")
    done

    # VPS nodes
    for info in "node-1:45.145.165.223" "seed-1:151.240.19.253" "seed-2:45.145.164.76"; do
        name="${info%%:*}"; ip="${info#*:}"
        vps_info=$($SSH root@$ip "curl -s http://127.0.0.1:9333/chain/info" 2>/dev/null)
        if [ -n "$vps_info" ]; then
            h=$(echo "$vps_info" | python3 -c "import sys,json; print(json.load(sys.stdin)['height'])" 2>/dev/null) || h="?"
            hash=$(echo "$vps_info" | python3 -c "import sys,json; print(json.load(sys.stdin)['latest_hash'][:12])" 2>/dev/null) || hash="?"
            work=$(echo "$vps_info" | python3 -c "import sys,json; print(json.load(sys.stdin).get('cumulative_work','?'))" 2>/dev/null) || work="?"
        else
            h="DOWN"; hash="?"; work="?"
        fi
        printf "  %-8s  h=%-5s hash=%s work=%s\n" "$name" "$h" "$hash" "$work" | tee -a "$REPORT"
        HEIGHTS+=("$h")
        HASHES+=("$hash")
    done

    # Quick convergence check
    unique_hashes=$(printf '%s\n' "${HASHES[@]}" | grep -v '?' | sort -u | wc -l)
    if [ "$unique_hashes" -le 1 ]; then
        echo "  → CONVERGED (1 unique hash)" | tee -a "$REPORT"
    else
        echo "  → DIVERGED ($unique_hashes unique hashes)" | tee -a "$REPORT"
    fi
    echo "" | tee -a "$REPORT"
done

# ── Final counters ──
echo "============================================" | tee -a "$REPORT"
echo "  FINAL COUNTERS" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

for i in $(seq 0 $((NUM_INSTANCES-1))); do
    log="$TEST_DIR/miner-$i/log.txt"
    mined=$(grep -c 'Mined block' "$log" 2>/dev/null || echo 0)
    reorg=$(grep -c 'ACCEPT REORG' "$log" 2>/dev/null || echo 0)
    dup=$(grep -c 'REJECT DUP' "$log" 2>/dev/null || echo 0)
    less=$(grep -c 'LESS_WORK' "$log" 2>/dev/null || echo 0)
    none=$(grep -c 'none accepted' "$log" 2>/dev/null || echo 0)
    ban=$(grep -ci 'banning\|banned' "$log" 2>/dev/null || echo 0)
    invalid=$(grep -c 'Invalid commitment' "$log" 2>/dev/null || echo 0)
    rollback=$(grep -c 'ROLLBACK_START' "$log" 2>/dev/null || echo 0)
    fork_behind=$(grep -c 'FORK_BEHIND_DETECTED' "$log" 2>/dev/null || echo 0)
    printf "  miner-%-2d  mined=%-4d reorg=%-3d rollback=%-3d less_work=%-3d dup=%-3d none=%-3d ban=%-3d invalid=%-3d fork_behind=%d\n" \
        $i $mined $reorg $rollback $less $dup $none $ban $invalid $fork_behind | tee -a "$REPORT"
done

# Node-1 counters
echo "" | tee -a "$REPORT"
$SSH root@45.145.165.223 "
    LOG=\$(journalctl -u tsn-node --no-pager --since '65 min ago' 2>/dev/null)
    mined=\$(echo \"\$LOG\" | grep -c 'Mined block')
    reorg=\$(echo \"\$LOG\" | grep -c 'ACCEPT REORG')
    less=\$(echo \"\$LOG\" | grep -c 'LESS_WORK')
    none=\$(echo \"\$LOG\" | grep -c 'none accepted')
    ban=\$(echo \"\$LOG\" | grep -ci 'banning\|banned')
    invalid=\$(echo \"\$LOG\" | grep -c 'Invalid commitment')
    rollback=\$(echo \"\$LOG\" | grep -c 'ROLLBACK_START')
    printf '  node-1    mined=%-4d reorg=%-3d rollback=%-3d less_work=%-3d none=%-3d ban=%-3d invalid=%d\n' \
        \$mined \$reorg \$rollback \$less \$none \$ban \$invalid
" 2>/dev/null | tee -a "$REPORT"

# ── Verdict ──
echo "" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"
echo "  VERDICT" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"

# Check final state
FINAL_HASHES=()
for i in $(seq 0 $((NUM_INSTANCES-1))); do
    port=$((PORTS_START+i))
    h=$(curl -s --connect-timeout 3 http://127.0.0.1:$port/chain/info 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['latest_hash'][:16])" 2>/dev/null) || h="?"
    FINAL_HASHES+=("$h")
done
n1_hash=$($SSH root@45.145.165.223 "curl -s http://127.0.0.1:9333/chain/info" 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['latest_hash'][:16])" 2>/dev/null) || n1_hash="?"
FINAL_HASHES+=("$n1_hash")

unique=$(printf '%s\n' "${FINAL_HASHES[@]}" | grep -v '?' | sort -u | wc -l)

# Count total invalid commitments
total_invalid=0
for i in $(seq 0 $((NUM_INSTANCES-1))); do
    c=$(grep -c 'Invalid commitment' "$TEST_DIR/miner-$i/log.txt" 2>/dev/null || echo 0)
    total_invalid=$((total_invalid + c))
done

echo "" | tee -a "$REPORT"
if [ "$unique" -eq 1 ] && [ "$total_invalid" -eq 0 ]; then
    echo "  ✅ TEST PASSED" | tee -a "$REPORT"
    echo "  All nodes converged on same tip hash" | tee -a "$REPORT"
    echo "  0 Invalid commitment errors" | tee -a "$REPORT"
elif [ "$unique" -eq 1 ]; then
    echo "  ⚠️  TEST PARTIAL — converged but $total_invalid Invalid commitment warnings" | tee -a "$REPORT"
else
    echo "  ❌ TEST FAILED — $unique unique hashes at end" | tee -a "$REPORT"
fi
echo "" | tee -a "$REPORT"
echo "  End: $(date)" | tee -a "$REPORT"
echo "  Report: $REPORT" | tee -a "$REPORT"
