#!/bin/bash
# ============================================================
# TSN MASSIVE TEST — LAUNCH 10 LOCAL MINERS
# ============================================================
BINARY="/tmp/tsn-v186"
TEST_DIR="/tmp/tsn-massive-test"
PORTS_START=9340
PORT_STEP=2  # Each instance uses port AND port+1 (libp2p)
NUM_INSTANCES=10
THREADS=4

# VPS peers
VPS_PEERS="--peer http://45.145.165.223:9333 --peer http://151.240.19.253:9333 --peer http://45.145.164.76:9333"

echo "============================================"
echo "  LAUNCHING $NUM_INSTANCES LOCAL MINERS"
echo "  Ports: $PORTS_START to $((PORTS_START + (NUM_INSTANCES-1)*PORT_STEP)) (step $PORT_STEP)"
echo "  $(date)"
echo "============================================"

cd /opt/tsn

for i in $(seq 0 $((NUM_INSTANCES-1))); do
    port=$((PORTS_START + i*PORT_STEP))
    dir="$TEST_DIR/miner-$i"
    log="$dir/log.txt"

    # Build peer list: VPS + all other local instances (excluding self)
    PEERS="$VPS_PEERS"
    for j in $(seq 0 $((NUM_INSTANCES-1))); do
        if [ $j -ne $i ]; then
            PEERS="$PEERS --peer http://127.0.0.1:$((PORTS_START + j*PORT_STEP))"
        fi
    done

    # Miner-0 is the bridge: expose via public URL so VPS can sync from it
    PUBLIC_URL_ARG=""
    if [ $i -eq 0 ]; then
        PUBLIC_URL_ARG="--public-url http://82.66.133.163:9340"
    fi

    RUST_LOG=warn nohup "$BINARY" node \
        --port $port \
        --no-seeds \
        $PEERS \
        $PUBLIC_URL_ARG \
        -j $THREADS \
        --data-dir "$dir" \
        --mine "$dir/wallet.json" \
        --force-mine \
        > "$log" 2>&1 &

    echo "  Miner $i: port=$port PID=$! threads=$THREADS"
done

echo ""
echo "All $NUM_INSTANCES miners launched."
echo "Logs in $TEST_DIR/miner-*/log.txt"
echo ""
echo "Waiting 60s for all to sync..."
sleep 60

echo ""
echo "=== INITIAL STATUS ==="
for i in $(seq 0 $((NUM_INSTANCES-1))); do
    port=$((PORTS_START + i*PORT_STEP))
    result=$(curl -s --connect-timeout 3 http://127.0.0.1:$port/chain/info 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'h={d[\"height\"]} hash={d[\"latest_hash\"][:12]}')" 2>/dev/null) || result="NOT READY"
    printf "  miner-%-2d (:%d) %s\n" $i $port "$result"
done

SSH_KEY="/root/tsn-team/ssh_keys/tsn_ed25519"
SSH="ssh -i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10"
for info in "node-1:45.145.165.223:9333" "seed-1:151.240.19.253:9333" "seed-2:45.145.164.76:9333"; do
    name="${info%%:*}"; rest="${info#*:}"; ip="${rest%%:*}"
    h=$($SSH root@$ip "curl -s http://127.0.0.1:9333/chain/info" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'h={d[\"height\"]} hash={d[\"latest_hash\"][:12]}')" 2>/dev/null) || h="?"
    printf "  %-8s        %s\n" "$name" "$h"
done

echo ""
echo "Test running. Use monitor.sh for periodic checks."
