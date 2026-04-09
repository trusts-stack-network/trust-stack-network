#!/bin/bash
# ============================================================
# TSN MASSIVE TEST — STOP ALL
# ============================================================

echo "Stopping all TSN processes..."

# Local
pkill -9 -f "tsn.*node" 2>/dev/null || true
sleep 2
remaining=$(pgrep -c -f "tsn.*node" 2>/dev/null || echo 0)
echo "Local: $remaining remaining"

# VPS
SSH_KEY="/root/tsn-team/ssh_keys/tsn_ed25519"
SSH="ssh -i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10"
for info in "node-1:45.145.165.223" "seed-1:151.240.19.253" "seed-2:45.145.164.76"; do
    name="${info%%:*}"; ip="${info#*:}"
    $SSH root@$ip "systemctl stop tsn-node; killall -9 tsn 2>/dev/null" 2>/dev/null || true
    echo "$name stopped"
done

echo "All stopped."
