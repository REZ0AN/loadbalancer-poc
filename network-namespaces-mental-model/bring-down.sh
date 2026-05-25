#!/bin/bash
# Bring down everything created by bring-up.sh.
# Idempotent — safe to run even if nothing is up.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/topology.sh"

for entry in "${NODES[@]}"; do
    NS=$(echo "$entry" | awk '{print $1}')
    echo "[-] Removing netns $NS"
    ip netns del "$NS" 2>/dev/null || true
done

echo "[-] Removing bridge $BRIDGE"
ip link del "$BRIDGE" 2>/dev/null || true

echo "[✓] Topology down."