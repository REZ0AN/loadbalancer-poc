#!/bin/bash

# Detaches XDP from veth-lb and removes the pinned map.
# Idempotent — safe to run multiple times.

set -e

LB_NS="lb"
LB_IFACE="veth-lb"
PIN_DIR="/sys/fs/bpf/xdp-lb"

echo "[-] Detaching XDP from $LB_IFACE (netns: $LB_NS)"
sudo ip netns exec "$LB_NS" \
    ip link set "$LB_IFACE" xdp off 2>/dev/null || true
echo "[✓] XDP detached"

echo "[-] Removing pinned map at $PIN_DIR/pkt_count"
sudo rm -f "$PIN_DIR/pkt_count"
sudo rmdir "$PIN_DIR" 2>/dev/null || true
echo "[✓] Pins removed"

# Remove compiled object
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rm -f "$SCRIPT_DIR/xdp_drop.o"
echo "[✓] Object file removed"