#!/bin/bash

#
# Detaches the XDP program from veth-lb inside the lb netns.
# Safe to run even if nothing is attached (idempotent).

set -e

LB_NS="lb"
LB_IFACE="veth-lb"

echo "[-] Detaching XDP from $LB_IFACE (netns: $LB_NS)"
sudo ip netns exec "$LB_NS" \
    ip link set "$LB_IFACE" xdp off 2>/dev/null || true

echo "[✓] XDP detached"

# Cleanup compiled object (optional — comment out to keep for inspection)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rm -f "$SCRIPT_DIR/xdp_observer.o"
echo "[✓] Object file removed"