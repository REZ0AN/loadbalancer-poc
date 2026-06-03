#!/bin/bash
# bring-down.sh — Phase 08

set -e
LB_NS="lb"
LB_IFACE="veth-lb"
PIN_DIR="/sys/fs/bpf/xdp-lb"

echo "[-] Detaching XDP"
sudo ip netns exec "$LB_NS" ip link set "$LB_IFACE" xdpgeneric off 2>/dev/null || true
sudo ip netns exec "$LB_NS" ip link set "$LB_IFACE" xdp off 2>/dev/null || true
echo "[✓] Detached"

echo "[-] Removing pinned maps"
for f in lb_info backends backend_count rr_counter flow_table; do
    sudo rm -f "$PIN_DIR/$f"
done
sudo rmdir "$PIN_DIR" 2>/dev/null || true
echo "[✓] Pins removed"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rm -f "$SCRIPT_DIR/xdp_lb.o"
echo "[✓] Done"