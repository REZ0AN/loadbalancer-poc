#!/bin/bash

# rr_counter incrementing = forward path works (client → lb → backend)
# curl hanging             = return path broken  (backend → lb → client)
#
# Run this when curl hangs despite rr_counter incrementing.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../network-namespaces-mental-model/topology.sh"

PIN_DIR="/sys/fs/bpf/xdp-lb"
LB_NS="lb"

echo "══════════════════════════════════════════════════════"
echo " PHASE 07 RETURN-PATH DIAGNOSTIC"
echo "══════════════════════════════════════════════════════"
echo ""

# ── 1. XDP attachment ─────────────────────────────────────────────────────────
echo "── 1. XDP mode on veth-lb ──"
sudo ip netns exec "$LB_NS" ip link show veth-lb | grep -E "xdp|state|link"
echo ""
# Look for xdpgeneric. Native xdp mode causes XDP_TX to loop back to the
# same RX queue — frames never reach the bridge. See README § Problem 7.

# ── 2. Map contents ───────────────────────────────────────────────────────────
echo "── 2. Map contents ──"
for m in lb_info client_info backends backend_count rr_counter; do
    echo "  $m:"
    sudo bpftool map dump pinned "$PIN_DIR/$m" --json 2>/dev/null \
        | python3 -c "
import sys, json
for e in json.load(sys.stdin):
    f = e.get('formatted', e)
    print('   ', f.get('value', f))
" 2>/dev/null || echo "  (not found)"
done
echo ""

# ── 3. Live MACs vs map contents ──────────────────────────────────────────────
echo "── 3. Live MACs ──"
for ns in lb client b1 b2 b3; do
    MAC=$(sudo ip netns exec "$ns" ip link show "veth-$ns" 2>/dev/null \
          | awk '/link\/ether/{print $2}')
    echo "  $ns: $MAC"
done
echo ""
echo "  (compare with map contents above — all-zero MAC means map was not populated)"
echo ""

# ── 4. Can lb netns reach backends directly? ──────────────────────────────────
echo "── 4. Connectivity: lb → backends ──"
for be in b1 b2 b3; do
    IP=$(for entry in "${NODES[@]}"; do
        [[ "$entry" == "$be "* ]] && echo "$entry" | awk '{print $2}'
    done)
    echo -n "  $be ($IP): "
    sudo ip netns exec "$LB_NS" curl -s --max-time 2 "http://$IP/" 2>/dev/null \
        || echo "FAILED / TIMEOUT"
done
echo ""

# ── 5. tcpdump on bridge — watch full packet flow ─────────────────────────────
echo "── 5. Bridge tcpdump (8 seconds) ──"
echo "   Run in another terminal NOW:"
echo "   sudo ip netns exec client curl -s --max-time 5 http://10.0.0.5/"
echo ""
echo "   Watching lb0 bridge..."
sudo timeout 8 tcpdump -i lb0 -nn -e 'tcp port 80' 2>/dev/null | head -30
echo ""
# What to look for:
#   SYN from client    → forward path fired
#   SYN from lb        → IP rewrite correct (src now lb_ip)
#   SYN-ACK from be_N  → backend received the packet
#   SYN-ACK to client  → return path fired and XDP_TX reached the bridge
#   Silence after SYN  → backend unreachable or IP/MAC wrong in map

# ── 6. ARP tables ─────────────────────────────────────────────────────────────
echo "── 6. ARP table in lb netns ──"
sudo ip netns exec "$LB_NS" ip neigh show
echo ""

echo "── 6b. ARP table in b1 netns ──"
sudo ip netns exec b1 ip neigh show
echo ""

# ── 7. XDP_TX loop-back check ─────────────────────────────────────────────────
echo "── 7. XDP mode check (must be xdpgeneric, not xdp) ──"
MODE=$(sudo ip netns exec "$LB_NS" ip link show veth-lb 2>/dev/null | grep -oE 'xdp\w*')
echo "  Mode: ${MODE:-not attached}"
if [[ "$MODE" == "xdp" ]]; then
    echo ""
    echo "  WARNING: native xdp mode detected."
    echo "  XDP_TX on veth in native mode loops back to the same RX queue."
    echo "  Frames never reach the bridge — return path will always fail."
    echo "  Fix: sudo ./bring-down.sh && sudo ./loader.sh"
    echo "  loader.sh uses xdpgeneric which calls dev_queue_xmit() instead."
fi
echo ""

echo "══════════════════════════════════════════════════════"
echo " SUMMARY"
echo "══════════════════════════════════════════════════════"
echo ""
echo " rr_counter increments but curl hangs:"
echo "   → return path broken. Check step 5 for SYN-ACK reaching bridge."
echo "   → Check step 7: must be xdpgeneric, not xdp."
echo "   → Check step 3: all-zero MACs mean map was not populated."
echo ""
echo " rr_counter does not increment:"
echo "   → forward path broken. Check step 1 for XDP attachment."
echo "   → Re-run: sudo ./loader.sh"
echo ""
echo " Backends timeout in step 4:"
echo "   → topology is down. Run bring-up.sh and launch-servers.sh."