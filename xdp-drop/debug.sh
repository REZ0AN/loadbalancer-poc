#!/bin/bash

# why counter stays at 0 despite traffic?  
# This script checks every link in the chain and tells you exactly what's broken.
# Run this whenever stats.sh shows 0 despite curl generating traffic.
# It checks every link in the chain and tells you exactly what's broken.

LB_NS="lb"
LB_IFACE="veth-lb"
PIN_DIR="/sys/fs/bpf/xdp-lb"

echo "══════════════════════════════════════════════════════"
echo " XDP_DROP DIAGNOSTIC"
echo "══════════════════════════════════════════════════════"
echo ""

# ── 1. Is the XDP program attached? ──────────────────────────────────────────
echo "── 1. XDP attachment on $LB_IFACE (netns: $LB_NS) ──"
sudo ip netns exec "$LB_NS" ip link show "$LB_IFACE" 2>/dev/null | grep -E "xdp|state|link"
echo ""
# What to look for:
#   "xdp" in the flags → native XDP (veth in recent kernels)
#   "xdpgeneric" in the flags → generic/skb mode (Lima/VM often falls back here)
#   Neither → program NOT attached — run loader.sh
#
# IMPORTANT: xdpgeneric works correctly for our purposes.
# The difference is only performance (native skips skb allocation;
# generic doesn't).  Counters increment in both modes.

# ── 2. Is the right interface being watched? ──────────────────────────────────
echo "── 2. All interfaces inside lb netns ──"
sudo ip netns exec "$LB_NS" ip link show 2>/dev/null
echo ""
# The XDP program is attached to veth-lb.
# Traffic from client arrives at veth-lb from the bridge lb0.
# If there's an unexpected interface name, the curl hits a different iface.

# ── 3. Are BPF programs loaded at all? ───────────────────────────────────────
echo "── 3. All XDP programs in kernel (bpftool prog list) ──"
sudo bpftool prog list type xdp 2>/dev/null || sudo bpftool prog list 2>/dev/null | grep xdp
echo ""
# Look for: "xdp_drop_filter" —> that's our function name from SEC("xdp")
# If it's not here, the object failed to load silently.

# ── 4. Is the pinned map accessible? ─────────────────────────────────────────
echo "── 4. Pinned map ──"
if [ -e "$PIN_DIR/pkt_count" ]; then
    echo "  EXISTS at $PIN_DIR/pkt_count"
    echo "  Raw dump:"
    sudo bpftool map dump pinned "$PIN_DIR/pkt_count" 2>/dev/null | head -20
else
    echo "  NOT FOUND at $PIN_DIR/pkt_count"
    echo "  Available maps in kernel:"
    sudo bpftool map list 2>/dev/null | head -30
fi
echo ""

# ── 5. Does a curl actually reach veth-lb? ───────────────────────────────────
echo "── 5. Traffic capture test (5 second window) ──"
echo "  Starting tcpdump on lb0 bridge for 5 seconds..."
echo "  ALSO run in another terminal: sudo ip netns exec client curl -s http://10.0.0.5/"
echo ""
sudo timeout 5 tcpdump -i lb0 -nn -c 10 'tcp port 80' 2>/dev/null || true
echo ""
# If you see packets here but counters don't increment, the XDP program
# is attached to the wrong interface or in a state where it doesn't fire.
# tcpdump on lb0 (the bridge) sees packets AFTER XDP_PASS or if XDP is
# on a different interface.  Seeing packets here confirms the path is right.

# ── 6. Direct map write test ──────────────────────────────────────────────────
echo "── 6. Manual map update test ──"
echo "  Attempting to manually set pkt_count[0] = 999 and read it back..."
if [ -e "$PIN_DIR/pkt_count" ]; then
    sudo bpftool map update pinned "$PIN_DIR/pkt_count" \
        key 0 0 0 0 value 231 3 0 0 0 0 0 0 2>/dev/null && echo "  Write OK" || echo "  Write FAILED"
    sudo bpftool map lookup pinned "$PIN_DIR/pkt_count" key 0 0 0 0 2>/dev/null
    # 999 in little-endian 8 bytes = e7 03 00 00 00 00 00 00
    # If this shows e7 03 ..., the map read/write path works.
    # If stats.sh still shows 0, the XDP program is writing to a DIFFERENT
    # map instance than the one pinned here.
else
    echo "  Skipped — map not pinned"
fi
echo ""

# ── 7. Lima-specific: check XDP mode ─────────────────────────────────────────
echo "── 7. Lima / VM notes ──"
KERNEL=$(uname -r)
echo "  Kernel: $KERNEL"
VETH_XDP=$(sudo ip netns exec "$LB_NS" ip link show "$LB_IFACE" 2>/dev/null | grep -oP 'xdp\w*')
echo "  XDP mode on $LB_IFACE: ${VETH_XDP:-not attached}"
if [[ "$VETH_XDP" == "xdpgeneric" ]]; then
    echo ""
    echo "  NOTE: xdpgeneric mode detected."
    echo "  This is NORMAL on Lima/VMs with veth pairs."
    echo "  Counters still increment — this is not the problem."
    echo "  xdpgeneric fires AFTER skb allocation (not at driver level)"
    echo "  but XDP_DROP and map updates work identically."
fi
echo ""
echo "══════════════════════════════════════════════════════"
echo " SUMMARY"
echo "══════════════════════════════════════════════════════"
echo ""
echo "If XDP is attached AND tcpdump shows curl packets BUT counters=0:"
echo "  → The program is loading a map but stats.sh is reading a DIFFERENT"
echo "    map (pinning failed silently).  Try:"
echo "      sudo bpftool map list | grep array"
echo "    Find the map with max_entries=2, note its id N, then:"
echo "      sudo bpftool map pin id N $PIN_DIR/pkt_count"
echo ""
echo "If XDP is NOT attached:"
echo "  → Re-run: sudo ./loader.sh"
echo ""
echo "If bpftool prog list shows no XDP programs:"
echo "  → Compilation succeeded but load failed. Check: dmesg | tail -20"