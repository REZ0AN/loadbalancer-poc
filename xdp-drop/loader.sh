#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../network-namespaces-mental-model/topology.sh"

LB_NS="lb"
LB_IFACE="veth-lb"
PIN_DIR="/sys/fs/bpf/xdp-lb"

# ── Sanity checks ─────────────────────────────────────────────────────────────
if ! ip netns list | grep -q "^${LB_NS}"; then
    echo "[!] netns '${LB_NS}' not found. Run bring-up.sh first."
    exit 1
fi
command -v bpftool >/dev/null 2>&1 || {
    echo "[!] bpftool not found: sudo apt install -y linux-tools-$(uname -r)"
    exit 1
}

# ── Compile ───────────────────────────────────────────────────────────────────
ARCH=$(uname -m)
echo "[+] Compiling xdp_drop.c (arch: $ARCH)"
clang -O2 -target bpf -g \
    -I/usr/include/${ARCH}-linux-gnu \
    -c "$SCRIPT_DIR/xdp_drop.c" \
    -o "$SCRIPT_DIR/xdp_drop.o"
echo "[✓] Compiled → xdp_drop.o"

# ── Prepare pin directory ─────────────────────────────────────────────────────
sudo mkdir -p "$PIN_DIR"
sudo rm -f "$PIN_DIR/pkt_count"

# ── Detach any existing XDP program ──────────────────────────────────────────
sudo ip netns exec "$LB_NS" \
    ip link set "$LB_IFACE" xdp off 2>/dev/null || true

# ── Attach ────────────────────────────────────────────────────────────────────
echo "[+] Attaching XDP program to $LB_IFACE in netns $LB_NS"
sudo ip netns exec "$LB_NS" \
    ip link set "$LB_IFACE" xdp obj "$SCRIPT_DIR/xdp_drop.o" sec xdp
echo "[✓] Attached"

# ── Find and pin the map ──────────────────────────────────────────────────────

# Why awk and not grep -oP?
# The id sits at column 1 on the "name pkt_count" line itself — awk $1
# is unambiguous regardless of bpftool version.  grep -oP with lookaheads
# was the source of the previous failure.

echo "[+] Locating pkt_count map..."
sleep 0.3   # tiny wait for kernel to register the map after attach

MAP_ID=$(sudo bpftool map list 2>/dev/null \
    | awk '/name pkt_count/ { gsub(/:/, "", $1); print $1 }' \
    | tail -1)

if [ -z "$MAP_ID" ]; then
    echo "[!] Could not find map named 'pkt_count' in bpftool map list."
    echo "    Run: sudo bpftool map list"
    echo "    Find the line with 'name pkt_count', note the id, then:"
    echo "      sudo bpftool map pin id <ID> $PIN_DIR/pkt_count"
    exit 1
fi

echo "[+] Found map id: $MAP_ID"
sudo bpftool map pin id "$MAP_ID" "$PIN_DIR/pkt_count"
echo "[✓] Pinned at $PIN_DIR/pkt_count"

# ── Confirm with a direct lookup before handing off ──────────────────────────
# bpftool map dump --json is available when BTF is present (btf_id shown
# in your map list output confirms BTF is active on your kernel).
echo ""
echo "Initial counter values (should both be 0):"
sudo bpftool map dump pinned "$PIN_DIR/pkt_count" --json 2>/dev/null \
    | python3 -c "
import sys, json
for e in json.load(sys.stdin):
    label = 'PASSED' if e['key'] == 0 else 'DROPPED'
    print(f'  {label} = {e[\"value\"]}')
"

echo ""
echo "XDP mode on $LB_IFACE:"
sudo ip netns exec "$LB_NS" ip link show "$LB_IFACE" \
    | grep -oE 'xdp[a-z]*' || echo "  (not shown — but should be attached)"

echo ""
echo "══════════════════════════════════════════════════"
echo " Ready. In another terminal:"
echo "   sudo ./stats.sh"
echo " Generate port-80 traffic (PASSED++):"
echo "   sudo ip netns exec client curl -s http://10.0.0.5/"
echo " Generate non-80 traffic  (DROPPED++):"
echo "   sudo ip netns exec client curl --max-time 2 http://10.0.0.5:9999/ || true"
echo "══════════════════════════════════════════════════"