#!/bin/bash

# Compiles xdp_lb.c, attaches to veth-lb in the lb netns,
# pins all BPF maps, and populates them from the live topology.
# No iptables / IPVS / nftables required.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../network-namespaces-mental-model/topology.sh"

LB_NS="lb"
LB_IFACE="veth-lb"
PIN_DIR="/sys/fs/bpf/xdp-lb"

# ── Sanity checks ─────────────────────────────────────────────────────────────
if ! ip netns list | grep -q "^${LB_NS}"; then
    echo "[!] netns 'lb' not found — run bring-up.sh first"; exit 1
fi
command -v bpftool >/dev/null 2>&1 || {
    echo "[!] bpftool not found: sudo apt install -y linux-tools-$(uname -r)"; exit 1
}

# ── Helpers ───────────────────────────────────────────────────────────────────

get_ip() {
    local ns=$1
    for entry in "${NODES[@]}"; do
        if [[ "$entry" == "$ns "* ]]; then
            echo "$entry" | awk '{print $2}'; return
        fi
    done
}

get_mac() {
    local ns=$1
    sudo ip netns exec "$ns" ip link show "veth-$ns" 2>/dev/null \
        | awk '/link\/ether/{print $2}'
}

# bpftool map update parses value tokens as decimal integers, not hex.
# IP: emit octets in network (big-endian) order — a b c d, no reversal.
# iph->saddr/daddr are __be32 so byte 0 = first dotted-decimal octet.
ip_to_be_dec() {
    IFS='.' read -r a b c d <<< "$1"
    printf "%d %d %d %d" "$a" "$b" "$c" "$d"
}

# MAC: convert each hex octet to decimal via printf %d.
mac_to_dec() {
    IFS=':' read -r a b c d e f <<< "$1"
    printf "%d %d %d %d %d %d" "0x$a" "0x$b" "0x$c" "0x$d" "0x$e" "0x$f"
}

# ── Compile ───────────────────────────────────────────────────────────────────
ARCH=$(uname -m)
echo "[+] Compiling xdp_lb.c (arch: $ARCH)"
clang -O2 -target bpf -g \
    -I/usr/include/${ARCH}-linux-gnu \
    -c "$SCRIPT_DIR/xdp_lb.c" \
    -o "$SCRIPT_DIR/xdp_lb.o"
echo "[✓] Compiled → xdp_lb.o"

# ── Prepare pin directory ─────────────────────────────────────────────────────
sudo mkdir -p "$PIN_DIR"
for f in lb_info client_info backends backend_count rr_counter; do
    sudo rm -f "$PIN_DIR/$f"
done

# ── Detach any existing XDP program ──────────────────────────────────────────
sudo ip netns exec "$LB_NS" ip link set "$LB_IFACE" xdpgeneric off 2>/dev/null || true
sudo ip netns exec "$LB_NS" ip link set "$LB_IFACE" xdp off 2>/dev/null || true

# Attach in xdpgeneric (skb) mode — required for XDP_TX to work correctly
# on veth. Native XDP_TX loops back to the same RX queue; generic mode
# calls dev_queue_xmit() which sends the frame to the bridge peer.
# See README § "Why xdpgeneric and not native XDP".
echo "[+] Attaching to $LB_IFACE in netns $LB_NS (xdpgeneric)"
sudo ip netns exec "$LB_NS" \
    ip link set "$LB_IFACE" xdpgeneric obj "$SCRIPT_DIR/xdp_lb.o" sec xdp
echo "[✓] Attached (xdpgeneric)"

sleep 0.3

# ── Pin maps ──────────────────────────────────────────────────────────────────
# awk extracts the numeric ID (first token on the line, strip trailing colon).
# tail -1 picks the highest ID in case stale maps exist from a previous run.
# Never use grep with quoted names — bpftool text output has no quotes.
pin_map() {
    local name=$1
    local MAP_ID
    MAP_ID=$(sudo bpftool map list 2>/dev/null \
        | awk "/name ${name}/ { gsub(/:/, \"\", \$1); print \$1 }" \
        | tail -1)
    if [ -z "$MAP_ID" ]; then
        echo "[!] Map '$name' not found in bpftool map list"; exit 1
    fi
    sudo bpftool map pin id "$MAP_ID" "$PIN_DIR/$name"
    echo "[✓] Pinned $name (id=$MAP_ID) → $PIN_DIR/$name"
}

pin_map lb_info
pin_map client_info
pin_map backends
pin_map backend_count
pin_map rr_counter

# ── Read live topology ────────────────────────────────────────────────────────
echo ""
echo "[+] Reading live addresses from namespaces..."

LB_IP=$(get_ip "lb")
LB_MAC=$(get_mac "lb")
CLIENT_IP=$(get_ip "client")
CLIENT_MAC=$(get_mac "client")

echo "    lb:     ip=$LB_IP  mac=$LB_MAC"
echo "    client: ip=$CLIENT_IP  mac=$CLIENT_MAC"

# ── Populate maps ─────────────────────────────────────────────────────────────
# struct endpoint layout: ip(4B) + mac(6B) + pad(2B) = 12 bytes
# All values written as space-separated decimal integers.

sudo bpftool map update pinned "$PIN_DIR/lb_info" \
    key 0 0 0 0 \
    value $(ip_to_be_dec "$LB_IP") $(mac_to_dec "$LB_MAC") 0 0
echo "[✓] lb_info"

sudo bpftool map update pinned "$PIN_DIR/client_info" \
    key 0 0 0 0 \
    value $(ip_to_be_dec "$CLIENT_IP") $(mac_to_dec "$CLIENT_MAC") 0 0
echo "[✓] client_info"

BACKEND_NS=("b1" "b2" "b3")
for i in "${!BACKEND_NS[@]}"; do
    NS="${BACKEND_NS[$i]}"
    BE_IP=$(get_ip "$NS")
    BE_MAC=$(get_mac "$NS")
    KEY_B0=$(( i & 0xFF ))
    sudo bpftool map update pinned "$PIN_DIR/backends" \
        key $KEY_B0 0 0 0 \
        value $(ip_to_be_dec "$BE_IP") $(mac_to_dec "$BE_MAC") 0 0
    echo "[✓] backends[$i] = $NS  ip=$BE_IP  mac=$BE_MAC"
done

NUM_BACKENDS=${#BACKEND_NS[@]}
sudo bpftool map update pinned "$PIN_DIR/backend_count" \
    key 0 0 0 0 \
    value $(printf "%d 0 0 0" "$NUM_BACKENDS")
echo "[✓] backend_count = $NUM_BACKENDS"

sudo bpftool map update pinned "$PIN_DIR/rr_counter" \
    key 0 0 0 0 \
    value 0 0 0 0
echo "[✓] rr_counter = 0"

sudo ip netns exec "$LB_NS" sysctl -qw net.ipv4.ip_forward=1

# ── Verify ────────────────────────────────────────────────────────────────────
echo ""
echo "XDP mode on $LB_IFACE:"
sudo ip netns exec "$LB_NS" ip link show "$LB_IFACE" | grep -oE 'xdp\w*'

echo ""
echo "Map contents:"
for m in lb_info client_info backends backend_count rr_counter; do
    echo "  ── $m ──"
    sudo bpftool map dump pinned "$PIN_DIR/$m" --json 2>/dev/null \
        | python3 -c "
import sys, json
for e in json.load(sys.stdin):
    f = e.get('formatted', e)
    print('   ', f.get('value', f))
" 2>/dev/null || true
done

echo ""
echo "══════════════════════════════════════════════════════════"
echo " XDP NAT LB RUNNING — no iptables / IPVS / nftables"
echo "══════════════════════════════════════════════════════════"
echo " Test round-robin:"
echo "   for i in \$(seq 1 9); do"
echo "     sudo ip netns exec client curl -s http://10.0.0.5/"
echo "   done"
echo ""
echo " Watch connection counter:"
echo "   sudo ./stats.sh"
echo "══════════════════════════════════════════════════════════"