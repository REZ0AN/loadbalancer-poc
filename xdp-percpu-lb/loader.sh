#!/bin/bash
# loader.sh — Phase 09: PERCPU Counters + Incremental Checksum

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
        [[ "$entry" == "$ns "* ]] && echo "$entry" | awk '{print $2}' && return
    done
}

get_mac() {
    local ns=$1
    sudo ip netns exec "$ns" ip link show "veth-$ns" 2>/dev/null \
        | awk '/link\/ether/{print $2}'
}

# bpftool map update expects decimal integers, not hex.
# IP: natural octet order (a b c d) — matches __be32 memory layout.
ip_to_be_dec() {
    IFS='.' read -r a b c d <<< "$1"
    printf "%d %d %d %d" "$a" "$b" "$c" "$d"
}

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
for f in lb_info backends backend_count rr_counter flow_table backend_stats; do
    sudo rm -f "$PIN_DIR/$f"
done

# ── Detach any existing XDP ───────────────────────────────────────────────────
sudo ip netns exec "$LB_NS" ip link set "$LB_IFACE" xdpgeneric off 2>/dev/null || true
sudo ip netns exec "$LB_NS" ip link set "$LB_IFACE" xdp off 2>/dev/null || true

# xdpgeneric required for XDP_TX on veth — see phase 07 README.
echo "[+] Attaching to $LB_IFACE in netns $LB_NS (xdpgeneric)"
sudo ip netns exec "$LB_NS" \
    ip link set "$LB_IFACE" xdpgeneric obj "$SCRIPT_DIR/xdp_lb.o" sec xdp
echo "[✓] Attached"

sleep 0.3

# ── Pin maps ──────────────────────────────────────────────────────────────────
pin_map() {
    local name=$1
    local MAP_ID
    MAP_ID=$(sudo bpftool map list 2>/dev/null \
        | awk "/name ${name}/ { gsub(/:/, \"\", \$1); print \$1 }" \
        | tail -1)
    if [ -z "$MAP_ID" ]; then
        echo "[!] Map '$name' not found"; exit 1
    fi
    sudo bpftool map pin id "$MAP_ID" "$PIN_DIR/$name"
    echo "[✓] Pinned $name (id=$MAP_ID)"
}

pin_map lb_info
pin_map backends
pin_map backend_count
pin_map rr_counter
pin_map flow_table
pin_map backend_stats

# ── Read live topology ────────────────────────────────────────────────────────
echo ""
echo "[+] Reading live addresses..."

LB_IP=$(get_ip "lb")
LB_MAC=$(get_mac "lb")
echo "    lb: ip=$LB_IP  mac=$LB_MAC"

# struct endpoint: ip(4) + mac(6) + pad(2) = 12 bytes
sudo bpftool map update pinned "$PIN_DIR/lb_info" \
    key 0 0 0 0 \
    value $(ip_to_be_dec "$LB_IP") $(mac_to_dec "$LB_MAC") 0 0
echo "[✓] lb_info"

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
echo "══════════════════════════════════════════════════════════"
echo " XDP NAT LB — phase 09"
echo " PERCPU counters + RFC 1624 incremental checksum"
echo "══════════════════════════════════════════════════════════"
echo " Test:"
echo "   for i in \$(seq 1 9); do"
echo "     sudo ip netns exec client curl -s http://10.0.0.5/"
echo "   done"
echo ""
echo " Watch per-backend stats:  sudo ./stats.sh"
echo "══════════════════════════════════════════════════════════"