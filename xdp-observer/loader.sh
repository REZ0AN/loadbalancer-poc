#!/bin/bash

# What this script does, in order:
#   1. Sources topology.sh to get the bridge name and node IPs
#   2. Compiles xdp_observer.c to BPF bytecode (xdp_observer.o)
#   3. Attaches the BPF object to the veth inside the "lb" netns
#   4. Tells you how to read the trace output
# Note: the script doesn't generate any traffic or read the trace output itself;

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Source topology ───────────────────────────────────────────────────────────
# We need to know which netns is "lb" and what interface name was created
# by bring-up.sh (veth-lb, following the VETH_NS="veth-$NS" convention).

source "$SCRIPT_DIR/../network-namespaces-mental-model/topology.sh"

LB_NS="lb"
LB_IFACE="veth-lb"     # the veth end inside the lb netns — see bring-up.sh

# ── Sanity: topology must be up ──────────────────────────────────────────────
if ! ip netns list | grep -q "^${LB_NS}"; then
    echo "[!] netns '${LB_NS}' not found. Run bring-up.sh first."
    exit 1
fi

# ── Compile ───────────────────────────────────────────────────────────────────

ARCH=$(uname -m)
echo "[+] Compiling xdp_observer.c (arch: $ARCH)"

clang -O2 -target bpf -g \
    -I/usr/include/${ARCH}-linux-gnu \
    -c "$SCRIPT_DIR/xdp_observer.c" \
    -o "$SCRIPT_DIR/xdp_observer.o"

echo "[✓] Compiled → xdp_observer.o"


# ── Detach any existing XDP program first ────────────────────────────────────
# If a previous run left a program attached, attaching a new one would fail
# with "busy".  We detach silently; the 2>/dev/null suppresses "no XDP" errors.

sudo ip netns exec "$LB_NS" \
    ip link set "$LB_IFACE" xdp off 2>/dev/null || true


# ── Attach ────────────────────────────────────────────────────────────────────
# `ip link set ... xdp obj ... sec xdp`
#
# xdp obj xdp_observer.o  — load the ELF object into the kernel and attach it
# sec xdp                  — which ELF section to use as the entry point
#                            (matches SEC("xdp") in the C source)
#
# We run this inside the lb netns because the interface veth-lb exists only
# inside that namespace, it has no presence in the root namespace.
#
# "Generic XDP" vs "native XDP":
# Without any flag, `ip link set ... xdp obj` tries native mode (driver hook)
# and falls back to generic mode (skb hook) if the driver doesn't support it.
# veth pairs support native XDP since kernel 4.18, so in modern kernels you
# get native mode automatically, check with `ip link show veth-lb` and look
# for "xdp" vs "xdpgeneric" in the output.
#
# For this learning phase the difference doesn't matter because we don't
# modify packets.

echo "[+] Attaching XDP program to $LB_IFACE inside netns $LB_NS"
sudo ip netns exec "$LB_NS" \
    ip link set "$LB_IFACE" xdp obj "$SCRIPT_DIR/xdp_observer.o" sec xdp

echo "[✓] XDP observer attached"


# ── Verify ────────────────────────────────────────────────────────────────────
echo ""
echo "Verify: XDP program should be shown on the interface:"
sudo ip netns exec "$LB_NS" ip link show "$LB_IFACE" | grep -i xdp || true

echo ""
echo "──────────────────────────────────────────────────────────"
echo "To see traces, run in ANOTHER terminal:"
echo "  sudo cat /sys/kernel/debug/tracing/trace_pipe"
echo ""
echo "Then generate traffic from the client namespace:"
echo "  sudo ip netns exec client curl -s http://10.0.0.5/"
echo "  or use: cd ../ipvs-builtin-linux-lb && sudo ./test-distribution.sh 5"
echo ""
echo "Each curl should print one line per TCP packet to port 80."
echo "──────────────────────────────────────────────────────────"