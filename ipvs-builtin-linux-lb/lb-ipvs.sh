#!/bin/bash
# IPVS-based load balancer with NAT mode.

set -e

LB_NS="lb"
VIP="10.0.0.5"
VPORT="80"
SCHEDULER="${1:-rr}"     # rr, wrr, lc, sh, dh — pass as arg

BACKENDS=(
    "10.0.0.11"
    "10.0.0.12"
    "10.0.0.13"
)

echo "[+] Configuring IPVS in $LB_NS (scheduler: $SCHEDULER)"

# Enable IP forwarding inside the lb netns
sudo ip netns exec "$LB_NS" sysctl -w net.ipv4.ip_forward=1 > /dev/null

# IPVS NAT mode relies on conntrack to track the connection so the MASQUERADE rule in POSTROUTING can rewrite the source on the way back.
sudo ip netns exec "$LB_NS" sysctl -w net.ipv4.vs.conntrack=1 > /dev/null 2>&1 || true

# enable masquerading for the VIP subnet so backends can reply to the LB, not the client
sudo ip netns exec "$LB_NS" iptables -t nat -A POSTROUTING -j MASQUERADE

# Wipe any existing IPVS config
sudo ip netns exec "$LB_NS" ipvsadm -C

# Create the virtual service
sudo ip netns exec "$LB_NS" ipvsadm -A -t "$VIP:$VPORT" -s "$SCHEDULER"

# Add each backend as a real server in NAT mode (-m)
for BACKEND in "${BACKENDS[@]}"; do
    sudo ip netns exec "$LB_NS" ipvsadm -a -t "$VIP:$VPORT" -r "$BACKEND:$VPORT" -m
    echo "    added backend $BACKEND"
done

echo "[✓] IPVS LB ready. From client: curl http://$VIP/"
echo "    Show state: sudo ip netns exec lb ipvsadm -L -n"