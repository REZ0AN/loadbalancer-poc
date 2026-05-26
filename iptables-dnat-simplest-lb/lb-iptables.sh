#!/bin/bash
# iptables DNAT-based load balancer.
# Run inside the lb namespace via this script (it handles netns entry).

set -e

LB_NS="lb"
VIP="10.0.0.5"
VPORT="80"

BACKENDS=(
    "10.0.0.11"
    "10.0.0.12"
    "10.0.0.13"
)

echo "[+] Configuring iptables DNAT in $LB_NS"

# 1. Enable IP forwarding inside the lb netns
sudo ip netns exec "$LB_NS" sysctl -w net.ipv4.ip_forward=1 > /dev/null

# 2. Flush any existing rules
sudo ip netns exec "$LB_NS" iptables -t nat -F
sudo ip netns exec "$LB_NS" iptables -F

# 3. Round-robin DNAT using the statistic module
#    Each rule has a 1/N chance of matching, in order:
#    - Rule 1: 1/3 chance → b1
#    - Rule 2: 1/2 chance of what's left → b2
#    - Rule 3: catches the rest → b3
N=${#BACKENDS[@]}
for i in "${!BACKENDS[@]}"; do
    BACKEND="${BACKENDS[$i]}"
    REMAINING=$((N - i))

    if [ $REMAINING -gt 1 ]; then
        # Probabilistic distribution
        sudo ip netns exec "$LB_NS" iptables -t nat -A PREROUTING \
            -p tcp --dport "$VPORT" \
            -m statistic --mode nth --every $REMAINING --packet 0 \
            -j DNAT --to-destination "$BACKEND:$VPORT"
        echo "    [rule $((i+1))/$N] 1/$REMAINING → $BACKEND"
    else
        # Last backend: catch-all
        sudo ip netns exec "$LB_NS" iptables -t nat -A PREROUTING \
            -p tcp --dport "$VPORT" \
            -j DNAT --to-destination "$BACKEND:$VPORT"
        echo "    [rule $((i+1))/$N] default → $BACKEND"
    fi
done

# 4. SNAT/MASQUERADE on the way out so backends reply to the LB, not the client
#    Otherwise the client gets a reply from a "stranger" (the backend IP) and rejects it
sudo ip netns exec "$LB_NS" iptables -t nat -A POSTROUTING \
    -p tcp --dport "$VPORT" -j MASQUERADE

echo "[✓] iptables LB ready. From client: curl http://$VIP/"