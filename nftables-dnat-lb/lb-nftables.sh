#!/bin/bash
# nftables DNAT-based load balancer using jhash for stable backend selection.

set -e

LB_NS="lb"
VIP="10.0.0.5"
VPORT="80"

BACKENDS=("10.0.0.11" "10.0.0.12" "10.0.0.13")

echo "[+] Configuring nftables in $LB_NS"

sudo ip netns exec "$LB_NS" sysctl -w net.ipv4.ip_forward=1 > /dev/null

sudo ip netns exec "$LB_NS" nft flush ruleset

N=${#BACKENDS[@]}

# Build two separate maps — one for IP, one for port
IP_MAP=""
PORT_MAP=""
for i in "${!BACKENDS[@]}"; do
    [ -n "$IP_MAP" ] && IP_MAP+=", "
    [ -n "$PORT_MAP" ] && PORT_MAP+=", "
    IP_MAP+="$i : ${BACKENDS[$i]}"
    PORT_MAP+="$i : $VPORT"
done

sudo ip netns exec "$LB_NS" nft -f - <<EOF
table ip lb {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        tcp dport $VPORT dnat to \
            jhash ip saddr . tcp sport mod $N map { $IP_MAP } \
            : \
            jhash ip saddr . tcp sport mod $N map { $PORT_MAP }
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        tcp dport $VPORT masquerade
    }
}
EOF

echo "[✓] nftables LB ready"
echo "    Show ruleset: sudo ip netns exec lb nft list ruleset"