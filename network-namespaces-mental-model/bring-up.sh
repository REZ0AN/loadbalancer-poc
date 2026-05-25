#!/bin/bash
# Sets up the namespace topology.
# Run with sudo.

set -e   # fail on first error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/topology.sh"

echo "[+] Creating bridge $BRIDGE"
ip link add "$BRIDGE" type bridge
ip link set "$BRIDGE" up 

## constructing bridge ip by subnet
NETWORK="${SUBNET%%/*}"
BRIDGE_IP="${NETWORK%.*}.1"    

# Give the bridge an IP so the host can reach the namespaces too (handy for debugging)
ip addr add "$BRIDGE_IP/24" dev "$BRIDGE"

for entry in "${NODES[@]}"; do
    NS=$(echo "$entry" | awk '{print $1}')
    IP=$(echo "$entry" | awk '{print $2}')

    VETH_NS="veth-$NS"        # the end inside the netns
    VETH_BR="br-$NS"          # the end on the bridge (max 15 chars!)

    echo "[+] Creating netns $NS ($IP)"

    # 1. Create the namespace
    ip netns add "$NS"

    # 2. Create the veth pair (two ends of a virtual cable)
    ip link add "$VETH_NS" type veth peer name "$VETH_BR"

    # 3. Attach the "bridge end" to the bridge
    ip link set "$VETH_BR" master "$BRIDGE"
    ip link set "$VETH_BR" up

    # 4. Move the "namespace end" into the netns
    ip link set "$VETH_NS" netns "$NS"

    # 5. Inside the netns: bring up lo, configure IP, bring up veth
    ip netns exec "$NS" ip link set lo up
    ip netns exec "$NS" ip addr add "$IP/24" dev "$VETH_NS"
    ip netns exec "$NS" ip link set "$VETH_NS" up

    # 6. Default route inside the netns -> bridge
    ip netns exec "$NS" ip route add default via "$BRIDGE_IP"
done

echo ""
echo "[✓] Topology up. Try: sudo ip netns exec client ping -c 2 10.0.0.11"