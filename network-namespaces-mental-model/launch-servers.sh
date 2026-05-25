#!/bin/bash

# Launches simple HTTP servers in the backend namespaces. Run after bring-up.sh.
for backend in b1 b2 b3; do
    sudo ip netns exec "$backend" bash <<EOF
mkdir -p /tmp/$backend
MY_IP=\$(ip -o -4 addr show dev veth-$backend | awk '{print \$4}' | cut -d/ -f1)
echo "Hello from $backend (\$MY_IP)" > /tmp/$backend/index.html
cd /tmp/$backend
nohup python3 -m http.server 80 > /tmp/$backend/server.log 2>&1 &
disown
EOF
done

sleep 2
echo "[*] Checking listeners:"
for backend in b1 b2 b3; do
    echo -n "  $backend: "
    sudo ip netns exec "$backend" ss -tlnp 2>/dev/null | grep :80 || echo "NOT LISTENING"
done