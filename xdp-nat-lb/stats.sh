#!/bin/bash

PIN_DIR="/sys/fs/bpf/xdp-lb"

for m in rr_counter backend_count; do
    [ -e "$PIN_DIR/$m" ] || { echo "[!] $m not pinned — run loader.sh first"; exit 1; }
done

read_map_value() {
    local path=$1
    sudo bpftool map dump pinned "$path" --json 2>/dev/null \
        | python3 -c "
import sys, json
e = json.load(sys.stdin)
f = e[0].get('formatted', e[0])
v = f.get('value', f) if isinstance(f, dict) else f
print(int(v))
" 2>/dev/null || echo 0
}

echo "XDP NAT LB stats  (Ctrl-C to stop)"
echo ""
printf "%-10s  %-14s  %-10s\n" "TIME" "CONNECTIONS" "BACKENDS"
echo "────────────────────────────────────────"

PREV=0
while true; do
    RR=$(read_map_value "$PIN_DIR/rr_counter")
    N=$(read_map_value "$PIN_DIR/backend_count")
    DELTA=$(( RR - PREV ))
    printf "%-10s  %-8s (+%-4s)  %-10s\n" \
        "$(date '+%H:%M:%S')" "$RR" "$DELTA" "$N"
    PREV=$RR
    sleep 2
done