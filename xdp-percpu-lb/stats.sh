#!/bin/bash
# stats.sh — Phase 09: per-backend packets/bytes/rate from PERCPU_ARRAY

PIN_DIR="/sys/fs/bpf/xdp-lb"

for m in backend_stats backend_count rr_counter; do
    [ -e "$PIN_DIR/$m" ] || { echo "[!] $m not pinned — run loader.sh first"; exit 1; }
done

# Read PERCPU_ARRAY: sum packets and bytes across all CPU slots per backend.
# bpftool PERCPU_ARRAY JSON shape (with BTF):
# [
#   {
#     "key": 0,
#     "values": [
#       {"cpu": 0, "value": {"packets": 142, "bytes": 18632}},
#       {"cpu": 1, "value": {"packets": 139, "bytes": 18243}},
#       ...
#     ]
#   },
#   ...
# ]
read_stats() {
    sudo bpftool map dump pinned "$PIN_DIR/backend_stats" --json 2>/dev/null \
    | python3 -c "
import sys, json
entries = json.load(sys.stdin)
for e in entries:
    f = e.get('formatted', e)
    idx = f.get('key', 0)
    values = f.get('values', [])
    pkts  = 0
    bytes_ = 0
    for cpu_entry in values:
        v = cpu_entry.get('value', {})
        if isinstance(v, dict):
            pkts   += v.get('packets', 0)
            bytes_ += v.get('bytes',   0)
    print(idx, pkts, bytes_)
"
}

read_backends() {
    sudo bpftool map dump pinned "$PIN_DIR/backends" --json 2>/dev/null \
    | python3 -c "
import sys, json, socket, struct

def ip(n):
    return socket.inet_ntoa(struct.pack('<I', n))

entries = json.load(sys.stdin)
for e in entries:
    f = e.get('formatted', {})
    k = f.get('key', 0)
    v = f.get('value', {})
    if not v: continue
    print(k, ip(v.get('ip', 0)))
"
}

read_rr() {
    sudo bpftool map dump pinned "$PIN_DIR/rr_counter" --json 2>/dev/null \
    | python3 -c "
import sys, json
e = json.load(sys.stdin)
f = e[0].get('formatted', e[0])
v = f.get('value', f) if isinstance(f, dict) else f
print(int(v))
" 2>/dev/null || echo 0
}

echo "Phase 09 stats  (Ctrl-C to stop)"
echo ""

declare -A PREV_PKTS
declare -A PREV_BYTES

while true; do
    RR=$(read_rr)

    printf "%s  total_connections=%s\n" "$(date '+%H:%M:%S')" "$RR"
    printf "  %-6s %-16s %-12s %-10s %-12s %-10s\n" \
        "SLOT" "IP" "PACKETS" "PKT/s" "BYTES" "B/s"
    echo "  ──────────────────────────────────────────────────────────────"

    # Build backend IP lookup: idx → ip
    declare -A BE_IP
    while read idx ip; do
        BE_IP[$idx]="$ip"
    done < <(read_backends)

    while read idx pkts bytes; do
        ip="${BE_IP[$idx]:-?}"
        prev_p="${PREV_PKTS[$idx]:-0}"
        prev_b="${PREV_BYTES[$idx]:-0}"
        delta_p=$(( pkts  - prev_p ))
        delta_b=$(( bytes - prev_b ))

        printf "  %-6s %-16s %-12s %-10s %-12s %-10s\n" \
            "[$idx]" "$ip" "$pkts" "$delta_p" "$bytes" "$delta_b"

        PREV_PKTS[$idx]=$pkts
        PREV_BYTES[$idx]=$bytes
    done < <(read_stats)

    unset BE_IP
    declare -A BE_IP

    echo ""
    sleep 2
done