#!/bin/bash
# stats.sh — Phase 08: flow table viewer + rr_counter

PIN_DIR="/sys/fs/bpf/xdp-lb"

for m in rr_counter flow_table; do
    [ -e "$PIN_DIR/$m" ] || { echo "[!] $m not pinned — run loader.sh first"; exit 1; }
done

echo "Phase 08 stats  (Ctrl-C to stop)"
echo ""

PREV=0
while true; do
    RR=$(sudo bpftool map dump pinned "$PIN_DIR/rr_counter" --json 2>/dev/null \
        | python3 -c "
import sys, json
e = json.load(sys.stdin)
f = e[0].get('formatted', e[0])
v = f.get('value', f) if isinstance(f, dict) else f
print(v)
" 2>/dev/null || echo 0)

    FLOWS=$(sudo bpftool map dump pinned "$PIN_DIR/flow_table" --json 2>/dev/null \
        | python3 -c "
import sys, json
print(len(json.load(sys.stdin)))
" 2>/dev/null || echo 0)

    DELTA=$(( RR - PREV ))
    printf "%s  connections=%-6s (+%-3s)  active_flows=%-6s\n" \
        "$(date '+%H:%M:%S')" "$RR" "$DELTA" "$FLOWS"

    if [ "$DELTA" -gt 0 ] && [ "$FLOWS" -gt 0 ]; then
        sudo bpftool map dump pinned "$PIN_DIR/flow_table" --json 2>/dev/null \
        | python3 -c "
import sys, json, socket, struct

def ip(n):
    # bpftool decodes __u32 as a host-endian integer.
    # On a little-endian host, pack as '<I' to recover the original bytes,
    # then inet_ntoa reads them in network order (big-endian = natural order).
    return socket.inet_ntoa(struct.pack('<I', n))

entries = json.load(sys.stdin)
for e in entries:
    f = e.get('formatted', {})
    k = f.get('key', {})
    v = f.get('value', {})
    if not k or not v:
        continue
    # key fields match struct flow_key: { ip, port, pad }
    key_ip   = k.get('ip', 0)
    key_port = k.get('port', 0)
    be_ip    = v.get('backend_ip', 0)
    cl_ip    = v.get('client_ip', 0)
    print(f'  key=({ip(key_ip):<14} port={key_port:<6})  client={ip(cl_ip):<14} → backend={ip(be_ip)}')
" 2>/dev/null || true
        echo ""
    fi

    PREV=$RR
    sleep 2
done