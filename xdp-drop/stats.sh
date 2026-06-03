#!/bin/bash

PIN_DIR="/sys/fs/bpf/xdp-lb"
MAP_PATH="$PIN_DIR/pkt_count"

if [ ! -e "$MAP_PATH" ]; then
    echo "[!] Map not found at $MAP_PATH — run loader.sh first."
    exit 1
fi

echo "Reading $MAP_PATH  (Ctrl-C to stop)"
echo ""
printf "%-10s  %-16s  %-16s\n" "TIME" "PASSED" "DROPPED"
echo "────────────────────────────────────────────"

PREV_PASS=0
PREV_DROP=0

while true; do
    # bpftool --json on this kernel emits both a raw byte array AND a
    # "formatted" object with the decoded integer value.
    # We read from "formatted" to avoid byte-reversal entirely.
    #
    # JSON shape on this machine:
    # [
    #   {"key":[...],"value":[...],"formatted":{"key":0,"value":42}},
    #   {"key":[...],"value":[...],"formatted":{"key":1,"value":7}}
    # ]

    read PASS DROP < <(
        sudo bpftool map dump pinned "$MAP_PATH" --json 2>/dev/null \
        | python3 -c "
import sys, json
entries = json.load(sys.stdin)
counts = {}
for e in entries:
    # 'formatted' key holds the decoded integers — use it when present,
    # fall back to raw 'key'/'value' (int) for older bpftool versions.
    if 'formatted' in e:
        k = e['formatted']['key']
        v = e['formatted']['value']
    else:
        k = e['key']
        v = e['value']
    counts[k] = v
print(counts.get(0, 0), counts.get(1, 0))
"
    )

    D_PASS=$(( PASS - PREV_PASS ))
    D_DROP=$(( DROP - PREV_DROP ))

    printf "%-10s  %-8d  (+%-5d)   %-8d  (+%-5d)\n" \
        "$(date '+%H:%M:%S')" "$PASS" "$D_PASS" "$DROP" "$D_DROP"

    PREV_PASS=$PASS
    PREV_DROP=$DROP
    sleep 2
done