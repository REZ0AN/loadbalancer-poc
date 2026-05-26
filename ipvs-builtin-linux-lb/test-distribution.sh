#!/bin/bash
# Send N requests from client to VIP and report the distribution.

set -e

VIP="10.0.0.5"
N="${1:-30}"
CONCURRENCY="${2:-1}"

echo "[*] Sending $N requests to http://$VIP/ (concurrency=$CONCURRENCY)"

if [ "$CONCURRENCY" -eq 1 ]; then
    # Sequential
    for i in $(seq 1 "$N"); do
        sudo ip netns exec client curl -s --max-time 2 "http://$VIP/" || echo "FAIL"
    done | sort | uniq -c | sort -rn
else
    # Concurrent — useful for testing flow stickiness under load
    seq 1 "$N" | xargs -P "$CONCURRENCY" -I{} sudo ip netns exec client \
        curl -s --max-time 2 "http://$VIP/" | sort | uniq -c | sort -rn
fi