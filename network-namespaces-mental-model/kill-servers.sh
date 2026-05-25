#!/bin/bash

# Kills the servers launched by launch-servers.sh. Idempotent.
sudo pkill -f "python3 -m http.server" 2>/dev/null