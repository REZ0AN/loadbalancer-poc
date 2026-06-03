#!/bin/bash
# Shared definitions — sourced by other scripts. Don't run directly.

BRIDGE="lb0"
SUBNET="10.0.0.0/24"

# Format: "<netns_name> <ip_in_subnet>"
NODES=(
    "client 10.0.0.10"
    "clientX 10.0.0.20"
    "lb     10.0.0.5"
    "b1     10.0.0.11"
    "b2     10.0.0.12"
    "b3     10.0.0.13"
)