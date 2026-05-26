#!/bin/bash
# Tear down the nftables LB configuration.
sudo ip netns exec lb nft flush ruleset