#!/bin/bash

# This script flushes the iptables rules in the lb namespace, 
# effectively "tearing down" the load balancer configuration.
sudo ip netns exec lb iptables -t nat -F
sudo ip netns exec lb iptables -F