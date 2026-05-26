#!/bin/bash
sudo ip netns exec lb ipvsadm -C
sudo ip netns exec lb iptables -t nat -F