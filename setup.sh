#!/bin/bash
# Enable IPv4 forwarding
sudo sysctl -w net.ipv4.ip_forward=1
# Make it persistent
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.d/99-sysctl.conf
sudo sysctl --system
echo "IP forwarding enabled."