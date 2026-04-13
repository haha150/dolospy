#!/bin/bash
# Restart DolosPy cleanly without losing network access
# Usage: sudo bash restart.sh

iptables -F && iptables -t nat -F && iptables -t mangle -F && iptables -P OUTPUT ACCEPT
ebtables -F && ebtables -t nat -F && ebtables -P OUTPUT ACCEPT
arptables -F && arptables -P OUTPUT ACCEPT
tmux kill-session -t dolospy 2>/dev/null
pkill -f "python3.*dolos.py" 2>/dev/null
ip link set mibr down 2>/dev/null
brctl delbr mibr 2>/dev/null
sleep 1
cd /root/dolospy
tmux new -s dolospy -d "./venv/bin/python3 dolos.py"
echo "DolosPy restarted"
