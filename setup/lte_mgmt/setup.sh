#!/bin/bash

#update repos
apt update
#update os
apt -y upgrade

#install deps required for DolosPy
apt --assume-yes install python3 python3-pip python3-venv bridge-utils iptables ebtables arptables network-manager libpcap-dev

#install Tailscale
curl -fsSL https://tailscale.com/install.sh | sh
systemctl enable tailscaled

#install isc-dhcp-client for USB tethering (dhclient usb0)
apt --assume-yes install isc-dhcp-client

#install other standard software to make life easier
apt --assume-yes install vim tmux screen zip unzip dnsutils curl

#force predictable interface names
ln -sf /dev/null /etc/systemd/network/99-default.link

#set up configs
cp ./config.yaml ../../
cp ./dolospy.service /etc/systemd/system/dolospy.service

#reload the daemons
systemctl daemon-reload

#install Python deps in a venv
cd ../../
python3 -m venv venv
./venv/bin/pip install -r requirements.txt

echo ""
echo "All set up! Check that your callback is working"
echo "SERIOUSLY test this to make sure you don't brick the box and have to start over"
echo "Run 'tailscale up' now to authenticate this device to your tailnet"
echo "Then you can run 'bash finish_setup.sh' to autorun the attack"
