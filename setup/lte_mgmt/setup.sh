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

#disable services that leak traffic onto the bridge/corp network
systemctl disable --now systemd-timesyncd 2>/dev/null || true
systemctl disable --now systemd-resolved 2>/dev/null || true
systemctl disable --now apt-daily.timer 2>/dev/null || true
systemctl disable --now apt-daily-upgrade.timer 2>/dev/null || true
systemctl disable --now unattended-upgrades 2>/dev/null || true

#force predictable interface names
ln -sf /dev/null /etc/systemd/network/99-default.link

#set resolv.conf to a safe default (LTE path, not corp network)
# systemd-resolved owns the /etc/resolv.conf symlink — remove it after the service is stopped
rm -f /etc/resolv.conf
echo 'nameserver 8.8.8.8' > /etc/resolv.conf
chattr +i /etc/resolv.conf

#set up configs
cp ./config.yaml ../../
cp ./dolospy.service /etc/systemd/system/dolospy.service
cp ./etc_dhcp_dhclient-usb0.conf /etc/dhcp/dhclient-usb0.conf

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
