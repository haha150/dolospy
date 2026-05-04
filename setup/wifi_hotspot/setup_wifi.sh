#!/bin/bash
# Optional WiFi hotspot setup for DolosPy
# Run this AFTER setup.sh if your device has a WiFi interface (e.g. Pi 5)
# Creates a hidden WPA2 AP on wlan0 (SSID: Deskjet) for local SSH backup access
#
# Usage: sudo bash setup_wifi.sh

set -e

WLAN_IF="wlan0"

# check if wlan0 exists
if [ ! -d "/sys/class/net/$WLAN_IF" ]; then
    echo "ERROR: $WLAN_IF not found. No WiFi interface on this device."
    exit 1
fi

echo "[*] Installing hostapd and udhcpd..."
apt --assume-yes install hostapd udhcpd

echo "[*] Copying WiFi AP config files..."
cp ./etc_hostapd_hostapd.conf /etc/hostapd/hostapd.conf
cp ./etc_default_hostapd /etc/default/hostapd
cp ./etc_udhcpd.conf /etc/udhcpd.conf
cp ./etc_default_udhcpd /etc/default/udhcpd
cp ./etc_network_interfaces.d_wlan0 /etc/network/interfaces.d/wlan0

# udhcpd must start after hostapd
mkdir -p /etc/systemd/system/udhcpd.service.d
cp ./etc_systemd_system_udhcpd.service.d_override.conf /etc/systemd/system/udhcpd.service.d/override.conf

echo "[*] Adding wlan0 to NetworkManager unmanaged devices..."
# update the unmanaged-devices line to include wlan0 if not already there
NM_CONF="/etc/NetworkManager/conf.d/99-unmanaged-devices.conf"
if grep -q "wlan0" "$NM_CONF" 2>/dev/null; then
    echo "    wlan0 already in unmanaged list"
else
    # append wlan0 to whatever interfaces are already listed
    sed -i '/^unmanaged-devices=/ s/$/,wlan0/' "$NM_CONF"
    echo "    added wlan0 to unmanaged list"
fi

echo "[*] Enabling hostapd and udhcpd services..."
systemctl daemon-reload
systemctl unmask hostapd 2>/dev/null || true
systemctl enable hostapd
systemctl enable udhcpd

echo ""
echo "WiFi hotspot configured!"
echo "  SSID:       Deskjet (hidden network)"
echo "  Password:   Password1"
echo "  Pi IP:      172.31.255.1"
echo "  DHCP pool:  172.31.255.10 - 172.31.255.254"
echo ""
echo "CHANGE THE SSID AND PASSWORD in /etc/hostapd/hostapd.conf before deploying!"
echo "Connect to the hidden network, then SSH to 172.31.255.1"
echo ""
echo "Services will start on next reboot, or start now with:"
echo "  sudo systemctl start hostapd && sudo systemctl start udhcpd"
