#!/bin/bash
# Read interface names from config.yaml
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$SCRIPT_DIR/../../config.yaml"

NIC1=$(grep '^network_interface1:' "$CONFIG" | awk '{print $2}')
NIC2=$(grep '^network_interface2:' "$CONFIG" | awk '{print $2}')

if [ -z "$NIC1" ] || [ -z "$NIC2" ]; then
    echo "ERROR: Could not read interface names from $CONFIG"
    exit 1
fi

echo "[*] Configuring interfaces: $NIC1, $NIC2"

# Generate interface configs from config.yaml values
printf "auto %s\niface %s inet manual\n    up ifconfig \$IFACE up\n" "$NIC1" "$NIC1" > "/etc/network/interfaces.d/$NIC1"
printf "auto %s\niface %s inet manual\n    up ifconfig \$IFACE up\n" "$NIC2" "$NIC2" > "/etc/network/interfaces.d/$NIC2"

# Generate NetworkManager unmanaged devices config
printf "[keyfile]\nunmanaged-devices=interface-name:%s,%s\n" "$NIC1" "$NIC2" > /etc/NetworkManager/conf.d/99-unmanaged-devices.conf

systemctl daemon-reload
systemctl enable dolospy.service
