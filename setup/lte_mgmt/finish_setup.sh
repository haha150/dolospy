#!/bin/bash
# Read interface names from config.yaml
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$SCRIPT_DIR/../../config.yaml"

NIC1=$(grep '^network_interface1:' "$CONFIG" | awk '{print $2}')
NIC2=$(grep '^network_interface2:' "$CONFIG" | awk '{print $2}')
SPOOF_MAC=$(grep '^spoof_mac:' "$CONFIG" | awk '{print $2}' | tr -d '"')

if [ -z "$NIC1" ] || [ -z "$NIC2" ]; then
    echo "ERROR: Could not read interface names from $CONFIG"
    exit 1
fi

echo "[*] Configuring interfaces: $NIC1, $NIC2"

# Derive a second MAC by incrementing the last byte
if [ -n "$SPOOF_MAC" ]; then
    LAST_BYTE=$(echo "$SPOOF_MAC" | awk -F: '{print $6}')
    NEXT_BYTE=$(printf '%02x' $(( 0x$LAST_BYTE + 1 )))
    SPOOF_MAC2=$(echo "$SPOOF_MAC" | sed "s/:${LAST_BYTE}$/:${NEXT_BYTE}/")
    echo "[*] Spoofing MACs: $NIC1=$SPOOF_MAC  $NIC2=$SPOOF_MAC2"
    HW1="    hwaddress ether $SPOOF_MAC\n"
    HW2="    hwaddress ether $SPOOF_MAC2\n"
else
    echo "[*] No spoof_mac in config — using hardware MACs"
    HW1=""
    HW2=""
fi

# Generate interface configs from config.yaml values
printf "auto %s\niface %s inet manual\n${HW1}    up ifconfig \$IFACE up\n" "$NIC1" "$NIC1" > "/etc/network/interfaces.d/$NIC1"
printf "auto %s\niface %s inet manual\n${HW2}    up ifconfig \$IFACE up\n" "$NIC2" "$NIC2" > "/etc/network/interfaces.d/$NIC2"

# Generate NetworkManager unmanaged devices config
printf "[keyfile]\nunmanaged-devices=interface-name:%s,%s\n" "$NIC1" "$NIC2" > /etc/NetworkManager/conf.d/99-unmanaged-devices.conf

systemctl daemon-reload
systemctl enable dolospy.service
