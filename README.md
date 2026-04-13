# DolosPy

A Python NAC (Network Access Control) bypass tool. Creates a transparent Layer 2 bridge between two network interfaces, passively discovers the gateway and client via ARP mismatch detection, and applies ebtables/iptables/arptables rules to masquerade as the client on the network.

Re-implementation of [DolosJS](https://github.com/xslem/dolosjs) in Python with improvements: scapy-based packet parsing, input validation, dynamic interface management, auto DHCP probing, NBNS/LLMNR/mDNS hostname discovery, and a modern web UI.

## How It Works

```
[Switch] ──eth0──┐                    ┌── usb0 (LTE USB tethering)
                  ├── mibr (bridge) ──┤         └── Tailscale SSH
[Victim] ──eth1──┘                    └── wlan0 (optional WiFi hotspot)
```

1. A transparent bridge (`mibr`) is created between `eth0` and `eth1`
2. All traffic passes through unmodified — the victim and switch don't know the bridge exists
3. ARP packets are sniffed to build a MAC→IP table
4. IP packets are compared against the ARP table — when the Ethernet source MAC maps to a different IP than the IP header claims, the gateway is identified (it's forwarding someone else's traffic)
5. Once gateway and client are identified, ebtables/iptables rules masquerade bridge traffic as the client toward the switch and as the gateway toward the client
6. 802.1X EAPOL frames are forwarded transparently so the victim's authentication stays active
7. The operator accesses the bridge device remotely via Tailscale over LTE

## Requirements

### Hardware

- Single-board computer with **2 Ethernet ports** (e.g., NanoPi R2S, Raspberry Pi 5 with USB Ethernet adapter)
- **LTE USB modem** or phone with USB tethering for remote management
- Two Ethernet cables

### Software

- Debian/Ubuntu-based Linux (tested on Armbian, Raspberry Pi OS)
- Python 3.10+
- Root access

## Installation

### 1. Clone and run setup

```bash
git clone <repo-url> /root/tools/dolospy
cd /root/tools/dolospy/setup/lte_mgmt
sudo bash setup.sh
```

This installs all dependencies: Python 3, pip, bridge-utils, iptables, ebtables, arptables, Tailscale, isc-dhcp-client, tmux, and the Python packages (fastapi, uvicorn, python-socketio, scapy, pyyaml).

### 2. Authenticate Tailscale

```bash
sudo tailscale up --ssh
```

Follow the URL to authenticate your device to your Tailnet. This only needs to be done once — Tailscale auto-reconnects on subsequent boots.

### 3. Test remote access

Verify you can SSH to the device over Tailscale before proceeding:

```bash
ssh root@<tailscale-ip>
```

### 4. Enable boot persistence

```bash
cd /root/tools/dolospy/setup/lte_mgmt
sudo bash finish_setup.sh
```

This copies interface configs, adds eth0/eth1 to the NetworkManager unmanaged list, and enables the `dolos_service` init script.

### 5. (Optional) WiFi hotspot

If your device has a WiFi interface and you want a local backup SSH path:

```bash
cd /root/tools/dolospy/setup/wifi_hotspot
sudo bash setup_wifi.sh
```

This creates a hidden WiFi AP (`SSID: Deskjet`, `Password: Password1`) on `wlan0` with IP `172.31.255.1`. **Change the SSID and password** in `/etc/hostapd/hostapd.conf` before deploying.

Connect to the hidden network and SSH to `172.31.255.1`.

## Configuration

Edit `config.yaml` (or let `setup.sh` copy the default from `setup/lte_mgmt/config.yaml`):

```yaml
network_interface1: eth0        # first bridge NIC (order doesn't matter)
network_interface2: eth1        # second bridge NIC
management_subnet: "172.31.255.0/24"  # subnet for WiFi AP / management traffic NAT
replace_default_route: false    # keep false for LTE — don't replace the LTE route
run_command_on_success: false   # run a command after spoofing is configured
autorun_command: ""             # command to run on success
```

**`replace_default_route`**: Set to `false` when using LTE for remote access (default). Set to `true` if the bridge is your only network path and you want the default route to go through the victim's gateway.

**`management_subnet`**: Used in iptables SNAT rules so traffic from the management network (WiFi AP, Tailscale) is properly NAT'd as the client's IP when exiting through the bridge.

**Interface order**: It does not matter which device (switch or victim) is connected to `eth0` vs `eth1`. The bridge detects this automatically.

## Usage

### Manual start

```bash
sudo /root/tools/dolospy/venv/bin/python3 /root/tools/dolospy/dolos.py
```

### Auto-start (after finish_setup.sh)

The service starts automatically on boot. DolosPy runs in a tmux session:

```bash
sudo tmux attach -t dolospy
```

### Web UI

Access the dashboard at `http://<device-ip>:4444` (via Tailscale IP or WiFi hotspot IP).

The web UI shows:
- **Status badge**: Waiting (orange) → Ready (green) when bypass is active
- **Connection indicator**: green/red dot showing Socket.IO connection state
- **Uptime counter**: time since bridge started
- **Host/Client card**: discovered client IP, MAC, hostname, TTL
- **Gateway/Network card**: gateway IP, MAC, subnet mask, domain, DHCP server, NTP server
- **DNS Servers table**: discovered DNS servers
- **ARP Neighbors table**: all MAC/IP pairs seen on the bridge, with vendor lookup
- **Event Log**: real-time log of bridge events

### Web UI Buttons

| Button | Action |
|--------|--------|
| **Lookup Hostname** | Reverse DNS lookup on the client IP |
| **DHCP Probe** | Send a spoofed DHCP Discover to provoke DHCP info |
| **Allow Internet** | Add a default route through the bridge (routes your traffic through the victim's gateway) |
| **Copy resolv.conf** | Copy discovered DNS config to clipboard |
| **View Log** | Open the current command log in a new tab |
| **Advertise Routes** | Tell Tailscale to advertise the discovered subnet to your Tailnet |
| **Flush & Shutdown** | Flush all rules, tear down bridge, and exit (with confirmation) |

### Keyboard Shortcuts

When running in a terminal (not tmux detached):

| Key | Action |
|-----|--------|
| `Ctrl+C` | Flush tables and shutdown |
| `a` | Allow internet traffic |
| `d` | Send DHCP probe |
| `i` | Print network info and ARP table as JSON |

## Deployment

### Physical setup

1. Plug LTE modem into USB
2. Connect one Ethernet cable from the **switch port** to `eth0` (or `eth1`)
3. Connect the other Ethernet cable from the **victim device** to `eth1` (or `eth0`)
4. Power on the bridge device

Order of eth0/eth1 does not matter.

### What happens on boot

1. Init script waits 10 seconds for hardware init
2. LTE USB interface (`usb0`) is brought up, `dhclient` gets an IP
3. Tailscale connects to your Tailnet
4. DolosPy starts in a tmux session
5. Bridge is created, traffic passthrough begins immediately
6. ARP/IP sniffing discovers gateway and client (typically within seconds)
7. Spoofing rules are applied automatically
8. If gateway not detected after 60 seconds, an automatic DHCP probe is sent
9. Web UI available on port 4444

### After bypass is active

- SSH via Tailscale for command-line access
- Web UI on port 4444 for monitoring
- Use "Allow Internet" to route your own traffic through the victim's gateway
- Use "Advertise Routes" to make the victim's subnet accessible from your Tailnet

## Teardown

### From web UI

Click **Flush & Shutdown** and confirm.

### From terminal

Press `Ctrl+C` or:

```bash
sudo /etc/init.d/dolos_service stop
```

### Full cleanup

To undo all setup and restore the device to stock:

```bash
# stop services
sudo /etc/init.d/dolos_service stop
sudo systemctl disable dolos_service

# remove init script
sudo rm /etc/init.d/dolos_service

# remove interface configs
sudo rm -f /etc/network/interfaces.d/eth0 /etc/network/interfaces.d/eth1
sudo rm -f /etc/NetworkManager/conf.d/99-unmanaged-devices.conf

# if WiFi hotspot was installed
sudo systemctl disable hostapd udhcpd
sudo rm -f /etc/hostapd/hostapd.conf /etc/network/interfaces.d/wlan0

# flush any remaining rules
sudo iptables -F && sudo iptables -t nat -F && sudo iptables -t mangle -F
sudo ebtables -F && sudo ebtables -t nat -F
sudo arptables -F

sudo reboot
```

## Project Structure

```
dolospy/
├── dolos.py                 # main entry point — FastAPI + Socket.IO web server
├── bridge_controller.py     # bridge lifecycle, iptables/ebtables/arptables rules
├── net_info.py              # packet sniffing state machine (gateway/TTL/DNS discovery)
├── arp_table.py             # ARP sniffer — maintains MAC→IP table
├── dhcp_probe.py            # sends spoofed DHCP Discover via scapy
├── mac_vendor.py            # MAC prefix → vendor name lookup
├── mac_to_vendor.json       # vendor database (43K entries)
├── config.yaml              # runtime config
├── requirements.txt         # Python dependencies
├── resources/
│   ├── templates/
│   │   └── index.html       # web UI dashboard
│   └── static/misc/
│       └── favicon.ico
├── setup/
│   ├── lte_mgmt/            # main setup (LTE + Tailscale)
│   │   ├── setup.sh         # install dependencies
│   │   ├── finish_setup.sh  # enable boot persistence
│   │   ├── config.yaml      # default config for LTE setup
│   │   ├── etc_init.d_dolos_service
│   │   ├── etc_network_interfaces.d_eth0
│   │   ├── etc_network_interfaces.d_eth1
│   │   └── etc_NetworkManager_conf.d_99-unmanaged-devices.conf
│   └── wifi_hotspot/         # optional WiFi AP setup
│       ├── setup_wifi.sh
│       ├── etc_hostapd_hostapd.conf
│       ├── etc_default_hostapd
│       ├── etc_udhcpd.conf
│       ├── etc_default_udhcpd
│       ├── etc_network_interfaces.d_wlan0
│       └── etc_systemd_system_udhcpd.service.d_override.conf
└── logs/                     # created at runtime
    ├── history.log           # persistent log (append)
    └── current.log           # current session log (overwritten each run)
```

## Troubleshooting

### Bridge not detecting gateway

- Ensure both Ethernet cables are connected and the victim device is generating traffic
- Check `tmux attach -t dolospy` for error messages
- Wait 60 seconds — an automatic DHCP probe will be sent
- Manually trigger a DHCP probe from the web UI or press `d`
- If the victim is idle (e.g., a printer), try printing a test page to generate traffic

### Tailscale not connecting

- Verify the LTE modem has a connection: `ping -I usb0 8.8.8.8`
- Check `tailscale status`
- Re-authenticate if needed: `tailscale up --ssh`

### Web UI not loading

- Verify dolospy is running: `pgrep -f dolos.py`
- Check port 4444 is listening: `ss -tlnp | grep 4444`
- Access via Tailscale IP, not the bridge IP

### WiFi hotspot not working

- Verify `wlan0` exists: `ip link show wlan0`
- Check hostapd status: `systemctl status hostapd`
- Check udhcpd status: `systemctl status udhcpd`
- On Pi 5, you may need to `sudo rfkill unblock wifi` first
