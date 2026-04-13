"""Network information tracker.

Sniffs IP traffic on the bridge interface to discover:
  - Gateway IP / MAC  (via ARP-table vs IP-header mismatch)
  - Client  IP / MAC
  - Client TTL
  - DNS servers  (from port-53 traffic and DHCP options)
  - DHCP details (subnet mask, search domain, NTP, hostname …)

Improvements over the JS version:
  - Uses scapy for packet parsing — more reliable across device types
    (fixes issues with printers/IoT not being detected correctly).
  - Handles gratuitous ARP and ARP probes that low-traffic devices emit.
  - Explicitly filters the bridge's own MAC to never misidentify itself.
"""

import logging
import socket
import subprocess
import threading
from typing import Callable

from scapy.all import (
    BOOTP,
    DHCP,
    DNS,
    IP,
    UDP,
    Ether,
    NBNSQueryRequest,
    Raw,
    sniff,
)

from arp_table import ArpTable

log = logging.getLogger("dolos.net_info")


class NetInfo:
    def __init__(self, network_interface: str, bridge_mac: str = "00:01:01:01:01:01") -> None:
        self.network_interface = network_interface
        self.bridge_mac = bridge_mac.lower()
        self.arp_table = ArpTable(network_interface)

        # discovered values
        self.client_mac: str = ""
        self.client_ip: str = ""
        self.client_name: str = ""
        self.client_ttl: str = ""
        self.gateway_mac: str = ""
        self.gateway_ip: str = ""
        self.dns_servers: list[str] = []
        self.search_domain: str = ""
        self.subnet: str = ""
        self.subnet_mask: str = ""
        self.dhcp_server: str = ""
        self.ntp_server: str = ""
        self.kerberos_server: str = ""

        # sniff state machine: gateway → ttl → dns/dhcp
        self._phase: str = "gateway_search"
        self._stop_event = threading.Event()
        self._sniff_thread: threading.Thread | None = None

        # callbacks ── mirrors the EventEmitter pattern
        self._callbacks: dict[str, list[Callable]] = {
            "new_arp": [],
            "dns_update": [],
            "client_ip_mac_and_gateway_mac": [],
            "gateway_ip_mac_and_client_mac": [],
            "client_ttl": [],
            "network_update": [],
        }

        # wire ARP table events
        self.arp_table.on_arp_entry(self._on_arp_entry)

    # ── public API ───────────────────────────────────────────────────

    def on(self, event: str, callback: Callable) -> None:
        self._callbacks.setdefault(event, []).append(callback)

    def once(self, event: str, callback: Callable) -> None:
        """Register a callback that fires only once."""
        def wrapper(*a, **kw):
            try:
                self._callbacks[event].remove(wrapper)
            except ValueError:
                pass
            callback(*a, **kw)
        self._callbacks.setdefault(event, []).append(wrapper)

    def start(self) -> None:
        self.arp_table.start()
        self._sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._sniff_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self.arp_table.stop()

    def print_info(self) -> dict:
        return {
            "client_mac": self.client_mac,
            "client_ip": self.client_ip,
            "client_name": self.client_name,
            "client_ttl": self.client_ttl,
            "gateway_mac": self.gateway_mac,
            "gateway_ip": self.gateway_ip,
            "dns_servers": self.dns_servers,
            "subnet": self.subnet,
            "search_domain": self.search_domain,
            "subnet_mask": self.subnet_mask,
            "dhcp_server": self.dhcp_server,
            "ntp_server": self.ntp_server,
            "kerberos_server": self.kerberos_server,
        }

    def lookup_hostname(self) -> None:
        if self.client_name == "" and self.client_ip != "":
            try:
                hosts = socket.gethostbyaddr(self.client_ip)
                self.client_name = hosts[0]
                log.info("Hostname resolved: %s", self.client_name)
            except socket.herror as exc:
                log.warning("Reverse lookup failed: %s", exc)

    # ── internal event helpers ───────────────────────────────────────

    def _emit(self, event: str, data=None) -> None:
        for cb in list(self._callbacks.get(event, [])):
            try:
                cb(data)
            except Exception:
                log.exception("Error in %s callback", event)

    def _on_arp_entry(self, arp_info: dict) -> None:
        self._emit("new_arp", arp_info)

    def _update_value(self, key: str, value: str, message: str) -> bool:
        """Set *key* only if it is still empty (first-write-wins).
        Returns True if the value was actually written."""
        if getattr(self, key) != "" or value == "ff:ff:ff:ff:ff:ff":
            return False
        setattr(self, key, str(value))
        log.info("%s → %s = %s", message, key, value)
        self._emit("network_update")
        return True

    def _update_dns(self, server: str) -> None:
        server = str(server)
        if server not in self.dns_servers:
            self.dns_servers.append(server)
            log.info("DNS server discovered: %s", server)
            self._emit("dns_update", self.dns_servers)

    # ── sniffing ─────────────────────────────────────────────────────

    def _sniff_loop(self) -> None:
        log.info("IP sniffer starting on %s (phase: %s)", self.network_interface, self._phase)
        try:
            sniff(
                iface=self.network_interface,
                filter="ip",
                prn=self._dispatch,
                stop_filter=lambda _: self._stop_event.is_set(),
                store=False,
            )
        except Exception:
            log.exception("IP sniffer crashed")
        log.info("IP sniffer stopped")

    def _dispatch(self, pkt) -> None:
        if self._phase == "gateway_search":
            self._gateway_search(pkt)
        elif self._phase == "ttl_search":
            self._ttl_search(pkt)
        elif self._phase == "dns_search":
            self._dns_search(pkt)

    # ── phase 1: gateway search ──────────────────────────────────────

    def _is_multicast_ip(self, ip_str: str) -> bool:
        try:
            first_octet = int(ip_str.split(".")[0])
            return 224 <= first_octet <= 239
        except (ValueError, IndexError):
            return False

    def _on_different_bridge_ports(self, mac1: str, mac2: str) -> bool:
        """Check that two MACs were learned on different bridge ports.
        Returns True if they are on different ports (valid client/gateway pair).
        Returns False if either MAC is not in the bridge table (not physically attached)
        or if both are on the same port (both coming from the switch side)."""
        try:
            result = subprocess.run(
                ["brctl", "showmacs", self.network_interface],
                capture_output=True, text=True, timeout=5,
            )
            port_map = {}
            for line in result.stdout.strip().split("\n")[1:]:
                parts = line.split()
                if len(parts) >= 3 and parts[2] == "no":
                    port_map[parts[1].lower()] = parts[0]
            p1 = port_map.get(mac1.lower())
            p2 = port_map.get(mac2.lower())
            if p1 is None or p2 is None:
                log.debug("MAC not in bridge table: %s=%s, %s=%s", mac1, p1, mac2, p2)
                return False  # MAC not learned on bridge — not physically attached
            return p1 != p2
        except Exception:
            return True  # brctl failed — accept to avoid blocking detection

    def _gateway_search(self, pkt) -> None:
        if not pkt.haslayer(IP) or not pkt.haslayer(Ether):
            return

        ether = pkt[Ether]
        ip = pkt[IP]

        smac = ether.src.lower()
        dmac = ether.dst.lower()
        shost = ip.src
        dhost = ip.dst

        # skip our own traffic
        if smac == self.bridge_mac or dmac == self.bridge_mac:
            return

        # check source MAC against ARP table — mismatch means gateway
        if smac in self.arp_table.entries:
            if dmac != "ff:ff:ff:ff:ff:ff" and not self._is_multicast_ip(dhost):
                arp_ip = self.arp_table.entries[smac]
                if shost != arp_ip:
                    # verify client and gateway are on different bridge ports
                    if not self._on_different_bridge_ports(smac, dmac):
                        log.info("Skipping mismatch: %s and %s on same bridge port (not the real client)", smac, dmac)
                        return
                    log.info("Gateway detected (src mismatch): GW=%s/%s  Client=%s/%s", arp_ip, smac, dhost, dmac)
                    self._update_value("gateway_ip", arp_ip, "Found Gateway IP from ARP mismatch")
                    self._update_value("gateway_mac", smac, "Found Gateway MAC from ARP mismatch")
                    self._update_value("client_ip", dhost, "Found Client IP from ARP mismatch")
                    self._update_value("client_mac", dmac, "Found Client MAC from ARP mismatch")
                    self._emit("client_ip_mac_and_gateway_mac", self.print_info())
                    self._emit("gateway_ip_mac_and_client_mac", self.print_info())
                    self.client_mac = dmac
                    self._transition("ttl_search")
                    return

        # check dest MAC against ARP table
        if dmac in self.arp_table.entries:
            if dmac != "ff:ff:ff:ff:ff:ff" and not self._is_multicast_ip(dhost):
                arp_ip = self.arp_table.entries[dmac]
                if dhost != arp_ip:
                    # verify client and gateway are on different bridge ports
                    if not self._on_different_bridge_ports(dmac, smac):
                        log.info("Skipping mismatch: %s and %s on same bridge port (not the real client)", dmac, smac)
                        return
                    log.info("Gateway detected (dst mismatch): GW=%s/%s  Client=%s/%s", arp_ip, dmac, shost, smac)
                    self._update_value("gateway_ip", arp_ip, "Found Gateway IP from ARP mismatch")
                    self._update_value("gateway_mac", dmac, "Found Gateway MAC from ARP mismatch")
                    self._update_value("client_ip", shost, "Found Client IP from ARP mismatch")
                    self._update_value("client_mac", smac, "Found Client MAC from ARP mismatch")
                    self._update_value("client_ttl", str(ip.ttl), "Found Client TTL from ARP mismatch")
                    self._emit("client_ip_mac_and_gateway_mac", self.print_info())
                    self._emit("gateway_ip_mac_and_client_mac", self.print_info())
                    self._emit("client_ttl", self.print_info())
                    self._transition("dns_search")
                    return

    # ── phase 2: TTL search ──────────────────────────────────────────

    def _ttl_search(self, pkt) -> None:
        if not pkt.haslayer(Ether) or not pkt.haslayer(IP):
            return
        ether = pkt[Ether]
        ip = pkt[IP]
        if ether.src.lower() == self.client_mac:
            self._update_value("client_ttl", str(ip.ttl), "Found Client TTL from client packet")
            self._emit("client_ttl", self.print_info())
            self._transition("dns_search")

    # ── phase 3: DNS / DHCP search ───────────────────────────────────

    def _dns_search(self, pkt) -> None:
        if not pkt.haslayer(IP) or not pkt.haslayer(UDP):
            return

        ether = pkt[Ether]
        ip = pkt[IP]
        udp = pkt[UDP]

        # DNS traffic
        if udp.dport == 53:
            log.info("DNS server found (dst): %s", ip.dst)
            self._update_dns(ip.dst)
        elif udp.sport == 53:
            log.info("DNS server found (src): %s", ip.src)
            self._update_dns(ip.src)

        # DHCP Request from client (port 67)
        if udp.dport == 67 and ether.src.lower() == self.client_mac:
            self._parse_dhcp_request(pkt)

        # DHCP Reply (port 68)
        if udp.dport == 68:
            self._parse_dhcp_reply(pkt)

        # NBNS name query (port 137) — many printers/IoT use this
        if (udp.sport == 137 or udp.dport == 137) and ether.src.lower() == self.client_mac:
            self._parse_nbns(pkt)

        # LLMNR (port 5355) — Windows devices
        if udp.dport == 5355 and ether.src.lower() == self.client_mac:
            self._parse_llmnr(pkt)

        # mDNS (port 5353) — Apple/Linux/IoT
        if udp.dport == 5353 and ether.src.lower() == self.client_mac:
            self._parse_mdns(pkt)

    def _parse_nbns(self, pkt) -> None:
        """Extract hostname from NetBIOS Name Service queries (UDP 137)."""
        try:
            if pkt.haslayer(NBNSQueryRequest):
                name = pkt[NBNSQueryRequest].QUESTION_NAME
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")
                name = name.strip()
                if name and name != "*":
                    self._update_value("client_name", name, "Found hostname from NBNS")
        except Exception:
            log.debug("NBNS parse error", exc_info=True)

    def _parse_llmnr(self, pkt) -> None:
        """Extract hostname from LLMNR queries (UDP 5355)."""
        try:
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                if dns.qr == 0 and dns.qdcount > 0:  # query
                    name = dns.qd.qname
                    if isinstance(name, bytes):
                        name = name.decode("utf-8", errors="replace")
                    name = name.rstrip(".")
                    if name:
                        self._update_value("client_name", name, "Found hostname from LLMNR")
        except Exception:
            log.debug("LLMNR parse error", exc_info=True)

    def _parse_mdns(self, pkt) -> None:
        """Extract hostname from mDNS queries (UDP 5353)."""
        try:
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                if dns.qr == 0 and dns.qdcount > 0:  # query
                    name = dns.qd.qname
                    if isinstance(name, bytes):
                        name = name.decode("utf-8", errors="replace")
                    # mDNS names end with .local.
                    if name.endswith(".local.") or name.endswith(".local"):
                        hostname = name.split(".")[0]
                        if hostname:
                            self._update_value("client_name", hostname, "Found hostname from mDNS")
        except Exception:
            log.debug("mDNS parse error", exc_info=True)

    def _parse_dhcp_request(self, pkt) -> None:
        if not pkt.haslayer(DHCP):
            return
        options = self._dhcp_options_dict(pkt[DHCP])
        hostname = options.get("hostname")
        if hostname:
            self._update_value("client_name", hostname, "Found hostname from DHCP request")

    def _parse_dhcp_reply(self, pkt) -> None:
        if not pkt.haslayer(DHCP):
            return
        options = self._dhcp_options_dict(pkt[DHCP])

        if "subnet_mask" in options:
            self._update_value("subnet_mask", options["subnet_mask"], "Found subnet mask from DHCP")
        if "hostname" in options:
            self._update_value("dhcp_server", options["hostname"], "Found DHCP server from DHCP")
        if "server_id" in options:
            self._update_value("dhcp_server", options["server_id"], "Found DHCP server from DHCP")
        if "NTP_server" in options:
            val = options["NTP_server"]
            if isinstance(val, list):
                val = val[0]
            self._update_value("ntp_server", str(val), "Found NTP server from DHCP")
        if "domain" in options:
            self._update_value("search_domain", options["domain"], "Found search domain from DHCP")
        if "name_server" in options:
            servers = options["name_server"]
            if isinstance(servers, str):
                servers = [servers]
            for srv in servers:
                self._update_dns(str(srv))

    @staticmethod
    def _dhcp_options_dict(dhcp_layer) -> dict:
        """Convert scapy DHCP options list into a dict."""
        result = {}
        for item in dhcp_layer.options:
            if isinstance(item, tuple) and len(item) >= 2:
                key, val = item[0], item[1]
                if isinstance(val, bytes):
                    try:
                        val = val.decode("utf-8", errors="replace")
                    except Exception:
                        pass
                result[key] = val
        return result

    # ── phase transitions ────────────────────────────────────────────

    def _transition(self, new_phase: str) -> None:
        log.info("Phase transition: %s → %s", self._phase, new_phase)
        self._phase = new_phase
