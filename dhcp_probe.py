"""DHCP Discover probe — pure Python replacement for the Go binary.

Sends a DHCP Discover packet on the specified interface, spoofing the
given client MAC and IP, to trick the DHCP server into revealing network
configuration (subnet, NTP, DNS, domain, etc.).
"""

import logging
import threading

from scapy.all import (
    BOOTP,
    DHCP,
    IP,
    UDP,
    Ether,
    RandInt,
    conf,
    get_if_hwaddr,
    sendp,
)

log = logging.getLogger("dolos.dhcp_probe")


def send_dhcp_discover(
    interface: str,
    client_mac: str,
    client_ip: str,
) -> None:
    """Send a DHCP Discover on *interface* spoofing *client_mac*."""

    def _send():
        try:
            # build the DHCP Discover packet
            ether = Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
            ip = IP(src="0.0.0.0", dst="255.255.255.255")
            udp = UDP(sport=68, dport=67)
            bootp = BOOTP(
                op=1,  # BOOTREQUEST
                chaddr=bytes.fromhex(client_mac.replace(":", "")),
                xid=int(RandInt()),
            )
            dhcp = DHCP(
                options=[
                    ("message-type", "discover"),
                    ("hostname", b"foobar"),
                    ("param_req_list", [1, 3, 6, 26, 42]),  # subnet, router, DNS, MTU, NTP
                    "end",
                ]
            )

            pkt = ether / ip / udp / bootp / dhcp
            log.info("Sending DHCP Discover on %s (spoofing %s)", interface, client_mac)
            sendp(pkt, iface=interface, verbose=False)
            log.info("DHCP Discover sent (%d bytes)", len(pkt))
        except Exception:
            log.exception("Failed to send DHCP Discover")

    # send in a separate thread so it doesn't block the caller
    threading.Thread(target=_send, daemon=True).start()
