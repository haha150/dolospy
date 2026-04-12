"""ARP table tracker using scapy.

Sniffs ARP packets on the bridge interface and maintains an in-memory
MAC -> IP mapping table.  Emits callbacks when new entries appear so
the bridge controller can update kernel neighbour / route state.
"""

import logging
import threading
from typing import Callable

from scapy.all import ARP, Ether, sniff

log = logging.getLogger("dolos.arp_table")


class ArpTable:
    def __init__(self, network_interface: str) -> None:
        self.network_interface = network_interface
        # mac -> ip
        self.entries: dict[str, str] = {}

        self._on_arp_entry_callbacks: list[Callable] = []
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # ── callback registration ────────────────────────────────────────
    def on_arp_entry(self, callback: Callable) -> None:
        self._on_arp_entry_callbacks.append(callback)

    def _emit_arp_entry(self, info: dict) -> None:
        for cb in self._on_arp_entry_callbacks:
            try:
                cb(info)
            except Exception:
                log.exception("Error in arp_entry callback")

    # ── sniffing ─────────────────────────────────────────────────────
    def start(self) -> None:
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _sniff_loop(self) -> None:
        log.info("ARP sniffer starting on %s", self.network_interface)
        try:
            sniff(
                iface=self.network_interface,
                filter="arp",
                prn=self._handle_packet,
                stop_filter=lambda _: self._stop_event.is_set(),
                store=False,
            )
        except Exception:
            log.exception("ARP sniffer crashed")
        log.info("ARP sniffer stopped")

    def _handle_packet(self, pkt) -> None:
        if not pkt.haslayer(ARP):
            return

        arp = pkt[ARP]
        arp_info = {
            "operation": arp.op,
            "sender_mac": arp.hwsrc,
            "sender_ip": arp.psrc,
            "target_mac": arp.hwdst,
            "target_ip": arp.pdst,
        }

        # ARP request (op=1)
        if arp.op == 1:
            if arp.psrc != "0.0.0.0":
                self.entries[arp.hwsrc] = arp.psrc
                self._emit_arp_entry(arp_info)

        # ARP reply (op=2)
        elif arp.op == 2:
            if arp.psrc != "0.0.0.0":
                self.entries[arp.hwsrc] = arp.psrc
            if arp.pdst != "0.0.0.0":
                self.entries[arp.hwdst] = arp.pdst
                self._emit_arp_entry(arp_info)
