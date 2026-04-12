"""MAC address to vendor lookup.

Loads the mac_to_vendor.json database (same data as the original JS project)
and provides prefix-match lookups.
"""

import json
import logging
from pathlib import Path

log = logging.getLogger("dolos.mac_vendor")

_VENDOR_DB: dict[str, str] = {}


def _load_db() -> None:
    global _VENDOR_DB
    db_path = Path(__file__).parent / "mac_to_vendor.json"
    if db_path.exists():
        with open(db_path) as f:
            _VENDOR_DB = json.load(f)
        log.info("Loaded %d MAC vendor entries", len(_VENDOR_DB))
    else:
        log.warning("mac_to_vendor.json not found")


def lookup(mac_addr: str) -> str:
    """Return the vendor name for *mac_addr*, or ``'unknown'``."""
    if not _VENDOR_DB:
        _load_db()

    addr = mac_addr.upper()
    while addr:
        if addr in _VENDOR_DB:
            return _VENDOR_DB[addr]
        addr = addr[:-1]
    return "unknown"
