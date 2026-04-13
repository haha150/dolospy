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
try:
    sio_app = socketio.ASGIApp(sio, other_app=app)
except TypeError:
    sio_app = socketio.ASGIApp(sio, app=app)

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


@app.get("/send_dhcp_probe", response_class=PlainTextResponse)
async def send_dhcp_probe():
    bridge.send_dhcp_probe()
    return "Performing DHCP Discover"


@app.get("/get_vendor", response_class=PlainTextResponse)
async def get_vendor(mac_addr: str = Query(...)):
    return mac_vendor.lookup(mac_addr)


@app.get("/uptime", response_class=JSONResponse)
async def uptime():
    if bridge.bridge_start_time:
        return {"start_time": bridge.bridge_start_time, "uptime": time.time() - bridge.bridge_start_time}
    return {"start_time": 0, "uptime": 0}


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


# ── main ─────────────────────────────────────────────────────────────

def main():
    # start bridge
    bridge.start_bridge()

    # start keyboard listener in background
    kb_thread = threading.Thread(target=_keyboard_listener, daemon=True)
    kb_thread.start()

    # start the web server
    log.info("Starting web server on port 4444")
    uvicorn.run(sio_app, host="0.0.0.0", port=4444, log_level="info")


if __name__ == "__main__":
    main()
