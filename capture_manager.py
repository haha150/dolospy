"""Traffic capture manager — scheduled tcpdump on the bridge interface.

Provides:
  - BPF filter presets (cleartext creds, print jobs, HTTP, DNS, custom)
  - Time-window scheduling (start/end hour)
  - Manual start/stop override
  - Auto-compression of completed pcaps (.pcap → .pcap.gz)
  - Size-limited storage with oldest-first cleanup
  - SCP offloading to a remote host
"""

import gzip
import logging
import os
import shutil
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

log = logging.getLogger("dolos.capture")

CAPTURE_DIR = Path(__file__).parent / "captures"
CAPTURE_DIR.mkdir(exist_ok=True)

# BPF filter presets
FILTER_PRESETS = {
    "all": "",
    "cleartext": (
        "port 21 or port 23 or port 25 or port 80 or port 110 "
        "or port 143 or port 389 or port 445"
    ),
    "print": "port 9100 or port 631 or port 515",
    "http": "port 80 or port 8080 or port 8443",
    "dns": "port 53",
    "smb": "port 445 or port 139",
    "custom": "",
}


class CaptureManager:
    def __init__(self, bridge_iface: str = "mibr", config: dict | None = None) -> None:
        self.bridge_iface = bridge_iface
        self._config = config or {}
        self.max_size_mb: int = self._config.get("capture_max_size_mb", 500)
        self.offload_target: str = self._config.get("capture_offload_target", "")

        # schedule state
        self.schedule_enabled: bool = False
        self.schedule_start_hour: int = 8
        self.schedule_end_hour: int = 17
        self.filter_preset: str = "cleartext"
        self.custom_filter: str = ""

        # runtime state
        self._tcpdump_proc: subprocess.Popen | None = None
        self._current_pcap: Path | None = None
        self._manual_override: bool = False  # True = manually started, ignore schedule
        self._stop_event = threading.Event()
        self._scheduler_thread: threading.Thread | None = None

    # ── public API ───────────────────────────────────────────────────

    def start_scheduler(self) -> None:
        """Start the background scheduler thread."""
        if self._scheduler_thread and self._scheduler_thread.is_alive():
            return
        self._stop_event.clear()
        self._scheduler_thread = threading.Thread(
            target=self._scheduler_loop, daemon=True, name="capture-scheduler"
        )
        self._scheduler_thread.start()
        log.info("Capture scheduler started")

    def stop_scheduler(self) -> None:
        """Stop the scheduler and any active capture."""
        self._stop_event.set()
        self.stop_capture()

    def start_capture(self, manual: bool = False) -> str:
        """Start a tcpdump capture on the bridge interface."""
        if self._tcpdump_proc and self._tcpdump_proc.poll() is None:
            return "Capture already running"

        if manual:
            self._manual_override = True

        bpf = self._get_bpf_filter()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_file = CAPTURE_DIR / f"capture_{timestamp}.pcap"

        cmd = [
            "tcpdump",
            "-i", self.bridge_iface,
            "-w", str(pcap_file),
            "-U",  # packet-buffered output
            "-s", "0",  # full packet capture
        ]
        if bpf:
            cmd.append(bpf)

        try:
            self._tcpdump_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._current_pcap = pcap_file
            preset_name = self.filter_preset if self.filter_preset != "custom" else f"custom: {self.custom_filter}"
            log.info("Capture started: %s (filter: %s, pid: %d)",
                     pcap_file.name, preset_name, self._tcpdump_proc.pid)
            return f"Capture started: {pcap_file.name}"
        except FileNotFoundError:
            log.error("tcpdump not found — install it with: apt install tcpdump")
            return "Failed: tcpdump not installed"
        except Exception as exc:
            log.error("Failed to start capture: %s", exc)
            return f"Failed: {exc}"

    def stop_capture(self) -> str:
        """Stop the active tcpdump capture and compress the pcap."""
        self._manual_override = False
        if not self._tcpdump_proc or self._tcpdump_proc.poll() is not None:
            self._tcpdump_proc = None
            return "No capture running"

        try:
            self._tcpdump_proc.terminate()
            self._tcpdump_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._tcpdump_proc.kill()
            self._tcpdump_proc.wait(timeout=3)
        except Exception as exc:
            log.warning("Error stopping tcpdump: %s", exc)

        self._tcpdump_proc = None
        result = "Capture stopped"

        # compress in background
        if self._current_pcap and self._current_pcap.exists():
            pcap = self._current_pcap
            self._current_pcap = None
            threading.Thread(
                target=self._compress_and_cleanup,
                args=(pcap,),
                daemon=True,
            ).start()
            result += f" — compressing {pcap.name}"

        return result

    def get_status(self) -> dict:
        """Return current capture state for the UI."""
        capturing = (
            self._tcpdump_proc is not None
            and self._tcpdump_proc.poll() is None
        )

        files = sorted(CAPTURE_DIR.glob("capture_*"))
        total_bytes = sum(f.stat().st_size for f in files if f.is_file())
        current_size = 0
        if capturing and self._current_pcap and self._current_pcap.exists():
            current_size = self._current_pcap.stat().st_size

        return {
            "capturing": capturing,
            "manual_override": self._manual_override,
            "schedule_enabled": self.schedule_enabled,
            "schedule_start_hour": self.schedule_start_hour,
            "schedule_end_hour": self.schedule_end_hour,
            "filter_preset": self.filter_preset,
            "custom_filter": self.custom_filter,
            "file_count": len(files),
            "total_size_mb": round(total_bytes / (1024 * 1024), 1),
            "current_size_mb": round(current_size / (1024 * 1024), 1),
            "max_size_mb": self.max_size_mb,
            "offload_target": self.offload_target,
        }

    def update_schedule(
        self,
        enabled: bool,
        start_hour: int,
        end_hour: int,
        filter_preset: str,
        custom_filter: str,
    ) -> str:
        """Update the capture schedule settings."""
        self.schedule_enabled = enabled
        self.schedule_start_hour = max(0, min(23, start_hour))
        self.schedule_end_hour = max(0, min(23, end_hour))
        self.filter_preset = filter_preset if filter_preset in FILTER_PRESETS else "cleartext"
        self.custom_filter = custom_filter
        log.info(
            "Capture schedule updated: enabled=%s, window=%02d:00–%02d:00, filter=%s",
            enabled, self.schedule_start_hour, self.schedule_end_hour, self.filter_preset,
        )
        if enabled:
            return (
                f"Schedule set: {self.schedule_start_hour:02d}:00–"
                f"{self.schedule_end_hour:02d}:00 ({self.filter_preset})"
            )
        return "Capture schedule disabled"

    def update_offload_target(self, target: str) -> str:
        """Update the SCP offload destination."""
        self.offload_target = target.strip()
        log.info("Offload target set: %s", self.offload_target)
        return f"Offload target: {self.offload_target}" if self.offload_target else "Offload target cleared"

    def offload(self) -> str:
        """SCP all compressed pcaps to the configured remote host."""
        if not self.offload_target:
            return "No offload target configured"

        gz_files = sorted(CAPTURE_DIR.glob("*.pcap.gz"))
        if not gz_files:
            return "No capture files to offload"

        transferred = 0
        failed = 0
        for gz in gz_files:
            try:
                result = subprocess.run(
                    [
                        "scp", "-o", "StrictHostKeyChecking=no",
                        "-o", "ConnectTimeout=10",
                        str(gz), self.offload_target,
                    ],
                    capture_output=True, text=True, timeout=120,
                )
                if result.returncode == 0:
                    gz.unlink()
                    transferred += 1
                    log.info("Offloaded and deleted: %s", gz.name)
                else:
                    failed += 1
                    log.warning("SCP failed for %s: %s", gz.name, result.stderr.strip())
            except Exception as exc:
                failed += 1
                log.warning("Offload failed for %s: %s", gz.name, exc)

        msg = f"Offloaded {transferred} file(s)"
        if failed:
            msg += f", {failed} failed"
        return msg

    def list_files(self) -> list[dict]:
        """List all capture files with sizes."""
        files = []
        for f in sorted(CAPTURE_DIR.glob("capture_*"), reverse=True):
            if f.is_file():
                files.append({
                    "name": f.name,
                    "size_mb": round(f.stat().st_size / (1024 * 1024), 2),
                })
        return files

    # ── internal ─────────────────────────────────────────────────────

    def _get_bpf_filter(self) -> str:
        """Build the BPF filter string from current settings."""
        if self.filter_preset == "custom":
            return self.custom_filter
        return FILTER_PRESETS.get(self.filter_preset, "")

    def _in_schedule_window(self) -> bool:
        """Check if the current hour falls within the capture window."""
        if not self.schedule_enabled:
            return False
        hour = datetime.now().hour
        if self.schedule_start_hour <= self.schedule_end_hour:
            # same-day window: e.g. 08–17
            return self.schedule_start_hour <= hour < self.schedule_end_hour
        else:
            # overnight window: e.g. 22–06
            return hour >= self.schedule_start_hour or hour < self.schedule_end_hour

    def _scheduler_loop(self) -> None:
        """Background loop that starts/stops capture based on time window."""
        while not self._stop_event.is_set():
            try:
                capturing = (
                    self._tcpdump_proc is not None
                    and self._tcpdump_proc.poll() is None
                )

                if self._manual_override:
                    # manual mode — don't interfere
                    pass
                elif self._in_schedule_window():
                    if not capturing:
                        log.info("Schedule window active — starting capture")
                        self.start_capture()
                else:
                    if capturing and not self._manual_override:
                        log.info("Schedule window ended — stopping capture")
                        self.stop_capture()
            except Exception:
                log.exception("Capture scheduler error")

            self._stop_event.wait(60)  # check every 60 seconds

    def _compress_and_cleanup(self, pcap_path: Path) -> None:
        """Compress a pcap file and enforce storage limits."""
        if not pcap_path.exists():
            return

        # skip tiny files (tcpdump header only, no packets)
        if pcap_path.stat().st_size < 100:
            pcap_path.unlink()
            log.info("Removed empty capture: %s", pcap_path.name)
            return

        gz_path = pcap_path.with_suffix(".pcap.gz")
        try:
            with open(pcap_path, "rb") as f_in:
                with gzip.open(gz_path, "wb", compresslevel=6) as f_out:
                    shutil.copyfileobj(f_in, f_out)
            pcap_path.unlink()
            log.info(
                "Compressed %s → %s (%.1f MB)",
                pcap_path.name, gz_path.name,
                gz_path.stat().st_size / (1024 * 1024),
            )
        except Exception:
            log.exception("Compression failed for %s", pcap_path.name)
            return

        # enforce storage limit — delete oldest files first
        self._enforce_size_limit()

    def _enforce_size_limit(self) -> None:
        """Delete oldest capture files until total size is under the limit."""
        max_bytes = self.max_size_mb * 1024 * 1024
        files = sorted(CAPTURE_DIR.glob("capture_*"))
        total = sum(f.stat().st_size for f in files if f.is_file())

        while total > max_bytes and files:
            oldest = files.pop(0)
            if oldest == self._current_pcap:
                continue  # never delete the active capture
            size = oldest.stat().st_size
            oldest.unlink()
            total -= size
            log.info("Cleanup: deleted %s (%.1f MB freed)", oldest.name, size / (1024 * 1024))
