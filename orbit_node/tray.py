#!/usr/bin/env python3
"""
Orbit — macOS menu bar (status bar) app.

A lightweight `rumps` app that lives in the macOS menu bar (top-right) and
surfaces the live state of the local Orbit station:

  1. Recently generated device-pairing PINs (parsed from the station log)
  2. The current Cloudflare tunnel address (from public.json)
  3. IPFS storage used + the disk cap dedicated to Orbit, with an edit dialog

It is a *local, owner-only* tool: it reads local files and shells out to the
local `ipfs` CLI. It opens no network ports of its own.

Run via launchd (see install-macos.command) or manually:

    .venv/bin/python -m orbit_node.tray
"""

import os
import re
import socket
import subprocess
import time
from pathlib import Path

try:
    import rumps
except ImportError:  # pragma: no cover - rumps is macOS-only
    raise SystemExit("rumps is required for the menu bar app: pip install rumps")

# Reuse the station's configuration so paths honour .env / ORBIT_BASE_DIR.
from orbit_node.config import BASE_DIR, PUBLIC_JSON_PATH, ORBIT_PORT

# ---------------------------------------------------------------------------
# Configuration (overridable via environment, set by the launchd plist)
# ---------------------------------------------------------------------------
LOG_PATH = Path(os.getenv("ORBIT_LOG_FILE", str(BASE_DIR / "logs" / "orbit.log")))
IPFS_BIN = os.getenv("ORBIT_IPFS_BIN", "ipfs")
IPFS_PATH = os.getenv("IPFS_PATH", str(Path.home() / ".orbit" / "ipfs"))

REFRESH_SECONDS = 15
PIN_LOOKBACK_SECONDS = 30 * 60          # only show PINs from the last 30 minutes
PIN_TTL_SECONDS = 5 * 60                # matches pairing.TTL_SECONDS
PINS_MAX = 8
SIZE_RE = re.compile(r"(?i)^\s*\d+(\.\d+)?\s*[kmgt]?b\s*$")
PIN_RE = re.compile(r"PAIRING PIN:\s*(\d{4,8})")
LOG_TS_FMT = "%Y-%m-%d %H:%M:%S"        # matches config.py logging datefmt


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _ipfs(*args, timeout: int = 10):
    """Run the local ipfs CLI against the Orbit repo. Returns stdout or None."""
    env = dict(os.environ, IPFS_PATH=IPFS_PATH)
    try:
        out = subprocess.run(
            [IPFS_BIN, *args],
            env=env, capture_output=True, text=True, timeout=timeout,
        )
        if out.returncode != 0:
            return None
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def _human_bytes(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _ago(epoch: float, now: float) -> str:
    secs = max(0, int(now - epoch))
    if secs < 60:
        return f"{secs}s ago"
    if secs < 3600:
        return f"{secs // 60}m ago"
    return f"{secs // 3600}h ago"


def _read_endpoint() -> dict:
    """Read endpoint + peer id from public.json. Returns {} on failure."""
    import json
    try:
        obj = json.loads(PUBLIC_JSON_PATH.read_text())
        return {
            "endpoint": obj.get("endpoint"),
            "peer_id": obj.get("ipfs_peer_id"),
            "uid": obj.get("uid"),
        }
    except Exception:
        return {}


def _read_recent_pins(now: float):
    """Parse the station log for recent PAIRING PIN lines. Newest first."""
    if not LOG_PATH.exists():
        return []
    try:
        # Only scan the tail of the log to stay cheap on large files.
        data = LOG_PATH.read_bytes()[-200_000:]
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return []

    pins = []
    for line in text.splitlines():
        m = PIN_RE.search(line)
        if not m:
            continue
        ts = None
        try:
            ts = time.mktime(time.strptime(line[:19], LOG_TS_FMT))
        except Exception:
            ts = None
        if ts is not None and (now - ts) > PIN_LOOKBACK_SECONDS:
            continue
        pins.append({"pin": m.group(1), "ts": ts})

    pins.reverse()  # newest first
    return pins[:PINS_MAX]


def _read_storage():
    """Return (used_bytes_or_None, configured_max_string_or_None)."""
    used = None
    stat = _ipfs("repo", "stat")  # needs the daemon; bytes by default
    if stat:
        for line in stat.splitlines():
            if line.strip().startswith("RepoSize:"):
                try:
                    used = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
    # The configured cap reads from the config file even when the daemon is down.
    configured = _ipfs("config", "Datastore.StorageMax")
    return used, (configured or None)


def _set_storage_max(value: str) -> bool:
    ok = _ipfs("config", "Datastore.StorageMax", value) is not None
    if ok:
        # StorageMax is applied at GC time; kickstart the daemon so it re-reads.
        uid = os.getuid()
        subprocess.run(
            ["launchctl", "kickstart", "-k", f"gui/{uid}/com.orbit.ipfs"],
            capture_output=True,
        )
    return ok


def _tcp_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _station_running() -> bool:
    return _tcp_open("127.0.0.1", ORBIT_PORT)


def _gateway_addr():
    """Parse (host, port) the IPFS gateway is bound to, from `ipfs config`."""
    addr = _ipfs("config", "Addresses.Gateway")  # e.g. /ip4/127.0.0.1/tcp/8080
    if not addr:
        return None, None
    parts = addr.strip("/").split("/")
    host = port = None
    for i in range(0, len(parts) - 1, 2):
        proto, val = parts[i], parts[i + 1]
        if proto in ("ip4", "ip6", "dns", "dns4", "dns6"):
            host = val
        elif proto == "tcp":
            port = val
    return host, port


def _gateway_status():
    """Return (live_or_None, host, port). The gateway always listens on
    localhost regardless of its configured bind host, so we probe 127.0.0.1."""
    host, port = _gateway_addr()
    if not port:
        return None, host, port
    live = _tcp_open("127.0.0.1", int(port))
    return live, host, port


def _copy(text: str):
    try:
        subprocess.run(["pbcopy"], input=text.encode(), check=False)
    except OSError:
        pass


def _notify(title: str, subtitle: str, message: str):
    # rumps.notification raises when the app isn't a signed/bundled .app
    # (which is the case when launched via `python -m`). Never let a missing
    # notification break a click handler.
    try:
        rumps.notification(title, subtitle, message)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# The app
# ---------------------------------------------------------------------------

class OrbitTray(rumps.App):
    def __init__(self):
        super().__init__("Orbit", title="🛰", quit_button=None)

        self.status_item = rumps.MenuItem("Status: checking…")
        self.gateway_item = rumps.MenuItem("IPFS Gateway: …")
        self.url_item = rumps.MenuItem("Cloudflare URL: …", callback=self._copy_url)
        self.peer_item = rumps.MenuItem("Peer ID: …", callback=self._copy_peer)
        self.pins_menu = rumps.MenuItem("Recent Pairing PINs")
        self.storage_item = rumps.MenuItem("Storage: …")
        self.edit_storage_item = rumps.MenuItem("Edit Storage Limit…", callback=self._edit_storage)

        self.menu = [
            self.status_item,
            self.gateway_item,
            None,
            self.url_item,
            self.peer_item,
            None,
            self.pins_menu,
            None,
            self.storage_item,
            self.edit_storage_item,
            None,
            rumps.MenuItem("Open Data Folder", callback=self._open_data),
            rumps.MenuItem("Restart Station", callback=self._restart_station),
            rumps.MenuItem("Refresh Now", callback=lambda _: self.refresh()),
            rumps.MenuItem("Quit Orbit", callback=rumps.quit_application),
        ]

        self._endpoint_cache = None
        self._peer_cache = None
        self.refresh()

    # -- periodic refresh -------------------------------------------------
    @rumps.timer(REFRESH_SECONDS)
    def _tick(self, _):
        self.refresh()

    def refresh(self):
        now = time.time()

        running = _station_running()
        self.title = "🛰" if running else "🛰⚠️"
        self.status_item.title = f"Status: {'Running' if running else 'Stopped'}"

        live, gw_host, gw_port = _gateway_status()
        if live is None:
            self.gateway_item.title = "IPFS Gateway: unknown"
        else:
            where = f"{gw_host}:{gw_port}" if (gw_host and gw_port) else (gw_port or "?")
            self.gateway_item.title = f"IPFS Gateway: {'🟢 Live' if live else '🔴 Down'} ({where})"

        info = _read_endpoint()
        endpoint = info.get("endpoint") or "(not published yet)"
        peer = info.get("peer_id") or "(unknown)"
        self._endpoint_cache = info.get("endpoint")
        self._peer_cache = info.get("peer_id")
        self.url_item.title = f"Cloudflare URL: {endpoint}"
        short_peer = (peer[:18] + "…") if len(peer) > 20 else peer
        self.peer_item.title = f"Peer ID: {short_peer}"

        self._rebuild_pins(now)
        self._refresh_storage()

    def _rebuild_pins(self, now: float):
        # rumps creates a MenuItem's submenu NSMenu lazily on first add(); calling
        # clear() before anything was added dereferences a None _menu. Only clear
        # once the submenu actually exists.
        if self.pins_menu._menu is not None:
            self.pins_menu.clear()
        pins = _read_recent_pins(now)
        if not pins:
            self.pins_menu.add(rumps.MenuItem("No recent PINs"))
            return
        for entry in pins:
            ts = entry["ts"]
            if ts is None:
                label = f"{entry['pin']}"
            else:
                age = _ago(ts, now)
                remaining = int(PIN_TTL_SECONDS - (now - ts))
                if remaining > 0:
                    suffix = f"{age} · expires in {remaining // 60}m{remaining % 60:02d}s"
                else:
                    suffix = f"{age} · expired"
                label = f"{entry['pin']}   ({suffix})"
            item = rumps.MenuItem(label, callback=self._copy_pin_factory(entry["pin"]))
            self.pins_menu.add(item)

    def _refresh_storage(self):
        used, configured = _read_storage()
        used_str = _human_bytes(used) if used is not None else "?"
        max_str = configured or "?"
        self.storage_item.title = f"Storage: {used_str} of {max_str}"

    # -- callbacks --------------------------------------------------------
    def _copy_url(self, _):
        if self._endpoint_cache:
            _copy(self._endpoint_cache)
            _notify("Orbit", "Copied", "Cloudflare URL copied to clipboard")

    def _copy_peer(self, _):
        if self._peer_cache:
            _copy(self._peer_cache)
            _notify("Orbit", "Copied", "Peer ID copied to clipboard")

    def _copy_pin_factory(self, pin: str):
        def _cb(_):
            _copy(pin)
            _notify("Orbit", "Copied", f"Pairing PIN {pin} copied")
        return _cb

    def _edit_storage(self, _):
        _, configured = _read_storage()
        current = configured or "10GB"
        win = rumps.Window(
            title="Orbit Storage Limit",
            message="Disk space dedicated to Orbit (the IPFS repo).\n"
                    "Examples: 10GB, 50GB, 500GB",
            default_text=current,
            ok="Save",
            cancel="Cancel",
            dimensions=(220, 22),
        )
        resp = win.run()
        if not resp.clicked:
            return
        value = resp.text.strip()
        if not SIZE_RE.match(value):
            rumps.alert("Invalid size", "Use a value like 10GB or 500GB.")
            return
        if _set_storage_max(value):
            _notify("Orbit", "Storage updated", f"Orbit limit set to {value}")
            self._refresh_storage()
        else:
            rumps.alert("Could not update", "Failed to set the IPFS storage limit. "
                        "Is the ipfs CLI installed and the Orbit repo initialized?")

    def _restart_station(self, _):
        uid = os.getuid()
        subprocess.run(
            ["launchctl", "kickstart", "-k", f"gui/{uid}/com.orbit.station"],
            capture_output=True,
        )
        _notify("Orbit", "Restarting", "Station is restarting…")

    def _open_data(self, _):
        subprocess.run(["open", str(BASE_DIR)], capture_output=True)


def main():
    OrbitTray().run()


if __name__ == "__main__":
    main()
