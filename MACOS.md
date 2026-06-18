# Orbit on macOS

Run a full Orbit station on your Mac with a menu bar app for day-to-day status —
no Raspberry Pi required.

## Install

1. Download/clone this repo.
2. In **Finder**, double-click **`install-macos.command`**.
   - First time only: macOS Gatekeeper may block it. **Right-click → Open**, then
     confirm. (It's an unsigned local script, so Gatekeeper warns by default.)
3. Wait for it to finish. It will:
   - download **IPFS (Kubo)** and **cloudflared** into `~/.orbit/bin` (no sudo),
   - create a Python virtual environment and install the station + `rumps`,
   - initialize a dedicated IPFS repo at `~/.orbit/ipfs` (API bound to localhost),
   - bootstrap your post-quantum identity,
   - register and start `launchd` services for IPFS, the station, the Cloudflare
     tunnel, and the menu bar app.

When it's done, look for the **🛰 icon in your menu bar** (top-right — the
top-left of the bar is the Apple menu).

> Prefer the terminal? `chmod +x install-macos.command && ./install-macos.command`.

## The menu bar app

Click the 🛰 icon for live station status:

- **Status** — Running / Stopped (🛰 turns to 🛰⚠️ when the station is down).
- **Cloudflare URL** — your current public tunnel address; click to copy.
- **Peer ID** — your permanent IPNS address; click to copy.
- **Recent Pairing PINs** — PINs generated in the last 30 minutes (with a live
  expiry countdown); click one to copy. Use these when pairing a new device
  (e.g. OrbitDrive) instead of digging through logs.
- **Storage** — IPFS repo used / cap, with **Edit Storage Limit…** to change how
  much disk Orbit may use (e.g. `10GB`, `500GB`). Saving updates
  `Datastore.StorageMax` and restarts the IPFS daemon so it takes effect.
- **Open Data Folder**, **Restart Station**, **Refresh Now**, **Quit**.

## Managing services

The station runs as user `launchd` LaunchAgents (labels `com.orbit.*`):

```bash
launchctl list | grep com.orbit                          # what's running
launchctl kickstart -k gui/$(id -u)/com.orbit.station    # restart the station
launchctl kickstart -k gui/$(id -u)/com.orbit.ipfs       # restart IPFS
launchctl unload ~/Library/LaunchAgents/com.orbit.*.plist  # stop everything
launchctl load -w ~/Library/LaunchAgents/com.orbit.*.plist # start everything
```

Logs live in `orbit_data/logs/` (`orbit.log`, `ipfs.log`, `tunnel.log`, `tray.log`).
Pairing PINs are written to `orbit.log` (that's what the menu bar reads).

## Notes & limitations

- **Unsigned installer.** This is a local script, not a notarized `.pkg`, so the
  first launch needs the right-click→Open step. Distributing a signed installer
  would require an Apple Developer ID + notarization.
- **Storage = the IPFS repo cap.** "Amount of space dedicated to Orbit" maps to
  IPFS `Datastore.StorageMax`. Changing it bounds what garbage collection keeps;
  it does not instantly delete pinned content.
- The menu bar app is a **local, owner-only** tool — it reads local files and the
  local `ipfs` CLI and opens no network ports of its own.
