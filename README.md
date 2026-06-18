# Orbit

**Self-hosted, post-quantum, end-to-end encrypted content sharing over IPFS.**

Orbit lets you run a personal **station** on a Raspberry Pi (or any Linux box) that publishes encrypted content to IPFS and grants access to followers via cryptographic envelopes. No centralized servers, no platform lock-in — you own your data and your identity.

Content access control and device authentication use **NIST post-quantum algorithms** — ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204) — so traffic captured today cannot be decrypted by a future quantum computer ("harvest now, decrypt later"). You can also publish **public, unencrypted** content for anyone to read.

## How It Works

```
You (Station)                         Followers
     |                                     |
     |  1. Encrypt content                 |
     |  2. Upload to IPFS                  |
     |  3. Create per-follower envelopes   |
     |  4. Publish manifest                |
     |  5. Update IPNS pointer             |
     |                                     |
     |          IPFS Network               |
     |  <------------------------------>   |
     |                                     |
     |     6. Resolve your Peer ID (IPNS)  |
     |     7. Fetch manifest               |
     |     8. Open their envelope          |
     |     9. Decrypt content              |
```

Each post gets its own random symmetric key. That key is wrapped in a **post-quantum envelope** (ML-KEM-768) for each authorized follower, encapsulated to their public key. Only they can open it. Your station's IPFS **Peer ID** acts as a permanent address — followers can always find you via IPNS, even if your IP or tunnel URL changes.

## Features

- **Post-quantum cryptography** — Content envelopes use ML-KEM-768 (FIPS 203) and device authentication uses ML-DSA-65 (FIPS 204). No classical X25519 anywhere — safe against "harvest now, decrypt later".
- **End-to-end encryption** — Content is encrypted before it leaves your device. IPFS peers only see ciphertext.
- **Per-post access control** — Each post has its own key. Grant access to everyone, specific followers, just yourself, or **publicly** (unencrypted).
- **Optional public hosting** — Publish a file unencrypted to IPFS for anyone to fetch via a public gateway — useful for a profile picture, a public document, or a static site asset.
- **Permanent discovery via IPNS** — Your IPFS Peer ID is your stable address. No DNS, no static IP required.
- **Zero-config public access** — Optional Cloudflare Quick Tunnel gives you a public HTTPS URL with no port forwarding.
- **Multi-client architecture** — One identity, many apps. Photo sharing (orbitstagram), file storage (orbitdrive), and more — all sharing the same encryption and social graph.
- **Device pairing** — Pair your phone or laptop as a delegate device via 6-digit PIN. Access your content from anywhere.
- **Encrypted social graph** — Your follower and following lists are encrypted before being published to IPFS.
- **One-click install** — Single script sets up everything on a Raspberry Pi: IPFS, Python, systemd services, firewall, identity.

## Quick Start

### Raspberry Pi (Recommended)

```bash
git clone https://github.com/your-username/orbit.git
cd orbit
chmod +x install.sh
./install.sh
```

The installer handles everything:
1. Installs Python 3.11+, IPFS (Kubo), and cloudflared
2. Creates a Python virtual environment with all dependencies
3. Bootstraps your cryptographic identity (Curve25519 keypair + UUID)
4. Configures and starts systemd services (IPFS, Orbit, Cloudflare tunnel)
5. Opens the firewall and prints your Peer ID

After install, your station is live. Share your **Peer ID** with followers — they can always find you at:

```
https://ipfs.io/ipns/<your-peer-id>
```

### Manual Setup (Dev / Non-Pi)

```bash
# Prerequisites: Python 3.11+, IPFS daemon running on localhost:5001

git clone https://github.com/your-username/orbit.git
cd orbit

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env as needed

python run.py
```

## Configuration

Copy `.env.example` to `.env` and customize:

| Variable | Default | Description |
|----------|---------|-------------|
| `ORBIT_PORT` | `8443` | HTTPS port |
| `ORBIT_PASSWORD` | _(empty)_ | Encrypt your private key at rest |
| `CLOUDFLARE_TUNNEL_ENABLED` | `false` | Enable zero-config public access |
| `IPFS_API_URL` | `http://127.0.0.1:5001` | Local IPFS daemon |
| `MAX_UPLOAD_SIZE` | `104857600` | Max upload size (100 MB) |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

See [PROTOCOL.md](PROTOCOL.md) Appendix B for the full configuration reference.

## Architecture

```
 +-------------------------------------------+
 |  Client Layer (orbitstagram, orbitdrive)   |  App-specific metadata
 +-------------------------------------------+
 |  Manifest Layer                            |  Post index, envelope pointers
 +-------------------------------------------+
 |  Social Graph Layer                        |  Encrypted followers/following
 +-------------------------------------------+
 |  Content Encryption Layer                  |  Per-post symmetric + envelopes
 +-------------------------------------------+
 |  Identity Layer                            |  Curve25519 keypairs, UIDs
 +-------------------------------------------+
 |  Discovery Layer (IPNS)                    |  Permanent station addresses
 +-------------------------------------------+
 |  Cryptographic Primitives                  |  ML-KEM-768, ML-DSA-65, NaCl, BLAKE2b
 +-------------------------------------------+
 |  Transport (IPFS + HTTPS API)              |  Content storage, station API
 +-------------------------------------------+
```

### Cryptography

| Purpose | Algorithm |
|---------|-----------|
| Post encryption | XSalsa20-Poly1305 (NaCl SecretBox) — 256-bit, already PQ-resistant |
| Envelope key wrapping | **ML-KEM-768** (FIPS 203) KEM-DEM + SecretBox |
| Envelope KDF | BLAKE2b (domain-separated, `person="orbit-kem"`) |
| Device request signing | **ML-DSA-65** (FIPS 204) signatures |
| PIN hashing | scrypt |
| Key-at-rest encryption | Argon2i |

ML-KEM is a Key Encapsulation Mechanism, so a post's symmetric key is wrapped using the standard **KEM-DEM** construction: encapsulate to the recipient's ML-KEM key, derive a wrapping key from the shared secret with BLAKE2b, and SecretBox-wrap the post key. Device authentication signs the canonical request string with ML-DSA instead of deriving an HMAC key from an (X25519) ECDH.

> **Caveats.** By default the post-quantum primitives use the pure-Python [`kyber-py`](https://pypi.org/project/kyber-py/) and [`dilithium-py`](https://pypi.org/project/dilithium-py/) libraries — chosen because they install with no native build on a Raspberry Pi. They are **not constant-time** and are self-described as educational; in Orbit's model decapsulation and signing happen client-side (never as a server oracle), so timing side-channels are low-risk, but this is not a hardened production crypto stack. For a **constant-time** implementation, install the optional [Open Quantum Safe](https://openquantumsafe.org/) `liboqs` backend (see below). This release is also a **hard breaking change** — there is no migration from older X25519 stations, and every client must implement ML-KEM envelope opening and ML-DSA request signing.

#### Optional: constant-time backend (liboqs)

The ML-KEM / ML-DSA math is provided by a pluggable backend, selected with `ORBIT_PQC_BACKEND`:

| Value | Backend | Notes |
|-------|---------|-------|
| `auto` (default) | liboqs if available, else pure-Python | Self-tests liboqs at startup and falls back safely |
| `liboqs` | Open Quantum Safe (C) | **Constant-time / hardened.** Requires the `oqs` binding (native build) |
| `python` | kyber-py + dilithium-py | Pure-Python, no native build |

Both backends implement the same FIPS standards, so keys, envelopes, and signatures are fully interoperable — you can switch backends without re-bootstrapping. To enable the hardened backend:

```bash
pip install oqs            # builds/links liboqs; needs cmake + a C compiler
# then restart with ORBIT_PQC_BACKEND=auto (default) or =liboqs to require it
```

## API

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /profile` | None | Public identity document (uid, ML-KEM + ML-DSA public keys, peer ID, manifest pointer) |
| `GET /health` | None | Station health check |
| `POST /inbox` | None* | Receive follow requests |
| `POST /post` | Signature | Create a post (`audience_mode`: `self` / `specific` / `all` / `public`) |
| `POST /rewrap` | Signature | Get a device-specific envelope |
| `POST /follow` | Signature | Follow another user |
| `POST /unfollow` | Signature | Unfollow a user |
| `POST /delegate/start` | None | Initiate device pairing |
| `POST /delegate/confirm` | None | Confirm pairing with PIN |

\* Follow requests are unauthenticated; other inbox message types require a signature.

**Authenticated requests** are signed with the device's **ML-DSA-65** key. The client sends `x-orbit-uid`, `x-orbit-device`, `x-orbit-ts`, `x-orbit-nonce`, `x-orbit-body-sha256`, and `x-orbit-sig` (base64 ML-DSA signature over the canonical string `METHOD\nPATH\nUID\nDEVICE_UID\nTS\nNONCE\nBODY_SHA256`). The station verifies the signature against the device's stored public key; a ±60 s timestamp window and a one-time nonce store prevent replay.

### Audience modes

Every post declares an `audience_mode`:

| Mode | Who can read | Encrypted? |
|------|--------------|------------|
| `self` | only you | yes |
| `specific` | you + listed follower UIDs | yes |
| `all` | you + all allowed followers | yes |
| `public` | **anyone** | **no** |

A `public` post is uploaded to IPFS **unencrypted** with no envelopes; its manifest entry is flagged `"encrypted": false` and any metadata is stored in the clear. Read it directly from any IPFS gateway:

```
https://ipfs.io/ipfs/<post_cid>
```

⚠️ Public content is **permanent and world-readable** once published — anyone who learns the CID (including via your public IPNS manifest) can fetch it, and IPFS has no delete. Only publish what you intend to share with the world.

## IPNS Discovery

Every Orbit station publishes its `public.json` to IPNS under its IPFS Peer ID. This creates a **permanent, location-independent address** for your station:

```
Peer ID (never changes)  -->  IPNS  -->  /ipfs/<CID>  -->  public.json
```

Clients discover stations in priority order:
1. **Direct endpoint** — fastest, uses the HTTP URL from the social graph
2. **IPNS resolution** — if the endpoint is down, resolve the Peer ID via DHT
3. **Public gateway** — last resort: `https://ipfs.io/ipns/<peer-id>`

This means you can move your Pi to a new network, get a new tunnel URL, or change ISPs — followers will still find you.

## Multi-Client Design

Orbit is a protocol, not a single app. Multiple clients share the same identity, encryption, and follower graph:

```json
{
  "clients": {
    "orbitstagram": {
      "posts": [
        { "post_cid": "Qm...", "audience_mode": "all", "envelopes_cid": "Qm..." },
        { "post_cid": "Qm...", "audience_mode": "public", "encrypted": false, "envelopes_cid": null }
      ]
    },
    "orbitdrive": {
      "posts": [{ "post_cid": "Qm...", "audience_mode": "self", "envelopes_cid": "Qm..." }]
    }
  }
}
```

Building a new client? Pick a name, define your metadata schema, and post to your namespace. See [PROTOCOL.md](PROTOCOL.md) Section 16.

## Project Structure

```
orbit/
├── install.sh              # One-click Raspberry Pi installer
├── run.py                  # Entry point (uvicorn + TLS)
├── requirements.txt        # Python dependencies
├── .env.example            # Configuration template
├── PROTOCOL.md             # Full protocol specification
├── orbit_node/
│   ├── main.py             # FastAPI app and routes
│   ├── pqcrypto.py         # Post-quantum primitives (ML-KEM-768, ML-DSA-65)
│   ├── identity.py         # PQC keypair generation and loading
│   ├── posts.py            # Post creation and encryption
│   ├── envelopes.py        # ML-KEM envelope create/open
│   ├── manifest.py         # Manifest serialization
│   ├── rewrap.py           # Delegate envelope rewrap
│   ├── auth.py             # ML-DSA signature authentication
│   ├── inbox.py            # Follow request handling
│   ├── pairing.py          # Device pairing (PIN)
│   ├── graph.py            # Social graph encryption
│   ├── followers.py        # Follower database ops
│   ├── following.py        # Following database ops
│   ├── ipfs_client.py      # IPFS/IPNS API wrapper
│   ├── tunnel.py           # Cloudflare tunnel monitor
│   ├── profile.py          # /profile endpoint
│   ├── config.py           # Configuration loading
│   ├── backup.py           # USB backup & restore (create/restore CLI)
│   └── database.py         # SQLite schema
├── orbit_data/             # Runtime data (created on first run)
│   ├── keys/mlkem.bin      # Station ML-KEM-768 keypair (content)
│   ├── keys/mldsa.bin      # Station ML-DSA-65 keypair (auth)
│   ├── public.json         # Public identity (uid, mlkem/mldsa public keys)
│   ├── orbit.db            # SQLite database
│   └── ssl/                # TLS certificates
└── tests/                  # Test suite
```

## Managing Your Station

```bash
# Check status
sudo systemctl status orbit

# View logs
sudo journalctl -u orbit -f

# Restart
sudo systemctl restart orbit

# View IPFS peer ID
ipfs id -f='<id>'

# Check tunnel URL
sudo journalctl -u cloudflared-tunnel -f
```

## Backup & Restore

microSD cards fail. A backup captures **everything that makes the station yours** —
your Orbit keys, the database, the manifest, **and** the IPFS peer identity (your
permanent peer ID / IPNS address) plus the pinned post content — into a single
portable archive on a USB drive, so you can rebuild on a fresh card or box and
come back at the **same address with the same posts**.

### Create a backup

Plug in a USB drive, then:

```bash
# Auto-detects a mounted USB drive (or set ORBIT_BACKUP_DEST / pass --dest)
.venv/bin/python -m orbit_node.backup create

# Explicit destination, or encrypt the archive with a passphrase:
.venv/bin/python -m orbit_node.backup create --dest /media/$USER/MYDRIVE
.venv/bin/python -m orbit_node.backup create --passphrase 'correct horse battery staple'

# List backups found on the drive
.venv/bin/python -m orbit_node.backup list
```

A **daily backup also runs automatically** whenever a USB drive is mounted, via
the `orbit-backup.timer` systemd unit the installer sets up (it cleanly no-ops
when no drive is present). Set a fixed destination with `ORBIT_BACKUP_DEST` in
`.env`.

> ⚠️ **Unencrypted backups contain your private keys** (Orbit + the IPFS node
> key + your `.env`). Keep the drive physically secure, or use `--passphrase`.

### Restore onto a fresh station

During install, point `install.sh` at a backup:

```bash
./install.sh --restore                                   # auto-detect a backup on a mounted USB
./install.sh --restore=/media/<user>/<drive>/orbit-backup-<id>-<ts>.tar.gz
```

Restore reinstates `orbit_data/`, the IPFS peer identity, and the pinned content
**before** a fresh identity would be generated — so `ipfs id` returns your
original peer ID and followers can still find you. (If you used a passphrase, it
will be prompted for.) The archive format is documented in
[PROTOCOL.md](PROTOCOL.md).

## Running Tests

```bash
source .venv/bin/activate
pytest
```

## Protocol Specification

The full protocol is documented in [PROTOCOL.md](PROTOCOL.md) — covering identity, cryptography, envelopes, manifests, IPNS discovery, device pairing, authentication, the social graph, and the installation process.

## License

TBD
