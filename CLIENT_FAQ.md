# Cipher Station Client Developer Guide & FAQ

A practical, opinionated pathway for building a **client** that speaks the Cipher Station
protocol — a photo app, a file drive, a CLI, a web reader, anything. It distills
[PROTOCOL.md](PROTOCOL.md) down to "what do I actually have to implement, and in
what order." Where you need byte-exact detail, this guide points you at the
relevant PROTOCOL.md section.

> **Cipher Station is post-quantum.** Content is wrapped with **ML-KEM-768** (FIPS 203)
> and requests are authenticated with **ML-DSA-65** (FIPS 204). There is **no**
> X25519/Ed25519 anywhere in the app layer. Your client must use these
> algorithms; classical NaCl `box`/`sign` will not interoperate.

---

## 1. The mental model

```
   YOUR CLIENT  ──HTTPS──►  STATION (Raspberry Pi, holds the secret keys)
        │                        │
        │                        └──►  local IPFS daemon ──► IPFS / IPNS network
        │
        └──────────────IPFS gateway / IPNS───────────────►  read content directly
```

- A **station** is the always-on server (someone's Pi). It holds the root secret
  keys, runs the HTTP API, and talks to IPFS. It fans encrypted post keys out to
  followers/delegates, but it does not encrypt your content — see below.
- A **client** is your app. It never holds the station's root keys. It has its
  own keypairs and plays one (or both) of two roles:

| Role | What it is | What it does |
|------|------------|--------------|
| **Owner / delegate client** | A device *paired* to a station you control | Authenticates, creates/deletes/reshares posts, manages follows, reads everything (via rewrap) |
| **Follower / reader client** | An app reading a station you *follow* | Pulls content from IPFS and decrypts the posts shared with you |

Most real apps do **both**: manage the user's own station *and* read the
stations they follow.

A key consequence: **the client encrypts content, not the station.** For any
`audience_mode` other than `public`, you generate the post's symmetric key,
encrypt the file and metadata with it, and seal that key to the *station's own*
ML-KEM public key (a "self_envelope") — all on-device, before anything is sent.
The station only ever receives ciphertext plus that one small sealed envelope;
it decapsulates the envelope to recover the key (never the content) so it can
fan out envelopes to followers. See §4 and §9.

This isn't incidental — it's what makes the "post-quantum" claim actually hold.
The transport between your client and the station is ordinary HTTPS (classical
key exchange, not post-quantum). If plaintext content or an unwrapped key ever
crossed that transport, a party recording the session today could decrypt it
later once classical key exchange is broken (a "harvest-now-decrypt-later"
attack) — regardless of how good the *storage*-side crypto is. Encrypting and
sealing client-side before the request is sent means there is nothing on the
wire worth harvesting.

Your client's crypto work therefore spans both directions: **sealing** your own
post keys on write, and **opening** envelopes (yours and, if you build a reader,
others') plus **decrypting** on read — plus **signing** your authenticated
requests.

---

## 2. What you must implement (crypto checklist)

You need standards-conformant implementations of:

| Primitive | Standard | Used for |
|-----------|----------|----------|
| **ML-KEM-768** | FIPS 203 | Sealing your own post keys to the station (`encaps`) on every upload; opening content envelopes (`decaps`) on read; sending follow/pair keys (`keygen`) |
| **ML-DSA-65** | FIPS 204 | Signing your authenticated requests (`sign`) |
| **XSalsa20-Poly1305** | NaCl `SecretBox` | Encrypting post bodies & metadata on upload; decrypting on read; the DEM inside an envelope |
| **BLAKE2b** | RFC 7693 | Deriving the envelope wrap-key (personalized) |
| **SHA-256** | — | Request body hash |
| Hex + Base64 | — | Encodings on the wire |

The station may run either a pure-Python or a constant-time **liboqs** backend —
both are FIPS-conformant, so as long as *your* implementation is conformant,
keys, envelopes, and signatures interoperate. Pick a maintained PQC library for
your platform (e.g. liboqs bindings for native apps, `@noble/post-quantum` for
JS/TS, etc.).

---

## 3. Identity: your keys

Every Cipher Station principal — station, follower, or delegate device — carries **two
keypairs** plus a couple of IDs:

| Item | What | Notes |
|------|------|-------|
| `uid` | UUIDv4 string | The *user* identity. Stable. |
| `device_uid` | string | This device's identity. For a single-identity follower, set it **equal to `uid`** (see §7 caveat). |
| ML-KEM-768 keypair | content | public = 1184 bytes (**2368 hex chars**), secret = 2400 bytes |
| ML-DSA-65 keypair | auth | public = 1952 bytes (**3904 hex chars**), secret = 4032 bytes |

- Public keys travel as **lowercase hex**.
- **Secret keys never leave the device.** Store them in the platform keystore.
- You generate these locally; the station learns only your *public* keys (via a
  follow request or the pairing ceremony).

---

## 4. The envelope format (get this byte-exact)

This is the one thing clients most often get wrong. An **envelope** wraps a
post's 32-byte symmetric key to a recipient's ML-KEM key using a **KEM-DEM**
construction. The on-the-wire envelope is a **hex string** of:

```
 ┌───────────────────┬──────────────────────┬──────────────────────────────┐
 │ uint16 big-endian │  kem_ct (1088 bytes) │  SecretBox(wrap_key, sym_key) │
 │  len(kem_ct)      │                      │  (24B nonce + ct + 16B tag)   │
 └───────────────────┴──────────────────────┴──────────────────────────────┘
```

where `wrap_key = BLAKE2b(shared_secret, digest_size=32, person="orbit-kem")`.

**Open an envelope** (what a reader does):

```text
raw      = hex_decode(envelope_hex)
ct_len   = uint16_be(raw[0:2])
kem_ct   = raw[2 : 2+ct_len]
sealed   = raw[2+ct_len : ]
shared   = ML_KEM_768.decaps(my_mlkem_secret, kem_ct)
wrap_key = BLAKE2b(shared, out_len=32, person="orbit-kem")
sym_key  = SecretBox(wrap_key).decrypt(sealed)        # 32 bytes
```

**Seal an envelope** (you MUST do this for every non-`public` post you create —
see §9 — sealing your fresh `sym_key` to the *station's own* ML-KEM public key
as `self_envelope`; the station also does this itself when fanning the same key
out to followers/delegates):

```text
shared, kem_ct = ML_KEM_768.encaps(recipient_mlkem_public)
wrap_key       = BLAKE2b(shared, out_len=32, person="orbit-kem")
sealed         = SecretBox(wrap_key).encrypt(sym_key)   # fresh random nonce
envelope_hex   = hex(uint16_be(len(kem_ct)) + kem_ct + sealed)
```

Notes:
- `person` (BLAKE2b personalization) is the ASCII bytes `orbit-kem`.
- `SecretBox.encrypt` output already includes its 24-byte nonce prefix; don't add
  your own.
- Total length ≈ `2 + 1088 + 72 = 1162` bytes → ~2324 hex chars.

See [PROTOCOL.md §4.3 and §6](PROTOCOL.md) for the authoritative spec.

---

## 5. Authentication: signing requests

Authenticated endpoints (`/post`, `/post/delete`, `/post/share`, `/rewrap`,
`/follow`, `/unfollow`, `/followers`, and non-`follow_request` `/inbox` messages)
require an **ML-DSA-65 signature** — there is no shared secret or HMAC.

**Step 1 — build the canonical string** (exactly this, `\n`-joined, UTF-8):

```
METHOD\nPATH\nUID\nDEVICE_UID\nTS\nNONCE\nBODY_SHA256
```

- `METHOD` uppercase (`POST`), `PATH` exactly as requested (e.g. `/post`).
- `TS` = current Unix time in **seconds** (string). Must be within **±60 s** of
  the station's clock — keep your device clock synced.
- `NONCE` = a unique random string per request (the station rejects reuse for 24h).
- `BODY_SHA256` = **lowercase hex** SHA-256 of the **exact raw request body
  bytes**. For a GET (empty body), it's `sha256("")`.

**Step 2 — sign it:**

```text
sig = ML_DSA_65.sign(my_mldsa_secret, utf8(canonical_string))
```

**Step 3 — send these headers:**

| Header | Value |
|--------|-------|
| `x-cipher-uid` | your `uid` |
| `x-cipher-device` | your `device_uid` |
| `x-cipher-ts` | the `TS` you signed |
| `x-cipher-nonce` | the `NONCE` you signed |
| `x-cipher-body-sha256` | the lowercase-hex body hash you signed |
| `x-cipher-sig` | **base64** of `sig` |

The station looks up your device's stored ML-DSA public key, recomputes the
canonical string, and verifies. (See [PROTOCOL.md §12](PROTOCOL.md).)

> **Header size:** an ML-DSA-65 signature is ~3309 bytes → ~4.4 KB base64. Make
> sure your HTTP stack allows large request headers.

> **`/rewrap` extra rule:** the body's `uid`/`device_uid` must match your
> `x-cipher-uid`/`x-cipher-device` headers, or you get 401.

---

## 6. Discovery: finding a station

A station is addressed by its **IPFS peer ID** (permanent) and/or a current
**endpoint URL**. Resolve in this priority order:

1. **Direct endpoint** — the `endpoint` URL from the social graph / a shared
   profile. Fastest. (TLS is self-signed; pin or trust-on-first-use.)
2. **IPNS** — resolve the peer ID via the DHT to `/ipfs/<cid>`, then fetch that
   `public.json`. Works even if the IP/tunnel changed.
3. **Public gateway** — last resort: `https://ipfs.io/ipns/<peer-id>`.

`public.json` (also returned by `GET /profile`) gives you everything you need to
start: `uid`, `mlkem_public_key`, `mldsa_public_key`, `endpoint`,
`ipfs_peer_id`, `manifest_pointer`, and the encrypted social-graph pointers. See
[PROTOCOL.md §5.3](PROTOCOL.md).

---

## 7. Reading content (follower flow)

```text
1. Get public.json        (GET /profile, or via IPNS)        -> manifest_pointer
2. Fetch the manifest     (IPFS cat <manifest_pointer>)
3. Walk manifest["clients"][<your-client-name>]["posts"]
4. For each post entry:
     if entry.audience_mode == "public" (entry.encrypted == false):
         body = IPFS cat <post_cid>            # already plaintext
         meta = entry.metadata                 # plaintext JSON object
     else:
         env_doc  = IPFS cat <entry.envelopes_cid>
         my_env   = env_doc["envelopes"][my_uid]   # absent => not in audience
         sym_key  = open_envelope(my_mlkem_secret, my_env)   # see §4
         body     = SecretBox(sym_key).decrypt(IPFS cat <post_cid>)
         meta     = SecretBox(sym_key).decrypt(hex_decode(entry.metadata))
```

- The manifest is partitioned by **client namespace** (`clients` map) — only read
  the namespace(s) your app understands (see §13).
- If `envelopes[my_uid]` is missing, the post simply wasn't shared with you.
- A plain follower does **not** need to call the station's API at all to read —
  everything is on IPFS. You only need the station/IPFS for fetching CIDs.

> **Follower caveat — register a single identity.** The station seals **one**
> envelope per follower *uid*, to that uid's "root" key (the device where
> `device_uid == uid`). External followers do **not** get the delegate `/rewrap`
> path. So when you send a follow request, present **one** identity with
> `device_uid == uid` and the ML-KEM key you'll decrypt with. (Multi-device
> *delegate* access is for the station owner's own paired devices — see §8.)

---

## 8. Reading as a delegate device (the rewrap step)

If you're the **station owner's** paired device, posts are sealed to the
*station's* key under the station's uid — not to your device key. To read them,
ask the station to **rewrap** the key to your device:

```text
POST /rewrap   (authenticated, see §5)
body: { "uid": <station_uid>, "device_uid": <your_device_uid>,
        "post_cid": <cid>, "envelopes_cid": <cid optional> }
-> { "status": "ok", "result": { "envelope": <hex sealed to YOUR device key> } }

sym_key = open_envelope(my_device_mlkem_secret, result.envelope)   # see §4
```

This is **one call per post**. Reading a long feed = many rewraps; cache the
recovered keys, and expect a burst after first pairing. (See [PROTOCOL.md §11](PROTOCOL.md).)

---

## 9. Creating, deleting, and resharing posts (owner/delegate)

For any `audience_mode` other than `public`, **you encrypt, the station never
sees plaintext.** Before calling `POST /post`:

```text
sym_key         = random(32)
encrypted_file  = SecretBox(sym_key).encrypt(file_bytes)
metadata_hex    = SecretBox(sym_key).encrypt(compact_json(metadata)).hex()   # if any
self_envelope   = seal_envelope(sym_key, station_mlkem_public_key)          # see §4
```

`station_mlkem_public_key` is the station's own ML-KEM public key — captured at
pairing time (delegates) or read from your own station's identity — not a
follower's key. The station decapsulates `self_envelope` to recover `sym_key`
(never the file), then fans out follower/delegate envelopes exactly as it
always has.

**Create** — `POST /post` (authenticated, `multipart/form-data`):

| Field | Required | Description |
|-------|----------|-------------|
| `file` | yes | For `audience_mode != public`: `encrypted_file` from above. For `public`: raw bytes. |
| `metadata` | no | For `audience_mode != public`: `metadata_hex` from above. For `public`: a plaintext JSON **string**. |
| `self_envelope` | yes, if `audience_mode != public` | Hex KEM-DEM envelope from above. Omitting it on a non-`public` post gets you a `400`. |
| `client` | no | Your client namespace (defaults to `default`) |
| `audience_mode` | no | `self` \| `specific` \| `all` (default) \| `public` |
| `audience_uids` | if `specific` | JSON array (or CSV) of follower UIDs |

Returns `{ status, cid, envelopes_cid, audience_mode, ... }`. For
`audience_mode=public` skip all of the above — the file is uploaded and stored
**unencrypted**, readable by anyone at `https://<gateway>/ipfs/<cid>`; there is
no `self_envelope` and no key to generate.

**Delete** — `POST /post/delete` `{ post_cid, client? }` (unpins + GC).
**Reshare** — `POST /post/share` `{ post_cid, audience_mode, audience_uids?, client? }`
re-issues envelopes for a new audience without re-uploading (not valid for `public`).

---

## 10. Following another user (owner action)

`POST /follow` (authenticated):

```json
{ "uid": "<target>", "endpoint": "<their-station-url>",
  "mlkem_public_key": "<their 2368-hex>", "mldsa_public_key": "<their 3904-hex | optional>",
  "ipns_id": "<their peer id | optional>" }
```

This records the outbound follow and rebuilds your encrypted social graph.
`POST /unfollow` `{ "uid": "<target>" }` reverses it.

---

## 11. Becoming someone's follower (send a follow request)

To read a station, that station has to know your public key. Send an **unauthenticated**
follow request to the *target* station:

```json
POST /inbox
{
  "type": "follow_request",
  "uid": "<your-uid>",
  "devices": [
    { "device_uid": "<your-uid>",
      "mlkem_public_key": "<your 2368-hex>",
      "mldsa_public_key": "<your 3904-hex | optional>" }
  ],
  "ipns_id": "<your peer id | optional>"
}
```

(There's also a legacy single-key shape — see [PROTOCOL.md §13.2](PROTOCOL.md).)
Once accepted, the station rewraps existing `all`-audience posts to include you,
and future `all`/`specific`-to-you posts will carry an envelope under your uid.

---

## 12. Pairing a new device to your own station

So a second device can authenticate and read your own content:

```text
New device: generate device_uid + ML-KEM keypair + ML-DSA keypair.

1. POST /delegate/start   { device_uid, mlkem_public_key, mldsa_public_key }   (no auth)
   -> { pairing_id, expires_in_seconds }
   The station prints a 6-digit PIN (in its logs / owner UI).

2. User reads the PIN and enters it on the new device.

3. POST /delegate/confirm { pairing_id, pin }   (no auth)
   -> device registered. It can now sign requests (§5) and /rewrap (§8).
```

PINs expire in 5 minutes and lock after 5 wrong attempts. (See [PROTOCOL.md §10](PROTOCOL.md).)

---

## 13. Multi-client namespacing

Cipher Station is a protocol, not one app. The manifest is partitioned by **client name**:

```json
{ "clients": {
    "cipherframe": { "posts": [ ... ] },
    "your-app":     { "posts": [ ... ] }
} }
```

- Pick a unique, stable client name and pass it as the `client` field on `/post`.
- Define your own metadata schema as a JSON object — it's encrypted with the post
  (or stored plaintext for `public` posts), so its shape is entirely yours.
- When reading, only walk the namespaces your app understands; ignore the rest.

See [PROTOCOL.md §16](PROTOCOL.md) for conventions.

---

## 14. Endpoint quick reference

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `GET /profile` | none | Public identity (`public.json`) |
| `GET /health` | none | Health check |
| `GET /storage` | none | Repo/disk/per-client usage |
| `POST /inbox` | none for `follow_request`, else sig | Follow requests & inbox messages |
| `POST /post` | sig | Create a post |
| `POST /post/delete` | sig | Delete a post |
| `POST /post/share` | sig | Reshare to a new audience |
| `POST /rewrap` | sig | Device-specific envelope |
| `GET /followers` | sig | List your allowed followers |
| `POST /follow` / `POST /unfollow` | sig | Manage outbound follows |
| `POST /delegate/start` / `POST /delegate/confirm` | none | Device pairing |

Full request/response details: [PROTOCOL.md §14](PROTOCOL.md).

---

## 15. FAQ

**Q: Do I have to implement the encryption myself?**
Yes, both directions. For *creating* a non-`public` post, you generate the key,
encrypt the file/metadata, and seal the key to the station's public key
(§4, §9) — the station never sees plaintext or an un-sealed key. For *reading*,
you implement envelope opening (ML-KEM decaps → BLAKE2b → SecretBox) and
post/metadata decryption. You also generate your own keypairs and sign your
requests. `public` posts are the one exception: no keys, no encryption, plaintext
both ways.

**Q: Why two keypairs?**
ML-KEM is a key-encapsulation mechanism (confidentiality) and can't sign; ML-DSA
is a signature scheme (authentication) and can't encrypt. They do different jobs,
so every principal has one of each.

**Q: My request gets `401 bad auth`. Checklist:**
1. Canonical string is exactly `METHOD\nPATH\nUID\nDEVICE_UID\nTS\nNONCE\nBODY_SHA256`, UTF-8, `METHOD` uppercase, `PATH` exactly as sent.
2. `x-cipher-body-sha256` is lowercase hex of the **exact** bytes you sent (and the same value you signed).
3. `x-cipher-sig` is **base64** (not hex) of the signature.
4. You signed with the **ML-DSA** secret whose public key the station has for this `device_uid`.

**Q: `401 stale request`?** Your clock is off by >60 s. Sync it (NTP).

**Q: `401 bad body hash`?** The body you hashed ≠ the body you sent. Hash the
final serialized bytes (multipart bodies included).

**Q: `403 device not authorized` / `device has no auth key`?** This `device_uid`
isn't registered under that `uid`, or it was registered without an ML-DSA key.
Pair it (§12) or include `mldsa_public_key` in the follow request.

**Q: Can a follower client work purely offline of the station?**
Mostly yes — a plain follower reads everything from IPFS/IPNS and decrypts with
its own key; it never needs the station API. Only **delegate** reads need the
station (for `/rewrap`).

**Q: Does the station's backend (liboqs vs pure-Python) affect me?**
No. Both are FIPS-203/204 conformant with identical encodings. Just be conformant
yourself.

**Q: How do I read a `public` post with no keys?**
Fetch the CID from any IPFS gateway: `https://ipfs.io/ipfs/<post_cid>`. The
manifest entry has `"encrypted": false` and plaintext metadata.

---

## 16. TL;DR build order

1. Add ML-KEM-768, ML-DSA-65, SecretBox, BLAKE2b, SHA-256 to your app.
2. Generate the user's `uid`, `device_uid`, and both keypairs; store secrets securely.
3. Implement `open_envelope` AND `seal_envelope` (§4) and the request signer (§5). Unit-test all three.
4. **Read path:** profile → manifest → decrypt posts in your namespace (§7).
5. **Follow path:** send a follow request to stations you want to read (§11).
6. **Owner path (optional):** pair the device (§12), then create/manage posts (§9, including client-side pre-upload encryption) and follows (§10).
7. For owner devices, add the `/rewrap` step to read your own content (§8).

When in doubt about an exact byte, defer to [PROTOCOL.md](PROTOCOL.md) — it's the
normative spec; this guide is the map.
