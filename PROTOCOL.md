# Orbit Protocol Specification

**Version:** 2.0-draft
**Date:** 2026-06-04
**Status:** Draft

---

## Abstract

Orbit is a self-hosted, end-to-end encrypted content sharing protocol built on IPFS. A user runs a **station** (e.g., on a Raspberry Pi at home), publishes encrypted content to IPFS, and provisions access to friends, family, or followers via cryptographic **envelopes** containing per-post decryption keys. The station owner's content is replicated and made available through IPFS's content-addressed storage, removing dependence on centralized platforms.

Orbit is **post-quantum**: content confidentiality uses ML-KEM-768 (FIPS 203) key encapsulation and device authentication uses ML-DSA-65 (FIPS 204) digital signatures. The legacy X25519/SealedBox/HMAC scheme has been removed entirely (see Section 20).

The protocol is designed to be **extensible**: different application-layer **clients** (photo sharing, file storage, document collaboration, etc.) share the same identity, encryption, and access-control infrastructure while defining their own metadata schemas within a unified manifest.

Stations are **permanently discoverable** via IPNS. Each station's IPFS peer ID acts as a stable address: followers resolve it through the DHT to find the station's current `public.json`, regardless of whether the station's IP address or tunnel URL has changed.

---

## 1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

All integers are unsigned unless otherwise noted. All strings are UTF-8. Hexadecimal encodings use lowercase characters. JSON serialization for IPFS upload MUST use compact encoding (no whitespace separators: `(",", ":")`).

---

## 2. Glossary

| Term | Definition |
|------|------------|
| **Station** | The user's self-hosted Orbit node. Holds the root secret keys (ML-KEM + ML-DSA). Runs the API server and local IPFS daemon. Typically a Raspberry Pi or similar always-on device. |
| **Delegate** | A secondary device (phone, laptop) paired with the station. Has its own ML-KEM-768 keypair (content) and ML-DSA-65 keypair (auth) but relies on the station for envelope rewrapping. |
| **UID** | A UUID v4 string that uniquely identifies a user across the Orbit network. |
| **Device UID** | A UUID v4 string that uniquely identifies a single device belonging to a user. For a station, `device_uid` equals `uid`. |
| **Envelope** | An ML-KEM-768 KEM-DEM wrapping of a 32-byte symmetric key, encapsulated to a specific recipient's ML-KEM-768 public key. |
| **Manifest** | A JSON document listing all posts across all clients, with pointers to encrypted content and envelope files on IPFS. Published to IPFS; its CID is stored in `public.json` as `manifest_pointer`. |
| **Client** | An application-layer module that uses the Orbit protocol for a specific use case (e.g., `orbitstagram` for photos, `orbitdrive` for files). Each client occupies a namespace within the manifest. |
| **CID** | Content Identifier. An IPFS content-addressed hash (typically CIDv0/Base58). |
| **Post** | A single encrypted content blob stored on IPFS, along with its associated envelopes and metadata. |
| **Audience** | The set of UIDs permitted to decrypt a given post. Controlled by `audience_mode`. A `public` post has no envelopes and is stored unencrypted, readable by anyone. |
| **IPNS** | InterPlanetary Name System. A mutable pointer system built on IPFS, keyed by the node's peer ID. Used to publish a stable address that resolves to the station's current `public.json` CID. |
| **Peer ID** | The IPFS node's cryptographic identity, derived from its keypair. Acts as the permanent, location-independent address for a station. |

---

## 3. Architecture Overview

### 3.1 System Topology

```
                          IPFS Network
                         /            \
                        /              \
    [Station]  <-- IPFS Daemon -->  [IPFS Peers]
    (FastAPI)      (port 5001)
        |                \
        |  HTTPS / LAN    \--- IPNS DHT
        |                      (permanent discovery)
    [Delegate Device]
    (iOS / Android / Web)
```

A station consists of:
- An **Orbit server** (HTTP API)
- A **local IPFS daemon** (Kubo, port 5001)
- A **SQLite database** for follower/device state
- A **local filesystem** for key material and manifests
- An optional **Cloudflare Quick Tunnel** for zero-configuration public access

Delegate devices communicate with the station over HTTP (ideally HTTPS in production) and access IPFS content either through the station's IPFS gateway or their own IPFS node.

### 3.2 Trust Model

The **station** is the root of trust:
- It holds the only copy of the user's root secret keys (ML-KEM decapsulation key and ML-DSA signing key).
- It generates all envelopes (encrypts symmetric keys for recipients).
- It approves or denies follow requests.
- It performs envelope rewrapping for delegate devices.

**Delegates** are trusted devices that have been paired via a PIN-based ceremony. They can create posts and request envelope rewraps, but cannot access the root secret keys directly.

**Followers** are external users who have been granted access. They receive envelopes encapsulated to their ML-KEM public key, allowing them to decrypt posts they are authorized to see.

### 3.3 Protocol Layers

```
 +-------------------------------------------+
 |  Client Layer (orbitstagram, orbitdrive)   |  Application-specific metadata
 +-------------------------------------------+
 |  Manifest Layer                            |  Post index, envelope pointers
 +-------------------------------------------+
 |  Social Graph Layer                        |  Followers, following, graph encryption
 +-------------------------------------------+
 |  Content Encryption Layer                  |  Per-post symmetric encryption + envelopes
 +-------------------------------------------+
 |  Identity Layer                            |  Keypairs, UIDs, public identity
 +-------------------------------------------+
 |  Discovery Layer (IPNS)                    |  Permanent station addresses
 +-------------------------------------------+
 |  Cryptographic Primitives                  |  ML-KEM-768, ML-DSA-65, NaCl, Argon2i, BLAKE2b
 +-------------------------------------------+
 |  Transport (IPFS + HTTP API)               |  Content storage, station API
 +-------------------------------------------+
```

---

## 4. Cryptographic Primitives

### 4.1 Key Types

| Key Type | Algorithm | Size | Usage |
|----------|-----------|------|-------|
| Content keypair | ML-KEM-768 (FIPS 203) | 1184 bytes (public/encapsulation), 2400 bytes (secret/decapsulation) | Envelope creation (key wrapping) |
| Auth keypair | ML-DSA-65 (FIPS 204) | 1952 bytes (public), 4032 bytes (secret) | Request signing/verification |
| Symmetric key | XSalsa20-Poly1305 (NaCl SecretBox) | 32 bytes | Post encryption, graph encryption, metadata encryption, KEM-DEM key wrapping |

Every principal (station, follower, delegate device) has **two** keypairs: an ML-KEM-768 keypair for content and an ML-DSA-65 keypair for authentication. The symmetric layer (SecretBox), scrypt PIN hashing, and Argon2i key-at-rest encryption are already quantum-resistant and are unchanged.

### 4.2 Symmetric Encryption (SecretBox)

Used for encrypting post content, metadata, and social graphs.

- **Algorithm:** XSalsa20-Poly1305 (NaCl SecretBox)
- **Key size:** 32 bytes
- **Nonce:** 24 bytes, randomly generated per encryption

**Output format:**

```
+----------+------------------+--------+
| nonce    | ciphertext       | tag    |
| 24 bytes | len(plaintext)   | 16 B   |
+----------+------------------+--------+
```

Total output size: `24 + len(plaintext) + 16` bytes.

The nonce is prepended to the ciphertext by NaCl's `SecretBox.encrypt()`. Implementations MUST generate a fresh random nonce for every encryption operation.

### 4.3 Asymmetric Encryption (ML-KEM-768)

Used for creating envelopes (wrapping per-post symmetric keys for specific recipients).

- **Algorithm:** ML-KEM-768 (FIPS 203) key encapsulation, combined with NaCl SecretBox in a KEM-DEM construction
- **Input:** a 32-byte symmetric key, recipient ML-KEM-768 public (encapsulation) key
- **Sizes:** public/encapsulation key = 1184 bytes; secret/decapsulation key = 2400 bytes; KEM ciphertext = 1088 bytes; shared secret = 32 bytes

ML-KEM is a Key Encapsulation Mechanism: it produces a *random* shared secret rather than encrypting a caller-chosen plaintext. To wrap a chosen 32-byte symmetric key, Orbit uses the standard **KEM-DEM** construction:

```
shared_secret, kem_ct = ML_KEM_768.encaps(recipient_mlkem_pubkey)   # 32 B, 1088 B
wrap_key = BLAKE2b(shared_secret, digest_size=32, person=b"orbit-kem")
sealed   = SecretBox(wrap_key).encrypt(sym_key)                      # 24 + 32 + 16 = 72 B
```

**Envelope wire format (hex-encoded):**

```
+------------------+-----------+---------------------------+
| len(kem_ct)      | kem_ct    | sealed                    |
| 2 bytes (BE)     | 1088 B    | 72 B (SecretBox of key)   |
+------------------+-----------+---------------------------+
```

Total: `2 + 1088 + 72 = 1162` bytes, which encodes to **~2324 hex characters**. (Envelopes are no longer the fixed 160-hex-char SealedBox blobs of the X25519 era.)

The `person` parameter is the ASCII string `orbit-kem` (per BLAKE2b spec, treated as the personalization input).

### 4.4 Password-Based Key Encryption (Argon2i)

Used for encrypting the station's secret-key files (`mlkem.bin`, `mldsa.bin`) at rest. This wrapper is algorithm-agnostic and unchanged from the X25519 era; it now protects post-quantum key bundles.

- **KDF:** Argon2i (via PyNaCl defaults)
- **Salt:** 16 bytes, randomly generated
- **Output key:** 32 bytes
- **Encryption:** The derived key encrypts the key-bundle bytes using SecretBox

**Stored format:**

```
+--------+----------------------------------+
| salt   | SecretBox(public_key + secret_key) |
| 16 B   | 24 (nonce) + len + 16 (tag)      |
+--------+----------------------------------+
```

The encryption is applied only when `ORBIT_PASSWORD` is set; otherwise the bundle (`public_key || secret_key`) is written in the clear. See Section 5.2 for the bundle layouts.

### 4.5 PIN Hashing (scrypt)

Used for hashing device-pairing PINs.

- **Algorithm:** scrypt
- **Parameters:** n=16384 (2^14), r=8, p=1, dklen=32
- **Salt:** 16 bytes, randomly generated per session

### 4.6 Auth Key Derivation (None)

There is **no** auth key derivation. The previous scheme derived an HMAC key from an X25519 ECDH shared secret; this is obsolete. With ML-DSA-65 signatures there is no shared secret and no symmetric auth key: the device signs with its ML-DSA secret key and the station verifies with the device's stored ML-DSA public key (see Section 12).

### 4.7 Request Signing (ML-DSA-65)

- **Algorithm:** ML-DSA-65 (FIPS 204) digital signatures
- **Secret key:** the device's ML-DSA-65 secret key (4032 bytes)
- **Public key:** the device's ML-DSA-65 public key (1952 bytes), stored by the station
- **Message:** canonical request string (see Section 12)
- **Signature:** 3309 bytes, transmitted base64-encoded (~4412 base64 characters) in the `x-orbit-sig` header

---

## 5. Identity Layer

### 5.1 Identity Structure

Each Orbit identity consists of:

| Field | Type | Description |
|-------|------|-------------|
| `uid` | UUID v4 string | Globally unique user identifier |
| `device_uid` | UUID v4 string | Per-device identifier. For the station, `device_uid == uid`. |
| `mlkem_public_key` | 2368 hex chars | ML-KEM-768 public (encapsulation) key (1184 bytes), used for content envelopes |
| `mldsa_public_key` | 3904 hex chars | ML-DSA-65 public key (1952 bytes), used to verify request signatures |

### 5.2 Key Storage

The station stores its secret keys in **two** binary files, each holding `public_key || secret_key` so the public key is always recoverable from the file alone:

**File:** `orbit_data/keys/mlkem.bin` (ML-KEM-768, content)

```
+----------------------------+----------------------------+
| encapsulation_key (public) | decapsulation_key (secret) |
| 1184 bytes                 | 2400 bytes                 |
+----------------------------+----------------------------+
```

Total: 3584 bytes.

**File:** `orbit_data/keys/mldsa.bin` (ML-DSA-65, auth)

```
+---------------+---------------+
| public_key    | secret_key    |
| 1952 bytes    | 4032 bytes    |
+---------------+---------------+
```

Total: 5984 bytes.

Each file is written in the clear by default. When `ORBIT_PASSWORD` is set, each file is encrypted at rest using the Argon2i scheme described in Section 4.4 (16-byte salt + SecretBox). The legacy single `keys/private.bin` (64-byte X25519 keypair) has been removed.

### 5.3 Public Identity Document

**File:** `orbit_data/public.json`

Every station MUST publish a public identity document:

```json
{
  "uid": "<uuid-v4>",
  "alias": "<human-readable-name> | null",
  "mlkem_public_key": "<2368-hex-chars>",
  "mldsa_public_key": "<3904-hex-chars>",
  "endpoint": "<https://station-url> | null",
  "manifest_pointer": "<ipfs-cid> | null",
  "followers_cid": "<ipfs-cid> | null",
  "following_cid": "<ipfs-cid> | null",
  "follow_decoder_envelopes_cid": "<ipfs-cid> | null",
  "ipfs_peer_id": "<peer-id> | null"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `uid` | MUST | User's UUID v4 |
| `alias` | MAY | Human-readable display name |
| `mlkem_public_key` | MUST | Hex-encoded ML-KEM-768 public (encapsulation) key. MUST match the station's actual content keypair. |
| `mldsa_public_key` | MUST | Hex-encoded ML-DSA-65 public key. MUST match the station's actual auth keypair. |
| `endpoint` | SHOULD | HTTPS URL where the station API is reachable |
| `manifest_pointer` | MUST (after first post) | IPFS CID of the current manifest |
| `followers_cid` | MAY | IPFS CID of the encrypted followers graph |
| `following_cid` | MAY | IPFS CID of the encrypted following graph |
| `follow_decoder_envelopes_cid` | MAY | IPFS CID of the graph decoder envelopes |
| `ipfs_peer_id` | SHOULD | The station's IPFS peer ID, used for IPNS-based discovery (see Section 18) |

### 5.4 Bootstrap Flow

When a station starts for the first time:

1. Generate an ML-KEM-768 keypair and an ML-DSA-65 keypair.
2. Generate a UUID v4 for `uid`.
3. Write `keys/mlkem.bin` (ek + dk) and `keys/mldsa.bin` (pk + sk).
4. Write `public.json` with the generated uid, `mlkem_public_key`, and `mldsa_public_key`.
5. Register the station as its own follower (uid, device_uid=uid, station ML-KEM and ML-DSA public keys, allowed="Allowed").

---

## 6. Envelope System

### 6.1 Concept

An **envelope** wraps a per-post symmetric key for a specific recipient using the ML-KEM-768 KEM-DEM construction (Section 4.3). The recipient's ML-KEM-768 public key is used to encapsulate a shared secret, which derives a wrap key that seals the symmetric key. Only the holder of the corresponding ML-KEM secret (decapsulation) key can open the envelope and recover the symmetric key.

### 6.2 Envelope Creation

```
Input:  sym_key (32 bytes), recipient_mlkem_pubkey (2368 hex chars)
Steps:  shared_secret, kem_ct = ML_KEM_768.encaps(recipient_mlkem_pubkey)
        wrap_key = BLAKE2b(shared_secret, digest_size=32, person=b"orbit-kem")
        sealed   = SecretBox(wrap_key).encrypt(sym_key)
Output: hex( 2-byte BE len(kem_ct) || kem_ct || sealed )  -> ~2324 hex chars
```

Implementations MUST:
- Validate that the recipient ML-KEM public key is exactly 1184 bytes (2368 hex characters).
- Skip envelope creation for invalid keys (log and continue).
- Hex-encode the envelope output using lowercase characters.

### 6.3 Envelope Opening

```
Input:  envelope_hex (~2324 hex chars), recipient_mlkem_secret (2400 bytes)
Steps:  raw = bytes.fromhex(envelope_hex)
        ct_len = int(raw[:2], big-endian); kem_ct = raw[2:2+ct_len]; sealed = raw[2+ct_len:]
        shared_secret = ML_KEM_768.decaps(recipient_mlkem_secret, kem_ct)
        wrap_key = BLAKE2b(shared_secret, digest_size=32, person=b"orbit-kem")
Output: sym_key = SecretBox(wrap_key).decrypt(sealed)   # 32 bytes
```

The recipient splits off `kem_ct` using the 2-byte length prefix, decapsulates to recover the shared secret, derives the wrap key, and SecretBox-decrypts the sealed portion.

### 6.4 User-Level Keying

Post envelopes are keyed by **UID** (not device_uid). This means:
- Each post has **one envelope per user**, regardless of how many devices that user has.
- The envelope is encapsulated to the **root device's ML-KEM public key** for that user.
- For the station owner, the envelope is always encapsulated to the station's own ML-KEM public key.

This design prevents envelope explosion (N posts * M followers * D devices) and keeps the envelopes JSON compact.

### 6.5 Self-Envelope

Every post MUST include a "self" envelope — an envelope encapsulated to the station's own ML-KEM public key, keyed by the station's uid. This ensures the station can always decrypt its own content. (Public posts are the exception: they have no envelopes at all — see Section 8.4.)

When constructing the envelope list:
1. Remove any existing entry for the station's uid.
2. Insert a self-entry at position 0, using the station's ML-KEM public key (not any delegate device key).

### 6.6 Delegate Access via Rewrap

Delegate devices cannot directly open user-level envelopes (they have different keypairs). Instead, they request an **envelope rewrap** from the station:

1. Delegate sends authenticated request: "I am device D of user U, give me access to post P."
2. Station opens the root envelope with its ML-KEM secret key -> recovers sym_key.
3. Station re-encapsulates sym_key to the delegate device's ML-KEM public key -> new envelope.
4. Station returns the device-specific envelope.

See Section 11 for the full rewrap protocol.

---

## 7. Content Encryption

### 7.1 Post Encryption Flow

When creating a new post, the station first checks the `audience_mode`.

**Public posts (`audience_mode == "public"`) take a separate, unencrypted path:**

1. Upload the raw file bytes directly to IPFS (NO symmetric key, NO encryption) -> `post_cid`.
2. Append a public manifest entry with `"audience_mode": "public"`, `"encrypted": false`, `"envelopes_cid": null`, `"envelopes_count": 0`, and any `metadata` stored **in the clear** as a plaintext JSON object (NOT a hex blob).
3. Publish the manifest and update the pointer (Steps 8–9 below).

No envelopes JSON is created. The content is world-readable via any IPFS gateway at `https://<gateway>/ipfs/<post_cid>` and discoverable through the public IPNS manifest. **Warning:** public IPFS content is permanent and world-readable; it cannot be reliably unpublished once peers have cached it.

**Encrypted posts (`self` / `specific` / `all`) execute the following steps:**

**Step 1: Generate symmetric key**
```
sym_key = random(32)  # NaCl SecretBox.KEY_SIZE
```

**Step 2: Encrypt content**
```
box = SecretBox(sym_key)
encrypted_blob = box.encrypt(plaintext_bytes)
# Output: nonce(24) + ciphertext + tag(16)
```

**Step 3: Upload to IPFS**
```
post_cid = ipfs_add_bytes(encrypted_blob)
```

**Step 4: Determine recipients**

The recipient list depends on the `audience_mode`:

| Mode | Recipients |
|------|------------|
| `self` | Station only (self-envelope) |
| `specific` | Station + explicitly listed UIDs |
| `all` | Station + all approved followers |
| `public` | None — see the unencrypted path above |

Followers are deduplicated to one entry per uid. When multiple devices exist for a uid, preference is given to the entry where `device_uid == uid` (the root device).

**Step 5: Create envelopes**
```
envelopes = {}
for each recipient:
    envelopes[recipient.uid] = mlkem_seal_key(sym_key, recipient.mlkem_public_key)  # hex KEM-DEM envelope
```

The station's self-envelope is always included, encapsulated to the station's own ML-KEM public key.

**Step 6: Publish envelopes to IPFS**
```json
{
  "v": 1,
  "post_cid": "<ipfs-cid>",
  "envelopes": {
    "<uid-1>": "<~2324-hex-mlkem-envelope>",
    "<uid-2>": "<~2324-hex-mlkem-envelope>"
  }
}
```
```
envelopes_cid = ipfs_add_bytes(compact_json(envelopes_doc))
```

**Step 7: Encrypt metadata (optional)**

If the post has associated metadata (caption, filename, etc.), it is encrypted with the same symmetric key:

```
metadata_json = compact_json(metadata_dict)
encrypted_metadata = SecretBox(sym_key).encrypt(metadata_json)
metadata_hex = encrypted_metadata.hex()
```

**Step 8: Append to manifest**

See Section 8.

**Step 9: Publish manifest to IPFS and update pointer**
```
manifest_cid = ipfs_add_bytes(compact_json(manifest))
public.json["manifest_pointer"] = manifest_cid
```

### 7.2 Content Decryption Flow

A post with `"encrypted": false` (audience_mode `public`) is fetched directly from IPFS at `post_cid` and used as-is; there is no envelope to open and metadata is already plaintext. The flows below apply only to encrypted posts.

**For the station (root device):**
1. Load manifest, find post entry by `post_cid`.
2. Fetch envelopes JSON from IPFS using `envelopes_cid`.
3. Look up envelope for own uid.
4. Open envelope with station ML-KEM secret key -> recover `sym_key`.
5. Fetch encrypted blob from IPFS using `post_cid`.
6. Decrypt blob with `SecretBox(sym_key)` -> plaintext.

**For a delegate device:**
1. Load manifest from station (via `/profile` -> `manifest_pointer` -> IPFS).
2. Send authenticated `/rewrap` request for the desired `post_cid`.
3. Receive device-specific envelope from station.
4. Open envelope with device ML-KEM secret key -> recover `sym_key`.
5. Fetch encrypted blob from IPFS using `post_cid`.
6. Decrypt blob with `SecretBox(sym_key)` -> plaintext.

**For an external follower:**
1. Fetch the station's `public.json` (via their endpoint or IPNS — see Section 18).
2. Fetch manifest from IPFS using `manifest_pointer`.
3. For each post, fetch envelopes JSON using `envelopes_cid`.
4. Look up envelope for own uid.
5. Open envelope with own ML-KEM secret key -> recover `sym_key`.
6. Fetch and decrypt the post blob.

---

## 8. Manifest System

### 8.1 Manifest Schema

The manifest is the central index of all published content. It supports multiple application-layer clients within a single document.

```json
{
  "clients": {
    "<client-name>": {
      "posts": [
        {
          "post_cid": "<ipfs-cid>",
          "audience_mode": "self | specific | all | public",
          "encrypted": true,
          "envelopes_cid": "<ipfs-cid | null>",
          "envelopes_count": 5,
          "metadata": "<hex-encrypted-json | plaintext-object>",
          "audience_uids": ["<uid>", "..."]
        }
      ]
    }
  }
}
```

### 8.2 Post Entry Fields

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `post_cid` | MUST | string | IPFS CID of the content blob (encrypted, or plaintext when `public`) |
| `audience_mode` | MUST | string | One of: `"self"`, `"specific"`, `"all"`, `"public"` |
| `encrypted` | SHOULD | boolean | `false` for `public` posts. Absent or `true` for encrypted posts. |
| `envelopes_cid` | MUST (encrypted) | string\|null | IPFS CID of the envelopes JSON document. `null` for `public` posts. |
| `envelopes_count` | SHOULD | integer | Number of envelopes (informational). `0` for `public` posts. |
| `metadata` | MAY | string \| object | For encrypted posts: hex-encoded SecretBox ciphertext of client-specific metadata JSON. For `public` posts: a plaintext JSON object (NOT a hex blob). |
| `audience_uids` | MUST if `specific` | string[] | Sorted list of UIDs when `audience_mode` is `"specific"` |

### 8.3 Envelopes JSON Document

Published separately to IPFS. One per post.

```json
{
  "v": 1,
  "post_cid": "<ipfs-cid>",
  "envelopes": {
    "<uid>": "<hex-encoded-mlkem-envelope>"
  }
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `v` | MUST | Schema version. Currently `1`. |
| `post_cid` | MUST | The post this envelope set belongs to |
| `envelopes` | MUST | Map of uid -> hex-encoded ML-KEM KEM-DEM envelope (~2324 hex chars for a 32-byte key). `public` posts have no envelopes document. |

### 8.4 Audience Modes

| Mode | Behavior |
|------|----------|
| `self` | Only the station can decrypt. No follower envelopes are created. The self-envelope is always present. |
| `specific` | The station plus an explicit list of approved follower UIDs. `audience_uids` MUST be present and sorted. |
| `all` | The station plus all followers with `allowed == "Allowed"`. |
| `public` | No encryption. The content is uploaded to IPFS in the clear with no symmetric key and no envelopes (`encrypted: false`, `envelopes_cid: null`, `envelopes_count: 0`). Metadata, if any, is stored as a plaintext JSON object. The post is readable by anyone via an IPFS gateway and discoverable through the public IPNS manifest. **Warning:** public IPFS content is permanent and world-readable. |

### 8.5 Manifest Publishing

When the manifest changes (new post, updated envelopes):

1. Serialize the manifest to compact JSON (`separators=(",", ":")`, `ensure_ascii=False`).
2. Upload to IPFS -> `manifest_cid`.
3. Update `public.json["manifest_pointer"]` to the new CID.

Since IPFS is content-addressed, every manifest change produces a new CID. Previous versions remain available on IPFS as long as they are pinned or cached by peers.

### 8.6 Legacy Manifest Migration

Implementations SHOULD support loading the legacy flat manifest format and normalizing it to the multi-client schema:

**Legacy format:**
```json
{
  "client": "orbitstagram",
  "posts": [...]
}
```

**Normalized to:**
```json
{
  "clients": {
    "orbitstagram": {
      "posts": [...]
    }
  }
}
```

The legacy `audience_mode` value `"all_followers"` MUST be normalized to `"all"`.

---

## 9. Social Graph

### 9.1 Followers (Inbound)

Followers are tracked at the **device level** in the station's local database.

**Schema:**

| Column | Type | Description |
|--------|------|-------------|
| `uid` | TEXT, NOT NULL | Follower's user ID |
| `device_uid` | TEXT, NOT NULL | Follower's device ID |
| `mlkem_public_key` | TEXT, NOT NULL | ML-KEM-768 public key (2368 hex chars) for content envelopes |
| `mldsa_public_key` | TEXT, NULL | ML-DSA-65 public key (3904 hex chars) for request verification. NULL for read-only content followers that do not authenticate. |
| `alias` | TEXT, NULL | Human-readable name |
| `allowed` | TEXT, NOT NULL, DEFAULT "Allowed" | Access status: `"Allowed"` or `"Denied"` |
| `endpoint` | TEXT, NULL | Follower's station URL |
| `ipns_id` | TEXT, NULL | Follower's IPFS peer ID for IPNS-based discovery |

**Primary key:** `(uid, device_uid)`

### 9.2 Following (Outbound)

Users the station owner follows.

| Column | Type | Description |
|--------|------|-------------|
| `uid` | TEXT, NOT NULL | Target user's ID |
| `mlkem_public_key` | TEXT, NOT NULL | Target user's ML-KEM-768 public key |
| `mldsa_public_key` | TEXT, NULL | Target user's ML-DSA-65 public key (optional) |
| `endpoint` | TEXT, NOT NULL | Target user's station URL |
| `alias` | TEXT, NULL | Human-readable name |
| `ipns_id` | TEXT, NULL | Target user's IPFS peer ID for IPNS-based discovery |

**Primary key:** `(uid)`

The `ipns_id` field enables endpoint-independent discovery. Even when a station's HTTP endpoint changes (e.g., after a Cloudflare tunnel restart), followers can resolve the station's current `public.json` via IPNS using the peer ID (see Section 18).

### 9.3 Graph Encryption

The follower and following lists are encrypted and published to IPFS for distribution to authorized followers. This uses the same SecretBox scheme as post encryption, with an ephemeral key shared via per-follower envelopes.

**Encrypted followers graph:**
```json
{
  "version": 1,
  "updated_at": "<uuid-hex>",
  "followers": [
    {
      "uid": "<uuid>",
      "device_uid": "<uuid>",
      "mlkem_public_key": "<2368-hex>",
      "mldsa_public_key": "<3904-hex | null>",
      "alias": "<string | null>",
      "allowed": "Allowed",
      "endpoint": "<url | null>",
      "ipns_id": "<peer-id | null>"
    }
  ]
}
```

**Encrypted following graph:**
```json
{
  "version": 1,
  "updated_at": "<uuid-hex>",
  "following": [
    {
      "uid": "<uuid>",
      "mlkem_public_key": "<2368-hex>",
      "mldsa_public_key": "<3904-hex | null>",
      "endpoint": "<url>",
      "ipns_id": "<peer-id | null>"
    }
  ]
}
```

Both are encrypted with a fresh ephemeral SecretBox key, uploaded to IPFS, and their CIDs stored in `public.json`.

### 9.4 Graph Decoder Envelopes

To allow followers to decrypt the social graph, the station creates decoder envelopes. Unlike post envelopes (which are user-level), graph decoder envelopes are **device-level**: each device of each follower gets its own envelope.

```json
{
  "version": 1,
  "envelopes": {
    "<follower-uid>": [
      {
        "device_uid": "<device-uuid>",
        "envelope": "<hex-mlkem-envelope>"
      }
    ]
  }
}
```

This document is published to IPFS (unencrypted JSON, since the envelopes themselves are cryptographically sealed). Its CID is stored in `public.json["follow_decoder_envelopes_cid"]`.

### 9.5 Graph Rebuild

The social graph is rebuilt and re-published whenever the follower or following list changes (follow, unfollow, new device). The rebuild process:

1. Generate a new ephemeral symmetric key.
2. Encrypt the following graph -> upload to IPFS -> `following_cid`.
3. Filter followers to `allowed == "Allowed"` only.
4. Encrypt the followers graph -> upload to IPFS -> `followers_cid`.
5. Create device-level decoder envelopes for all allowed followers -> upload to IPFS -> `follow_decoder_envelopes_cid`.
6. Update `public.json` with all three CIDs.

---

## 10. Device Pairing

### 10.1 Overview

Device pairing allows a delegate device (e.g., a phone) to authenticate with the station and gain access to content via envelope rewrapping. The pairing uses a 6-digit PIN displayed on the station and entered on the delegate device.

### 10.2 Pairing Session

| Field | Type | Description |
|-------|------|-------------|
| `pairing_id` | string | URL-safe random token (18 bytes, base64url) |
| `created_at` | integer | Unix timestamp |
| `expires_at` | integer | Unix timestamp (`created_at + 300`) |
| `device_uid` | string | The delegate device's UUID |
| `device_mlkem_public_key` | string | The delegate device's ML-KEM-768 public key (2368 hex) |
| `device_mldsa_public_key` | string | The delegate device's ML-DSA-65 public key (3904 hex) |
| `salt_hex` | string | 16-byte random salt (32 hex chars) |
| `pin_hash_hex` | string | scrypt hash of PIN (64 hex chars) |
| `attempts` | integer | Failed PIN attempts (max 5) |
| `status` | string | `"pending"` -> `"confirmed"` or `"expired"` or `"locked"` |

### 10.3 PIN Format

- 6 decimal digits, zero-padded: `000000` through `999999`
- Generated using `secrets.randbelow(10^6)`

### 10.4 Pairing Flow

**Step 1: Delegate initiates pairing**

```
POST /delegate/start
Content-Type: application/json

{
  "device_uid": "<uuid>",
  "mlkem_public_key": "<2368-hex-chars>",
  "mldsa_public_key": "<3904-hex-chars>"
}
```

Both keys are validated for correct hex length. Response:
```json
{
  "status": "ok",
  "pairing_id": "<url-safe-token>",
  "expires_in_seconds": 300
}
```

The station generates a 6-digit PIN, hashes it with scrypt, and displays the PIN to the station operator (e.g., via console, display, or notification).

**Step 2: User communicates PIN to delegate out-of-band**

The station operator reads the PIN and enters it on the delegate device (or tells it to the person holding the device). This is the trust bridge.

**Step 3: Delegate confirms pairing**

```
POST /delegate/confirm
Content-Type: application/json

{
  "pairing_id": "<url-safe-token>",
  "pin": "123456"
}
```

The station:
1. Validates `pairing_id` exists and status is `"pending"`.
2. Checks expiration (MUST be within 300 seconds of creation).
3. Checks attempt count (MUST be < 5).
4. Hashes the submitted PIN with the stored salt using scrypt.
5. Compares against stored hash using constant-time comparison.
6. On success: sets status to `"confirmed"`, registers the device as a follower with `allowed="Allowed"`, storing both the device's ML-KEM and ML-DSA public keys.
7. On failure: increments attempt count; locks session if attempts >= 5.

Response (success):
```json
{
  "status": "ok",
  "action": "delegate_added",
  "uid": "<station-uid>",
  "device_uid": "<device-uid>"
}
```

---

## 11. Envelope Rewrap Protocol

### 11.1 Purpose

Delegate devices need access to post content, but post envelopes are sealed to the station's public key (user-level keying). The rewrap protocol allows a delegate to request a device-specific envelope from the station.

### 11.2 Request

```
POST /rewrap
Content-Type: application/json
[ML-DSA Signature Authentication Headers - see Section 12]

{
  "uid": "<user-uuid>",
  "device_uid": "<device-uuid>",
  "post_cid": "<ipfs-cid>",
  "envelopes_cid": "<ipfs-cid>"    // OPTIONAL override
}
```

The `uid` and `device_uid` in the body MUST match the values in the authentication headers.

### 11.3 Server-Side Processing

1. Verify ML-DSA signature authentication (see Section 12).
2. Verify header/body uid and device_uid match.
3. Load the manifest and find the post entry matching `post_cid`.
4. Determine `envelopes_cid` (from body override or post entry).
5. Fetch the envelopes JSON from IPFS.
6. Extract the root envelope for the station's uid.
7. Open the root envelope with the station's ML-KEM secret key -> recover `sym_key`.
8. Look up the delegate device's ML-KEM public key from the followers database.
9. Re-encapsulate `sym_key` to the device's ML-KEM public key -> new ML-KEM envelope.
10. Return the device-specific envelope.

### 11.4 Response

**Success:**
```json
{
  "status": "ok",
  "result": {
    "status": "rewrap_ok",
    "uid": "<user-uuid>",
    "device_uid": "<device-uuid>",
    "post_cid": "<ipfs-cid>",
    "envelope": "<~2324-hex-mlkem-envelope>"
  }
}
```

**Error:**
```json
{
  "status": "ok",
  "result": {
    "error": "<error-description>"
  }
}
```

### 11.5 Security Requirements

- The delegate device MUST be registered in the followers table with `allowed == "Allowed"`.
- The request MUST pass ML-DSA signature authentication.
- The station MUST NOT return envelopes for devices that are not authorized.

---

## 12. Authentication Scheme

### 12.1 Overview

Authenticated endpoints use **ML-DSA-65 (FIPS 204) digital signatures**. The delegate device signs the canonical request string with its ML-DSA-65 secret key; the station verifies the signature using the device's ML-DSA-65 public key stored in the followers table. This provides device authentication (only paired devices holding the secret key can produce valid signatures) and request integrity. There is no shared secret and no symmetric auth key.

### 12.2 Keys

```
signing key:      the device's ML-DSA-65 secret key (held only by the device)
verification key: the device's ML-DSA-65 public key (stored by the station as mldsa_public_key)
```

Unlike the previous HMAC scheme, the station and device do NOT share a secret. The station never needs the device's secret key; it only verifies signatures against the stored public key.

### 12.3 Canonical String

The signed message is constructed by joining the following fields with newline (`\n`) separators:

```
METHOD\nPATH\nUID\nDEVICE_UID\nTIMESTAMP\nNONCE\nBODY_SHA256
```

| Component | Format | Example |
|-----------|--------|---------|
| METHOD | Uppercase HTTP method | `POST` |
| PATH | Request path (no query string) | `/rewrap` |
| UID | User UUID string | `52dd6e1a-...` |
| DEVICE_UID | Device UUID string | `a1b2c3d4-...` |
| TIMESTAMP | Unix epoch seconds (decimal string) | `1704067200` |
| NONCE | Random hex string (SHOULD be >= 16 bytes / 32 hex chars) | `a3f2...` |
| BODY_SHA256 | Lowercase hex SHA-256 of the raw request body | `e3b0c442...` |

The canonical string is UTF-8 encoded before signing. The canonical string format is unchanged from the previous HMAC scheme.

### 12.4 Signature Computation

```
signature = ML_DSA_65.sign(device_mldsa_secret_key, canonical_string_bytes)   # 3309 bytes
```

The signature is **base64-encoded** for transmission (~4412 base64 characters) in the `x-orbit-sig` header. The station decodes the base64 and verifies with `ML_DSA_65.verify(device_mldsa_public_key, canonical_string_bytes, signature)`.

### 12.5 HTTP Headers

Authenticated requests MUST include the following headers:

| Header | Value |
|--------|-------|
| `x-orbit-uid` | User UUID |
| `x-orbit-device` | Device UUID |
| `x-orbit-ts` | Unix timestamp (seconds) |
| `x-orbit-nonce` | Random hex string |
| `x-orbit-body-sha256` | Lowercase hex SHA-256 of request body |
| `x-orbit-sig` | Base64-encoded ML-DSA-65 signature over the canonical string |

### 12.6 Server Verification

The station verifies authenticated requests in this order:

1. **Time window:** `|now - timestamp| <= 60` seconds. Reject if stale.
2. **Device authorization:** Look up device in followers table. MUST have `allowed == "Allowed"` AND have a stored `mldsa_public_key`.
3. **Replay protection:** Check nonce against the nonce table. Reject if seen before. (The nonce is recorded only after the signature verifies — see step 6.)
4. **Body integrity:** If the middleware captured a body SHA-256, compare against the header value (constant-time).
5. **Signature verification:** Decode the device's ML-DSA public key and the base64 `x-orbit-sig` value, then verify the signature over the canonical string with `ML_DSA_65.verify`.
6. **Record nonce:** After successful verification, store the nonce in the database to prevent replay.

**Error responses:**

| Condition | HTTP Status | Detail |
|-----------|-------------|--------|
| Bad timestamp format | 401 | `"bad timestamp"` |
| Stale request | 401 | `"stale request"` |
| Device not found/allowed | 403 | `"device not authorized"` |
| Device has no ML-DSA public key | 403 | `"device has no auth (ML-DSA) public key"` |
| Nonce replay | 401 | `"replay"` |
| Body hash mismatch | 401 | `"bad body hash"` |
| Malformed device public key | 401 | `"bad device auth public key"` |
| Wrong device public key length | 401 | `"bad device auth public key length"` |
| Malformed signature encoding | 401 | `"bad signature encoding"` |
| Signature verification failed | 401 | `"bad auth"` |

### 12.7 Nonce Management

- Nonces are stored per (uid, device_uid, nonce) triple.
- Nonce TTL: 24 hours. Expired nonces are periodically cleaned up.
- Nonces MUST be unique per device per time window.

---

## 13. Inbox & Follow Requests

### 13.1 Follow Request (Multi-Device)

External users send follow requests to a station's inbox to request access to content.

```
POST /inbox
Content-Type: application/json

{
  "type": "follow_request",
  "uid": "<follower-uuid>",
  "devices": [
    {
      "device_uid": "<device-uuid>",
      "mlkem_public_key": "<2368-hex-chars>",
      "mldsa_public_key": "<3904-hex-chars | optional>"
    }
  ]
}
```

**Processing:**
1. Validate that the follower uid is not the station's own uid (prevents self-injection).
2. Validate each device entry has a valid `device_uid` and a 2368-hex-char `mlkem_public_key`; if `mldsa_public_key` is present it MUST be 3904 hex chars.
3. Check device cap: max 20 devices per follower (configurable via `ORBIT_MAX_DEVICES_PER_FOLLOWER`).
4. Register each device in the followers table.
5. If any new devices were added or keys rotated, optionally trigger envelope rewrap for all existing posts.

**Response:**
```json
{
  "status": "ok",
  "result": {
    "status": "follow_accepted_multi_device",
    "rewrap_triggered": true
  }
}
```

### 13.2 Follow Request (Legacy Single-Device)

```json
{
  "type": "follow_request",
  "uid": "<follower-uuid>",
  "mlkem_public_key": "<2368-hex-chars>",
  "mldsa_public_key": "<3904-hex-chars | optional>"
}
```

The uid is used as both uid and device_uid. Behaves the same as multi-device with a single entry.

### 13.3 Auto-Rewrap on Follow Change

When a new follower is accepted (or an existing follower's key changes), the station MAY automatically rewrap all post envelopes to include the new follower. This is controlled by the `ORBIT_AUTO_REWRAP_ON_FOLLOW_CHANGE` environment variable (default: enabled).

The rewrap process:
1. For each post in the manifest:
   a. Decrypt the root envelope -> recover `sym_key`.
   b. Rebuild the envelope map including the new follower.
   c. Publish updated envelopes JSON to IPFS -> new `envelopes_cid`.
   d. Update the post entry in the manifest.
2. Publish the updated manifest to IPFS.
3. Update `public.json["manifest_pointer"]`.

### 13.4 Follow Request Authentication

The `POST /inbox` endpoint does NOT require signature authentication for `follow_request` messages. This allows external users to send follow requests without prior key exchange. All other inbox message types MUST be authenticated.

### 13.5 Future Inbox Message Types

The following message types are reserved for future use:
- `post_key_update` — notification that post envelopes have been updated
- `manifest_update` — notification that the manifest has changed

---

## 14. API Reference

### 14.1 Public Endpoints

#### `GET /profile`

Returns the station's public identity document.

**Authentication:** None

**Response:** `public.json` contents (see Section 5.3), including `ipfs_peer_id` for IPNS discovery.

#### `GET /health`

Returns station health status.

**Authentication:** None

**Response:** `{"status": "healthy" | "degraded", "checks": {"database": bool, "ipfs": bool, "identity": bool}}`. HTTP 200 when all checks pass, 503 otherwise.

#### `GET /storage`

Returns IPFS repo usage, device disk usage, and a per-client storage breakdown computed from the manifest.

**Authentication:** None

> NOTE: this endpoint is currently unauthenticated and reveals repo/disk usage figures. Place it behind auth or remove it if that is sensitive in your deployment.

### 14.2 Unauthenticated Endpoints

#### `POST /inbox`

Receives inbox messages. Unauthenticated for `follow_request` type; authenticated for all others.

**Request body:** `InboxMessage` (see Section 13)

### 14.3 Authenticated Endpoints

All authenticated endpoints require the ML-DSA signature headers (Section 12.5).

#### `POST /post`

Create a new encrypted post.

**Content-Type:** `multipart/form-data`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file` | binary | MUST | Raw file content (encrypted unless `audience_mode` is `public`) |
| `metadata` | string (JSON) | MAY | Client-specific metadata JSON string |
| `client` | string | MAY | Client namespace (defaults to `default`) |
| `audience_mode` | string | MAY | One of `self`, `specific`, `all` (default), `public` |
| `audience_uids` | string (JSON array or CSV) | MUST if `specific` | Target UIDs when `audience_mode` is `specific` |

When `audience_mode` is `public`, the file is uploaded unencrypted and any `metadata` is stored in the clear (see Section 7.1 and the warning in Section 8.4).

**Response:**
```json
{
  "status": "post_ok",
  "cid": "<post-ipfs-cid>",
  "envelopes_cid": "<envelopes-ipfs-cid>",
  "audience_mode": "all",
  "audience_uids": null,
  "followers_raw": 5,
  "followers_used": 5,
  "manifest_posts": 4
}
```

#### `POST /rewrap`

Request an envelope rewrap for a delegate device. See Section 11.

#### `POST /follow`

Add an outbound follow (the station owner starts following another user).

**Request body:**
```json
{
  "uid": "<target-uuid>",
  "endpoint": "<target-station-url>",
  "mlkem_public_key": "<target-2368-hex>",
  "mldsa_public_key": "<target-3904-hex | optional>",
  "ipns_id": "<target-peer-id | optional>"
}
```

Triggers a social graph rebuild (Section 9.5).

#### `POST /unfollow`

Remove an outbound follow.

**Request body:**
```json
{
  "uid": "<target-uuid>"
}
```

Triggers a social graph rebuild.

#### `GET /followers`

List user-level followers for a share picker: Allowed followers deduplicated to one entry per uid, excluding the station's own uid.

**Response:**
```json
{
  "status": "ok",
  "followers": [
    { "uid": "...", "alias": "... | null", "endpoint": "... | null", "ipns_id": "... | null" }
  ]
}
```

#### `POST /post/delete`

Remove a post from the manifest, unpin its content + envelopes from IPFS, and run garbage collection.

**Request body:**
```json
{ "post_cid": "<cid>", "client": "<client | optional>" }
```

Returns 404 if the post is not found in the manifest.

#### `POST /post/share`

Re-wrap an existing post for a new audience (re-issue envelopes without re-uploading content). The station recovers the post's symmetric key from its own self-envelope and re-encrypts it for the new recipient set.

**Request body:**
```json
{
  "post_cid": "<cid>",
  "audience_mode": "specific",
  "audience_uids": ["<uid>", "..."],
  "client": "<client | optional>"
}
```

`audience_mode` accepts `self`, `specific`, or `all` — **not** `public` (resharing to/from `public` is unsupported; create a new public post instead). Returns 400 on an invalid audience and 404 if the post is not found.

### 14.4 Pairing Endpoints

#### `POST /delegate/start`

Initiate device pairing. See Section 10.4, Step 1.

**Authentication:** None

#### `POST /delegate/confirm`

Confirm device pairing with PIN. See Section 10.4, Step 3.

**Authentication:** None

---

## 15. Message Flows

### 15.1 Post Creation (Station)

```
Station                         IPFS
  |                               |
  |  1. Generate sym_key (32B)    |
  |  2. Encrypt content           |
  |  3. Upload encrypted blob --->|---> post_cid
  |  4. Build per-uid envelopes   |
  |  5. Upload envelopes JSON --->|---> envelopes_cid
  |  6. Update manifest           |
  |  7. Upload manifest --------->|---> manifest_cid
  |  8. Update public.json        |
  |                               |
```

### 15.2 Content Retrieval (Delegate)

```
Delegate                    Station                     IPFS
  |                           |                           |
  |  1. GET /profile -------->|                           |
  |  <-- public.json ---------|                           |
  |                           |                           |
  |  2. Fetch manifest ---------------------------------->|
  |  <-- manifest JSON -----------------------------------|
  |                           |                           |
  |  3. POST /rewrap -------->|                           |
  |     (authenticated)       |  4. Fetch envelopes ----->|
  |                           |  <-- envelopes JSON ------|
  |                           |  5. Decrypt root envelope |
  |                           |  6. Re-encrypt for device |
  |  <-- device envelope -----|                           |
  |                           |                           |
  |  7. Decrypt envelope      |                           |
  |     -> sym_key            |                           |
  |  8. Fetch post blob --------------------------------->|
  |  <-- encrypted blob ----------------------------------|
  |  9. Decrypt with sym_key  |                           |
  |     -> plaintext          |                           |
```

### 15.3 Follower Enrollment

```
Follower                    Station
  |                           |
  |  1. POST /inbox           |
  |     {type: follow_request |
  |      uid, devices}        |
  |  ----------------------->|
  |                           |  2. Validate uid != self
  |                           |  3. Check device cap
  |                           |  4. Register devices
  |                           |  5. Rewrap all posts (optional)
  |                           |  6. Rebuild social graph
  |  <-- follow_accepted -----|
  |                           |
```

### 15.4 Device Pairing

```
Delegate                    Station                     Operator
  |                           |                           |
  |  1. POST /delegate/start  |                           |
  |  {device_uid, mlkem_pk,   |                           |
  |   mldsa_pk}               |                           |
  |  ----------------------->|                            |
  |                           |  2. Generate PIN           |
  |                           |  3. Hash PIN (scrypt)      |
  |                           |  4. Store session          |
  |  <-- {pairing_id} --------|  5. Display PIN ---------->|
  |                           |                           |
  |                           |        6. Out-of-band     |
  |  <------- PIN communicated via voice/display ---------|
  |                           |                           |
  |  7. POST /delegate/confirm|                           |
  |     {pairing_id, pin}     |                           |
  |  ----------------------->|                            |
  |                           |  8. Verify PIN             |
  |                           |  9. Register device        |
  |  <-- {delegate_added} ----|                           |
```

### 15.5 External Follower Content Retrieval

```
Follower                                            IPFS
  |                                                   |
  |  1. Fetch station's public.json (via endpoint) -->|
  |  <-- public.json ----------------------------------|
  |                                                   |
  |  2. Fetch manifest (manifest_pointer) ----------->|
  |  <-- manifest JSON --------------------------------|
  |                                                   |
  |  3. For each post of interest:                    |
  |     a. Fetch envelopes (envelopes_cid) ---------->|
  |     <-- envelopes JSON ----------------------------|
  |     b. Find envelope for own uid                  |
  |     c. Decrypt envelope -> sym_key                |
  |     d. Fetch post blob (post_cid) --------------->|
  |     <-- encrypted blob ----------------------------|
  |     e. Decrypt blob -> plaintext                  |
  |     f. If metadata present: decrypt metadata      |
```

### 15.6 IPNS Discovery Flow

```
Follower                    IPFS DHT                    Station
  |                           |                           |
  |  1. Resolve IPNS name     |                           |
  |     /ipns/<peer-id> ----->|                           |
  |                           |  (DHT lookup)             |
  |  <-- /ipfs/<cid> ---------|                           |
  |                           |                           |
  |  2. Fetch public.json     |                           |
  |     via CID ------------->|                           |
  |  <-- public.json ---------|                           |
  |                           |                           |
  |  3. Read endpoint URL     |                           |
  |     from public.json      |                           |
  |  4. Connect to station ------------------------------>|
  |  <-- direct API access --------------------------------|
```

This flow allows followers to find a station even when its HTTP endpoint has changed, as long as the IPNS record is current.

---

## 16. Client Extension Model

### 16.1 Overview

The Orbit protocol is designed to support multiple application-layer clients sharing the same identity, encryption, and access-control infrastructure. Each client defines its own namespace within the manifest and its own metadata schema.

### 16.2 Adding a New Client

To add a new client type:

1. Choose a unique client name (lowercase, alphanumeric + hyphens recommended).
2. Define a metadata schema for your client's post type.
3. When creating posts, specify your client name so entries are placed under `manifest["clients"]["<your-client>"]`.
4. Encrypt metadata using the same per-post symmetric key.

### 16.3 Required vs. Client-Specific Fields

**Required fields** (all clients MUST include these in each post entry):

| Field | Description |
|-------|-------------|
| `post_cid` | IPFS CID of content (encrypted, or plaintext when `public`) |
| `audience_mode` | Access control mode |
| `envelopes_cid` | IPFS CID of envelopes document (`null` for `public` posts) |

**Client-specific fields** (carried in the `metadata` field):

Each client defines its own JSON schema for metadata. For encrypted posts the metadata is encrypted (as a hex blob) with the same symmetric key as the post content, so only authorized recipients can read it. For `public` posts the metadata is stored as a plaintext JSON object and is world-readable.

### 16.4 Example Client Schemas

**orbitstagram** (photo/video sharing):
```json
{
  "caption": "Sunset at the beach",
  "timestamp": 1704067200,
  "location": {"lat": 37.7749, "lon": -122.4194},
  "content_type": "image/jpeg",
  "width": 1920,
  "height": 1080
}
```

**orbitdrive** (file storage):
```json
{
  "filename": "report.pdf",
  "mime_type": "application/pdf",
  "size_bytes": 1048576,
  "created_at": 1704067200,
  "modified_at": 1704070800,
  "path": "/documents/work/"
}
```

**orbitdocs** (document collaboration):
```json
{
  "title": "Project Proposal",
  "version": 3,
  "authors": ["alice", "bob"],
  "format": "markdown",
  "word_count": 2450
}
```

### 16.5 Client Naming Conventions

- Client names SHOULD be lowercase and use only `[a-z0-9-]`.
- To avoid collisions, third-party clients SHOULD use a namespaced format: `orgname-clienttype` (e.g., `acme-photos`).
- The names `default`, `orbit`, and `system` are RESERVED.

### 16.6 Client Versioning

Clients MAY add a `version` field to their namespace object:

```json
{
  "clients": {
    "orbitdrive": {
      "version": 2,
      "posts": [...]
    }
  }
}
```

Clients SHOULD handle older versions gracefully by migrating data in-memory when reading.

---

## 17. Security Considerations

### 17.1 Threat Model

The Orbit protocol is designed to protect against:

- **Passive network observers:** All content is encrypted before leaving the station. IPFS peers see only encrypted blobs.
- **Compromised IPFS nodes:** Content is encrypted at rest. CIDs reveal content existence but not content.
- **Unauthorized followers:** Only approved followers with valid envelopes can decrypt content.

The protocol does NOT protect against:

- **Compromised station:** If the station's secret keys are compromised, all past and future content is exposed.
- **Compromised recipient:** A follower who has decrypted content can redistribute it.
- **Traffic analysis:** Post timing, frequency, and blob sizes are visible to IPFS peers.

### 17.2 Forward Secrecy

Each post uses a fresh random 32-byte symmetric key. Compromising one post's key does not reveal other posts' content. However, the station's root ML-KEM secret key can open all post envelopes (since the self-envelope is always present), so forward secrecy is bounded by the root key's integrity.

The protocol is now **post-quantum** for both confidentiality (ML-KEM-768 key encapsulation) and authentication (ML-DSA-65 signatures). Captured ciphertext is not exposed to a future quantum adversary performing "harvest now, decrypt later" attacks on the asymmetric layer, and request signatures cannot be forged via quantum attacks on the auth keypair.

### 17.3 Metadata Privacy

- **Encrypted metadata:** Post metadata (captions, filenames, etc.) is encrypted with the same key as the post content. Only authorized recipients can read it.
- **Manifest visibility:** The manifest itself is published to IPFS unencrypted. This reveals: number of posts, audience modes, number of envelopes per post, and post CIDs. Implementations concerned about this SHOULD consider encrypting the manifest.
- **Social graph encryption:** Follower and following lists are encrypted before IPFS publication.
- **Public posts:** Posts with `audience_mode == "public"` are uploaded to IPFS unencrypted, with plaintext metadata, and are world-readable via any IPFS gateway. Such content is permanent: once peers have cached it, it cannot be reliably unpublished. Clients SHOULD warn users before creating public posts.

### 17.4 Device Revocation

To revoke a delegate device's access:

1. Set the device's `allowed` status to `"Denied"` in the followers table.
2. Rebuild all post envelopes excluding the revoked device's user-level envelope (if this was their only device).
3. Republish the manifest.
4. Rebuild and republish the social graph.

Note: The revoked device may still have cached decryption keys for previously-accessed posts. Revocation only prevents access to future posts and future rewrap requests.

### 17.5 Rate Limiting

- **PIN attempts:** Device pairing is limited to 5 PIN attempts per session.
- **Device cap:** Each follower is limited to 20 devices (configurable).
- **Time window:** Authentication requests must be within 60 seconds of current time.

### 17.6 Self-UID Injection Prevention

Follow requests targeting the station's own uid MUST be rejected. This prevents an attacker from registering a device under the station owner's uid, which could grant unintended access to the self-envelope.

### 17.7 Post-Quantum Library Maturity

Orbit's post-quantum primitives are provided by a pluggable backend, selected via the `ORBIT_PQC_BACKEND` environment variable:

- **`python`** (default fallback) — pure-Python `kyber-py` (ML-KEM-768) and `dilithium-py` (ML-DSA-65). These are NOT constant-time and are self-described as educational. Chosen because they install with no native build (piwheels-friendly on a Raspberry Pi).
- **`liboqs`** — the Open Quantum Safe C library via the `oqs` binding. **Constant-time and hardened**, but requires a native build (cmake + C compiler).
- **`auto`** (default) — use `liboqs` if it imports AND passes a startup self-test (ML-KEM and ML-DSA round-trips), otherwise fall back to `python`. The self-test guarantees a broken or version-mismatched backend never goes live.

Both backends implement the same FIPS 203 / FIPS 204 standards with identical key, ciphertext, and signature encodings, so envelopes and signatures are interoperable across backends and the KEM-DEM wire format (Section 6) is backend-independent. A station may switch backends without re-bootstrapping its identity.

In Orbit's trust model, ML-KEM decapsulation and ML-DSA signing happen client-side on the device holding the secret key — never as a server-side oracle that an attacker can repeatedly query — so timing side-channels in the pure-Python backend are low-risk in practice. Implementers whose threat model includes a high-rate timing oracle SHOULD deploy the `liboqs` backend.

---

## 18. IPFS & IPNS Integration

### 18.1 IPFS Daemon

The station MUST run a local IPFS daemon (e.g., Kubo) with the HTTP API enabled on port 5001 (default). For resource-constrained devices (Raspberry Pi), the `lowpower` profile is RECOMMENDED.

The IPFS API and Gateway SHOULD be bound to localhost only (`/ip4/127.0.0.1/tcp/5001` and `/ip4/127.0.0.1/tcp/8080`) to prevent unauthorized access.

### 18.2 API Operations

**Upload content:**
```
POST http://127.0.0.1:5001/api/v0/add
Content-Type: multipart/form-data

file=<binary-data>
```

Response includes `"Hash"` field containing the CID.

**Fetch content:**
```
POST http://127.0.0.1:5001/api/v0/cat?arg=<CID>
```

Response body contains the raw bytes.

**Get node identity:**
```
POST http://127.0.0.1:5001/api/v0/id
```

Response includes `"ID"` (the peer ID), `"PublicKey"`, and `"Addresses"`.

### 18.3 Pinning

The station SHOULD pin all CIDs it publishes to ensure content remains available. This includes:
- Post blobs (`post_cid`)
- Envelopes documents (`envelopes_cid`)
- Manifest versions (`manifest_pointer`)
- Encrypted social graphs (`followers_cid`, `following_cid`, `follow_decoder_envelopes_cid`)
- The station's `public.json` (published to IPFS for IPNS resolution)

Old manifest versions and superseded envelope documents MAY be unpinned to reclaim storage.

### 18.4 Content Addressing

IPFS uses content-based addressing: the CID is a cryptographic hash of the content. This provides:
- **Integrity:** Content at a CID always matches the expected hash.
- **Deduplication:** Identical content produces the same CID.
- **Immutability:** Published content cannot be altered without changing the CID.

### 18.5 IPNS — Permanent Station Discovery

IPNS (InterPlanetary Name System) provides a mutable pointer that maps a station's IPFS **peer ID** to the CID of its current `public.json`. This solves the problem of changing CIDs: every time `public.json` is updated (new manifest, new endpoint URL, etc.), the content hash changes, but the IPNS name (the peer ID) stays the same.

#### 18.5.1 How IPNS Works

Each IPFS node has a cryptographic identity (peer ID) derived from its keypair. IPNS allows the node to sign a record saying "my peer ID currently points to CID X" and publish that record to the DHT. Anyone who knows the peer ID can resolve the current CID.

```
Peer ID (stable)  --IPNS-->  /ipfs/<CID>  --IPFS-->  public.json
```

#### 18.5.2 Publishing

The station publishes its `public.json` to IPNS whenever the document changes. The publishing flow:

1. Serialize `public.json` to bytes.
2. Upload to IPFS: `cid = ipfs_add_bytes(public_json_bytes)`.
3. Publish to IPNS: `ipfs_name_publish(cid, lifetime="8760h")`.

The `lifetime` parameter controls how long the IPNS record is valid before it needs to be refreshed. Stations SHOULD use a long lifetime (e.g., `8760h` = 1 year) and re-publish periodically to keep the record fresh.

**IPNS Publish API:**
```
POST http://127.0.0.1:5001/api/v0/name/publish?arg=<CID>&lifetime=8760h
```

Response:
```json
{
  "Name": "<peer-id>",
  "Value": "/ipfs/<cid>"
}
```

#### 18.5.3 Resolution

Followers (or any party) can resolve a station's current `public.json` using only the peer ID:

**IPNS Resolve API:**
```
POST http://127.0.0.1:5001/api/v0/name/resolve?arg=<peer-id>
```

Response:
```json
{
  "Path": "/ipfs/<cid>"
}
```

Public gateways also support IPNS resolution:
```
https://ipfs.io/ipns/<peer-id>
```

#### 18.5.4 Peer ID as a Stable User Address

The IPFS peer ID serves as a **permanent, location-independent address** for a station. Unlike HTTP endpoints (which change with IP addresses, tunnels, or DNS), the peer ID is derived from the IPFS node's keypair and remains constant for the lifetime of the node.

This means:
- A follower only needs to know a station's peer ID to find it.
- The station can change its IP address, domain name, or Cloudflare tunnel URL without breaking discoverability.
- The peer ID is stored in `public.json["ipfs_peer_id"]` and in the social graph's `ipns_id` field for each follower/following entry.
- Followers can always fall back to IPNS resolution if the station's HTTP endpoint is unreachable.

#### 18.5.5 Discovery Priority

Clients SHOULD attempt to reach a station in this order:

1. **Direct endpoint:** Use the `endpoint` URL from the station's `public.json` or social graph entry (fastest).
2. **IPNS resolution:** If the endpoint is unreachable, resolve `ipns_id` via IPNS to get the current `public.json`, which contains the updated endpoint.
3. **IPFS gateway:** As a last resort, fetch `public.json` via a public IPFS gateway: `https://ipfs.io/ipns/<peer-id>`.

#### 18.5.6 IPNS Publishing Triggers

The station SHOULD publish to IPNS whenever `public.json` changes materially:

- **Endpoint change:** When the Cloudflare tunnel URL changes (detected by the tunnel monitor).
- **Manifest update:** When new posts are published (the `manifest_pointer` CID changes).
- **Social graph rebuild:** When followers/following lists change.
- **Identity update:** When the alias or other identity fields change.

The tunnel monitor daemon automatically handles endpoint changes by polling the tunnel URL and re-publishing to IPNS when it detects a change.

### 18.6 Retry and Timeout Policy

IPFS operations use exponential-backoff retry on transient errors (connection errors, timeouts). Non-transient HTTP errors (4xx) are raised immediately.

| Operation | Timeout | Notes |
|-----------|---------|-------|
| `add` (upload) | Configurable (default 30s) | Standard timeout |
| `cat` (download) | Configurable (default 30s) | Standard timeout |
| `name/publish` | 60s | IPNS DHT publishing is slow |
| `name/resolve` | 30s | DHT resolution can be slow |
| `id` | Configurable (default 30s) | Local operation, fast |

Maximum retries default to 3 with exponential backoff (1s, 2s, 4s).

---

## 19. Station Setup & Installation

### 19.1 Overview

The `install.sh` script automates the complete setup of an Orbit station on a Raspberry Pi or similar Linux device. It installs all dependencies, configures services, bootstraps identity, and starts the station — producing a fully operational node in a single command.

### 19.2 Prerequisites

- A Linux system (Debian/Ubuntu-based, tested on Raspberry Pi OS)
- `sudo` access
- Internet connectivity for downloading dependencies

### 19.3 Supported Architectures

| Architecture | `uname -m` | IPFS Binary | Cloudflared |
|-------------|------------|-------------|-------------|
| ARM 64-bit | `aarch64`, `arm64` | `linux-arm64` | `linux-arm64` |
| ARM 32-bit | `armv7l`, `armhf` | `linux-arm` | `linux-arm` |
| x86 64-bit | `x86_64` | `linux-amd64` | `linux-amd64` |

### 19.4 Installation Steps

The installer executes the following steps in order:

**Step 1: Python Detection**

The installer searches for Python 3.11+ by probing `python3.12`, `python3.11`, and `python3` in order. If none is found, it installs Python via `apt-get`. The minimum version requirement is Python 3.11.

**Step 2: System Dependencies**

Installs required system packages:
- `git`, `curl`, `openssl` — general utilities
- `ufw` — firewall management
- `python3-venv` — Python virtual environment support
- `libsodium-dev` — NaCl cryptography library (required by PyNaCl)

The post-quantum libraries `kyber-py` (ML-KEM-768) and `dilithium-py` (ML-DSA-65) are pure-Python and installed via pip from `requirements.txt` (Step 6). They are piwheels-installable on a Raspberry Pi with no native build, so no additional system packages are required.

**Step 3: IPFS (Kubo) Installation**

Downloads and installs the Kubo IPFS daemon (v0.28.0) from `dist.ipfs.tech`. The binary is placed at `/usr/local/bin/ipfs`. Skipped if IPFS is already installed.

**Step 4: Cloudflared Installation (Optional)**

Downloads the `cloudflared` binary for Cloudflare Quick Tunnel support. This enables zero-configuration public access without port forwarding. Gracefully skipped if the architecture is unsupported. See Section 19.7 for details.

**Step 5: IPFS Initialization**

Initializes the IPFS repository with the `lowpower` profile (suitable for Raspberry Pi). Configures the API and Gateway to bind to localhost only for security.

**Step 6: Python Virtual Environment**

Creates a Python virtual environment at `$ORBIT_DIR/.venv` and installs all dependencies from `requirements.txt`.

**Step 7: Environment Configuration**

Copies `.env.example` to `.env` on first run. If Cloudflared is available, automatically enables the tunnel in `.env`.

**Step 8: Identity Bootstrap**

Calls `orbit_node.identity.load_identity()` which:
1. Generates an ML-KEM-768 keypair and an ML-DSA-65 keypair.
2. Generates a UUID v4.
3. Writes `orbit_data/keys/mlkem.bin` (ek + dk) and `orbit_data/keys/mldsa.bin` (pk + sk).
4. Writes `orbit_data/public.json` with the identity fields.
5. Registers the station as its own follower.

**Step 9: Systemd Services**

Creates and enables three systemd service units:

| Service | Description | Dependencies |
|---------|-------------|--------------|
| `ipfs.service` | IPFS daemon with garbage collection | `network.target` |
| `orbit.service` | Orbit FastAPI server | `ipfs.service` |
| `cloudflared-tunnel.service` | Cloudflare Quick Tunnel (optional) | `orbit.service` |

All services are configured with `Restart=on-failure` for automatic recovery.

**Step 10: Firewall**

Opens the Orbit port (default 8443/tcp) using UFW and force-enables the firewall.

**Step 11: Service Startup**

Starts IPFS first (with a 3-second delay for initialization), then the Orbit service, then optionally the Cloudflare tunnel.

### 19.5 Post-Installation Output

After installation, the script displays:
- Service status for IPFS, Orbit, and (optionally) the tunnel
- The station's **IPFS Peer ID** — the permanent address for IPNS discovery
- The IPNS URL: `https://ipfs.io/ipns/<peer-id>`
- LAN access URL
- Tunnel URL location (appears in logs within ~30 seconds)
- Useful management commands

### 19.6 Directory Layout

After installation, the station's data directory has this structure:

```
orbit_data/
├── keys/
│   ├── mlkem.bin             # ML-KEM-768 keypair (ek 1184 + dk 2400 = 3584 bytes)
│   └── mldsa.bin             # ML-DSA-65 keypair (pk 1952 + sk 4032 = 5984 bytes)
├── public.json               # Public identity document
├── manifests/
│   └── manifest.json         # Local manifest cache
├── orbit.db                  # SQLite database
├── ssl/
│   ├── cert.pem              # Self-signed TLS certificate
│   └── key.pem               # TLS private key
├── followers.json            # Plaintext followers (local inspection only)
├── following.json            # Plaintext following (local inspection only)
└── follow_envelopes.json     # Plaintext envelopes (local inspection only)
```

### 19.7 Cloudflare Quick Tunnel

The station supports Cloudflare Quick Tunnel for zero-configuration public access. This provides:

- **No port forwarding required.** The tunnel creates an outbound connection from the station to Cloudflare's edge, bypassing NAT and firewall restrictions.
- **Automatic HTTPS.** Cloudflare provides a valid TLS certificate for the tunnel URL.
- **Dynamic URLs.** Quick Tunnel URLs are randomly generated (e.g., `https://verb-noun-thing.trycloudflare.com`) and may change on restart.

The tunnel monitor daemon (a background thread started on FastAPI startup) handles URL changes:

1. Polls cloudflared's metrics endpoint (`http://localhost:40469/quicktunnel`) every 3 seconds during initial detection, then every 60 seconds.
2. When the tunnel URL changes, updates `public.json["endpoint"]`.
3. Re-publishes `public.json` to IPFS and updates the IPNS pointer.

Because tunnel URLs are ephemeral, IPNS is critical for ensuring followers can always find the station (see Section 18.5).

---

## 20. Backward Compatibility

### 20.0 Post-Quantum Cutover (Hard Break)

The migration from X25519/SealedBox/HMAC to ML-KEM-768 + ML-DSA-65 is a **hard breaking change with no migration path** from X25519-era stations. There is no on-the-wire or on-disk interoperability:

- The `public_key` field and the `keys/private.bin` file are gone, replaced by `mlkem_public_key`/`mldsa_public_key` and the `keys/mlkem.bin`/`keys/mldsa.bin` files.
- Content envelopes are ML-KEM KEM-DEM blobs (~2324 hex chars), not 160-hex SealedBox blobs.
- The `x-orbit-hmac` header is replaced by `x-orbit-sig` (base64 ML-DSA signature).

Clients MUST implement ML-KEM envelope opening (Section 6.3) and ML-DSA request signing (Section 12) to interoperate. There is no fallback to the legacy scheme.

### 20.1 Manifest Format

Implementations MUST accept both the legacy flat format and the current multi-client format, normalizing to multi-client on read (see Section 8.6).

### 20.2 Audience Mode

The legacy value `"all_followers"` MUST be normalized to `"all"` on read.

### 20.3 Envelope Encoding

Content envelopes are hex-encoded ML-KEM KEM-DEM blobs (Section 6.2). The legacy X25519 SealedBox envelopes (hex or base64) are NOT interoperable with this format and are not supported for reading (see Section 20.0).

### 20.4 Post CID Field

Legacy manifests used `"cid"` instead of `"post_cid"`. Implementations MUST check both field names.

### 20.5 Database Migrations

The `ipns_id` column was added to the `followers` and `following` tables after the initial schema. Implementations MUST handle databases that lack this column by running `ALTER TABLE ... ADD COLUMN ipns_id TEXT NULL` on startup. SQLite's `OperationalError` for duplicate columns is silently ignored.

---

## 21. Future Work

- **Content deletion/expiry:** Mechanism for removing posts and notifying followers to discard cached keys.
- **Manifest sharding:** For stations with large post counts, split the manifest into paginated segments.
- **Federation/discovery:** DNS-based or relay-based discovery of stations; cross-station search.
- **Key rotation:** Formal protocol for rotating the station's root keypair while maintaining access to historical content.
- **Manifest encryption:** Option to encrypt the manifest itself, hiding post metadata from unauthorized IPFS observers.
- **Streaming/chunked uploads:** Support for large files via IPFS UnixFS chunking with per-chunk encryption.
- **IPNS over PubSub:** Faster IPNS propagation using IPFS PubSub for real-time updates instead of DHT polling.
- **Multi-station federation:** Allow a user to run multiple stations that share the same identity and synchronize manifests.

---

## Appendix A: Database Schema

```sql
CREATE TABLE followers (
    uid TEXT NOT NULL,
    device_uid TEXT NOT NULL,
    mlkem_public_key TEXT NOT NULL,
    mldsa_public_key TEXT NULL,
    alias TEXT NULL,
    allowed TEXT NOT NULL DEFAULT 'Allowed',
    endpoint TEXT NULL,
    ipns_id TEXT NULL,
    PRIMARY KEY (uid, device_uid)
);

CREATE INDEX idx_followers_uid ON followers(uid);

CREATE TABLE following (
    uid TEXT NOT NULL,
    mlkem_public_key TEXT NOT NULL,
    mldsa_public_key TEXT NULL,
    endpoint TEXT NOT NULL,
    alias TEXT NULL,
    ipns_id TEXT NULL,
    PRIMARY KEY (uid)
);

CREATE TABLE auth_nonces (
    uid TEXT NOT NULL,
    device_uid TEXT NOT NULL,
    nonce TEXT NOT NULL,
    ts INTEGER NOT NULL,
    PRIMARY KEY (uid, device_uid, nonce)
);

CREATE INDEX idx_auth_nonces_ts ON auth_nonces(ts);

CREATE TABLE pairing_sessions (
    pairing_id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    device_uid TEXT NOT NULL,
    device_mlkem_public_key TEXT NOT NULL,
    device_mldsa_public_key TEXT NOT NULL,
    salt_hex TEXT NOT NULL,
    pin_hash_hex TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending'
);
```

`mldsa_public_key` on `followers` is nullable: read-only content followers may have only an ML-KEM key. The `pairing_sessions` table requires both device keys.

---

## Appendix B: Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `ORBIT_PORT` | `8443` | HTTPS port for the Orbit station API |
| `ORBIT_HOST` | `0.0.0.0` | Bind address for the station server |
| `ORBIT_PASSWORD` | _(empty)_ | Optional password to encrypt the secret-key files (`mlkem.bin`, `mldsa.bin`) at rest (Argon2i) |
| `ORBIT_PQC_BACKEND` | `auto` | PQC backend: `auto` (liboqs if available+self-test passes, else python), `liboqs` (constant-time, requires `oqs`), or `python` (pure-Python) |
| `IPFS_API_URL` | `http://127.0.0.1:5001` | IPFS daemon HTTP API URL |
| `IPFS_TIMEOUT` | `30` | Default timeout (seconds) for IPFS operations |
| `IPFS_MAX_RETRIES` | `3` | Maximum retry attempts for transient IPFS errors |
| `ORBIT_BASE_DIR` | `<project>/orbit_data` | Root directory for station data. Defaults to a folder next to `run.py`; relative values are resolved against the project directory (not the cwd), absolute values are used as-is. |
| `SSL_CERTFILE` | `./orbit_data/ssl/cert.pem` | Path to TLS certificate |
| `SSL_KEYFILE` | `./orbit_data/ssl/key.pem` | Path to TLS private key |
| `MAX_UPLOAD_SIZE` | `104857600` (100 MB) | Maximum upload size for post content |
| `CORS_ORIGINS` | `*` | Allowed CORS origins |
| `LOG_LEVEL` | `INFO` | Logging verbosity |
| `CLOUDFLARE_TUNNEL_ENABLED` | `false` | Enable Cloudflare Quick Tunnel integration |
| `CLOUDFLARE_METRICS_PORT` | `40469` | Port for cloudflared's metrics/quicktunnel endpoint |
| `ORBIT_MAX_DEVICES_PER_FOLLOWER` | `20` | Maximum devices per follower uid |
| `ORBIT_AUTO_REWRAP_ON_FOLLOW_CHANGE` | `1` | Enable auto-rewrap when followers change (`0` to disable) |
| `ORBIT_BACKUP_DEST` | _(empty)_ | Destination dir for `orbit_node.backup create` and the backup timer; blank → auto-detect a mounted USB drive |
| `MAX_SKEW_SECONDS` | `60` | Maximum clock skew for authenticated requests |
| `NONCE_TTL_SECONDS` | `86400` | How long to retain nonces (24 hours) |
| `PIN_LEN` | `6` | Length of pairing PIN |
| `TTL_SECONDS` (pairing) | `300` | Pairing session timeout (5 minutes) |
| `MAX_ATTEMPTS` (pairing) | `5` | Maximum PIN attempts per session |

---

## Appendix C: Backup Archive Format

A station's recoverable state spans `orbit_data/` **and** the IPFS repo (content
bytes + the node identity that determines the permanent peer ID / IPNS address).
`orbit_node.backup` packages all of it into a single portable archive so a fresh
`install.sh --restore` reproduces the station byte-for-byte (same peer ID, same
keys, same posts).

### D.1 Filename

```
orbit-backup-<peerid8>-<UTCstamp>.tar.gz        # plaintext
orbit-backup-<peerid8>-<UTCstamp>.tar.gz.enc    # passphrase-encrypted
```

`<peerid8>` is the first 8 chars of the IPFS peer ID (or `noipfs`); `<UTCstamp>`
is `YYYYMMDDTHHMMSSZ`. An encrypted archive is the gzipped tar wrapped with the
at-rest scheme of Section 4.4 (16-byte salt + Argon2i-derived SecretBox).

### D.2 Contents (tar members)

| Member | Description |
|--------|-------------|
| `backup.json` | Metadata (see D.3) |
| `orbit_data/keys/mlkem.bin`, `orbit_data/keys/mldsa.bin` | Secret-key files, copied as-is (still ORBIT_PASSWORD-encrypted if that was set) |
| `orbit_data/public.json` | Public identity document |
| `orbit_data/orbit.db` | Consistent SQLite snapshot taken via the backup API (WAL-safe) |
| `orbit_data/manifests/manifest.json` | The manifest |
| `env` | The project `.env` (config that pairs with the keys) |
| `ipfs_identity.json` | `{"PeerID","PrivKey"}` read from the IPFS repo `config` `Identity` |
| `content/<cid>.car` | One CAR file per recursively-pinned IPFS root |
| `pinned_roots.txt` | Newline-separated root CIDs to re-pin on restore |

Excluded: `orbit_data/ssl/` (regenerated on first run) and the derived plaintext
graph dumps. Any member that does not exist on the source station is simply
omitted (and absent from `backup.json.contents`).

### D.3 `backup.json`

```json
{
  "schema_version": 1,
  "tool": "orbit-backup",
  "created_at": "<ISO 8601 UTC>",
  "peer_id": "<ipfs peer id | null>",
  "uid": "<station uid | null>",
  "encrypted": false,
  "pinned_root_count": 12,
  "contents": ["orbit_data/keys/mlkem.bin", "..."],
  "sha256": { "orbit_data/keys/mlkem.bin": "<hex>", "...": "..." }
}
```

### D.4 Restore semantics

A restorer MUST: validate `schema_version`; lay `orbit_data/` and `env` back into
the project; ensure an IPFS repo exists and set `Identity.PeerID`/`Identity.PrivKey`
from `ipfs_identity.json`; `dag import` every `content/*.car`; and `pin add` each
CID in `pinned_roots.txt`. Restore is offline-capable (uses the `ipfs` CLI against
the repo, no daemon required) and refuses to overwrite a populated `orbit_data/`
unless forced. See Section 5.2 for key-file layout and Section 4.4 for the
encryption wrapper.

---

## Appendix D: References

- **NaCl / libsodium:** https://doc.libsodium.org/
- **PyNaCl:** https://pynacl.readthedocs.io/
- **IPFS:** https://docs.ipfs.tech/
- **IPNS:** https://docs.ipfs.tech/concepts/ipns/
- **Kubo:** https://github.com/ipfs/kubo
- **ML-KEM (FIPS 203):** https://csrc.nist.gov/pubs/fips/203/final
- **ML-DSA (FIPS 204):** https://csrc.nist.gov/pubs/fips/204/final
- **kyber-py (ML-KEM-768):** https://github.com/GiacomoPope/kyber-py
- **dilithium-py (ML-DSA-65):** https://github.com/GiacomoPope/dilithium-py
- **XSalsa20-Poly1305:** https://doc.libsodium.org/secret-key_cryptography/aead
- **Argon2:** RFC 9106
- **BLAKE2:** RFC 7693
- **scrypt:** RFC 7914
- **UUID v4:** RFC 9562
- **RFC 2119 Keywords:** RFC 2119
- **Cloudflare Quick Tunnel:** https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/
