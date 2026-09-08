"""
payload.py
----------
Builds the **verification payload** (FR3) and the **stable cover hash**
used for tamper detection (FR9).

The verification payload is a small JSON object describing the protected
file: media id, timestamp, a hash of the cover object, a random nonce, the
chosen LSB depth, the confidential message, and team metadata.  It is this
object that gets digitally signed, so anything inside it is protected
against alteration once the file is released.
"""

from __future__ import annotations

import json
import os
import time
import uuid

from crypto_utils import sha256_hex

# Team number. Replace this if the team number ever changes; the GUI and the
# demo scripts default to the same value.
TEAM_ID_DEFAULT = "P6-6"


def new_nonce() -> str:
    """A fresh random 128-bit value (hex) - makes every payload unique even
    if two files are protected with identical settings in the same second,
    and gives an anti-replay handle."""
    return uuid.uuid4().hex


def build_payload(
    media_id: str,
    cover_type: str,
    message: str,
    lsb_depth: int,
    cover_stable_hash_hex: str,
    team_id: str = TEAM_ID_DEFAULT,
    extra_metadata: dict | None = None,
) -> dict:
    """Assemble the verification payload dict (FR3).

    Fields:
      media_id   - identifies which media this payload belongs to
      cover_type - "image" or "audio"
      timestamp  - UTC time of protection, ISO-8601 with a trailing 'Z'
      nonce      - random uniqueness / anti-replay value
      cover_hash - SHA-256 (hex) of the cover content that does NOT carry
                   stego data (see `stable_cover_hash`)
      lsb_depth  - LSBs per unit used for the capsule
      message    - the confidential text being protected
      metadata   - team id, tool name, plus any caller-supplied extras
    """
    payload = {
        "media_id": media_id,
        "cover_type": cover_type,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "nonce": new_nonce(),
        "cover_hash": cover_stable_hash_hex,
        "lsb_depth": lsb_depth,
        "message": message,
        "metadata": {
            "team_id": team_id,
            "tool": "INF2005-ACW1-StegoVerify",
            **(extra_metadata or {}),
        },
    }
    return payload


def serialize_payload(payload: dict) -> bytes:
    """Encode the payload as **canonical** JSON: keys sorted, no spaces.

    This matters because the signer hashes these exact bytes and the
    verifier re-hashes them.  If the byte layout were not deterministic the
    signature would randomly fail to verify.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def deserialize_payload(raw: bytes) -> dict:
    """Parse the canonical JSON bytes back into a dict."""
    return json.loads(raw.decode("utf-8"))


def payload_digest_hex(payload_bytes: bytes) -> str:
    """SHA-256 (hex) of the serialised payload - handy for logs / evidence."""
    return sha256_hex(payload_bytes)


def stable_cover_hash(carrier: bytes, excluded_ranges: list[tuple[int, int]]) -> str:
    """SHA-256 (hex) of the cover object with the stego-bearing regions
    blanked out.

    `excluded_ranges` are (start, end) unit ranges that legitimately differ
    between the original and the protected file: the locator-header region
    and the capsule region.  We copy the carrier, overwrite every byte in
    those ranges with 0x00, then hash.

    Because the encoder (at embed time) and the verifier (at extract time,
    once it knows the same two ranges) blank exactly the same bytes, they
    compute an identical hash.  Any edit to the *visible / audible* part of
    the file changes this hash -> "Tampered", independently of the digital
    signature (which instead protects the hidden capsule bytes).
    """
    buf = bytearray(carrier)
    for start, end in excluded_ranges:
        for i in range(start, min(end, len(buf))):
            buf[i] = 0x00
    return sha256_hex(bytes(buf))


def media_id_from_filename(path: str) -> str:
    """Derive a media id from a file name plus a short random suffix, so two
    files with the same name still get distinct ids."""
    base = os.path.basename(path)
    return f"{base}-{uuid.uuid4().hex[:8]}"
