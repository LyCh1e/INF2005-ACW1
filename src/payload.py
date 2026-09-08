"""
payload.py
----------
Builds and serialises the compact verification payload (FR3): media ID,
timestamp, hash, nonce and team-defined metadata, plus helpers to compute
the "stable representation" hash of a cover object (the content that is
NOT used to carry stego data) used for tamper detection (FR9).
"""

from __future__ import annotations

import json
import os
import time
import uuid

from crypto_utils import sha256_hex

TEAM_ID_DEFAULT = "Px-x"  # replace with your actual team number, e.g. P1-4


def new_nonce() -> str:
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
    """Assemble the verification payload dict (FR3)."""
    payload = {
        "media_id": media_id,
        "cover_type": cover_type,          # "image" or "audio"
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "nonce": new_nonce(),
        "cover_hash": cover_stable_hash_hex,  # SHA-256 of non-stego-bearing cover content
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
    """Canonical, deterministic JSON encoding (stable key order, no extra whitespace)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def deserialize_payload(raw: bytes) -> dict:
    return json.loads(raw.decode("utf-8"))


def payload_digest_hex(payload_bytes: bytes) -> str:
    return sha256_hex(payload_bytes)


def stable_cover_hash(carrier: bytes, excluded_ranges: list[tuple[int, int]]) -> str:
    """
    SHA-256 (hex) of `carrier` with every byte inside `excluded_ranges`
    (the locator header region and the capsule region -- i.e. the bytes
    that legitimately change between the original and the stego object)
    replaced by a fixed placeholder (0x00) before hashing.

    Because both the encoder (at embedding time) and the verifier (at
    extraction time, once it knows the header + capsule ranges) compute
    this identically, any change to the cover object OUTSIDE those two
    regions is caught as tampering -- independent of the digital
    signature, which instead protects the payload/capsule bytes
    themselves.
    """
    buf = bytearray(carrier)
    for start, end in excluded_ranges:
        for i in range(start, min(end, len(buf))):
            buf[i] = 0x00
    return sha256_hex(bytes(buf))


def media_id_from_filename(path: str) -> str:
    base = os.path.basename(path)
    return f"{base}-{uuid.uuid4().hex[:8]}"
