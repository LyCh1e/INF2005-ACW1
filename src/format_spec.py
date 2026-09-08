"""
format_spec.py
---------------
Binary layouts shared by the image and audio steganography engines.

Two regions are embedded in every stego cover object:

1. LOCATOR HEADER -- a small, fixed-position region (always starting right
   after byte/sample index HEADER_RESERVED_UNITS's worth of "cover margin",
   NEVER at unit 0 / the top-left corner) always embedded at 1 bit per
   carrier unit for maximum reliability. It stores enough information for
   an authorised verifier (one who knows the shared secret key) to locate
   and decrypt the true payload start offset -- but reveals nothing useful
   to an attacker who does not know the key.

        MAGIC1  (4 bytes)  b"SVH1"
        lsb     (1 byte)   number of LSBs used for the capsule region (1-8)
        salt    (8 bytes)  random, unique per stego file
        enc_off (8 bytes)  HMAC-keystream-encrypted payload start offset
        clen    (4 bytes)  capsule length in bytes (big-endian)
        tag     (8 bytes)  HMAC-SHA256(secret_key, above fields)[:8]
        -------------------------------------------------------------
        total   33 bytes  ->  264 bits  (264 carrier units at 1 LSB/unit)

2. CAPSULE -- the actual verification payload + digital signature, embedded
   starting at the *derived* (secret-key-dependent) start offset, using the
   user-selected number of LSBs per carrier unit (1-8):

        MAGIC2     (4 bytes)  b"PLD1"
        payload_len(4 bytes)  big-endian length of the JSON payload
        payload    (payload_len bytes)  UTF-8 canonical JSON
        sig_len    (2 bytes)  big-endian length of the signature
        signature  (sig_len bytes)  RSA-PSS/SHA-256 signature bytes
"""

from __future__ import annotations

import hmac
import hashlib
import struct

MAGIC_HEADER = b"SVH1"
MAGIC_CAPSULE = b"PLD1"

SALT_LEN = 8
ENC_OFFSET_LEN = 8
TAG_LEN = 8

HEADER_LEN = 4 + 1 + SALT_LEN + ENC_OFFSET_LEN + 4 + TAG_LEN  # = 33 bytes

# The locator header itself is never placed at unit 0 (the top-left corner
# / first sample) -- it starts a small fixed margin in, which is public
# knowledge (documented here / in the README) but holds no secret.
HEADER_MARGIN_UNITS = 16


def header_tag(secret_key: bytes, lsb: int, salt: bytes, enc_offset: bytes, clen: int) -> bytes:
    body = bytes([lsb]) + salt + enc_offset + struct.pack(">I", clen)
    return hmac.new(secret_key, MAGIC_HEADER + body, hashlib.sha256).digest()[:TAG_LEN]


def pack_header(secret_key: bytes, lsb: int, salt: bytes, enc_offset: bytes, clen: int) -> bytes:
    tag = header_tag(secret_key, lsb, salt, enc_offset, clen)
    return MAGIC_HEADER + bytes([lsb]) + salt + enc_offset + struct.pack(">I", clen) + tag


class HeaderError(Exception):
    pass


def unpack_header(raw: bytes) -> dict:
    if len(raw) != HEADER_LEN:
        raise HeaderError(f"Expected {HEADER_LEN} header bytes, got {len(raw)}")
    magic = raw[0:4]
    if magic != MAGIC_HEADER:
        raise HeaderError("Locator header magic not found (payload missing or wrong LSB depth)")
    lsb = raw[4]
    salt = raw[5:5 + SALT_LEN]
    off = 5 + SALT_LEN
    enc_offset = raw[off: off + ENC_OFFSET_LEN]
    off += ENC_OFFSET_LEN
    clen = struct.unpack(">I", raw[off: off + 4])[0]
    off += 4
    tag = raw[off: off + TAG_LEN]
    return {"lsb": lsb, "salt": salt, "enc_offset": enc_offset, "clen": clen, "tag": tag}


def pack_capsule(payload_bytes: bytes, signature: bytes) -> bytes:
    return (
        MAGIC_CAPSULE
        + struct.pack(">I", len(payload_bytes))
        + payload_bytes
        + struct.pack(">H", len(signature))
        + signature
    )


class CapsuleError(Exception):
    pass


def parse_capsule(raw: bytes) -> tuple[bytes, bytes]:
    if len(raw) < 4 + 4 + 2:
        raise CapsuleError("Capsule too short")
    magic = raw[0:4]
    if magic != MAGIC_CAPSULE:
        raise CapsuleError("Capsule magic not found (payload missing or wrong start location)")
    plen = struct.unpack(">I", raw[4:8])[0]
    pos = 8
    if pos + plen > len(raw):
        raise CapsuleError("Truncated payload in capsule")
    payload_bytes = raw[pos: pos + plen]
    pos += plen
    if pos + 2 > len(raw):
        raise CapsuleError("Truncated capsule (missing signature length)")
    slen = struct.unpack(">H", raw[pos:pos + 2])[0]
    pos += 2
    if pos + slen > len(raw):
        raise CapsuleError("Truncated signature in capsule")
    signature = raw[pos: pos + slen]
    return payload_bytes, signature


def capsule_total_len(payload_bytes: bytes, signature: bytes) -> int:
    return 4 + 4 + len(payload_bytes) + 2 + len(signature)
