"""
format_spec.py
---------------
The exact byte layouts that the encoder writes and the decoder reads.

Every protected cover object contains **two** hidden regions:

1. LOCATOR HEADER  (small, fixed position, always 1 LSB/unit)
   -----------------------------------------------------------
   Sits a short public margin in from the start of the file
   (HEADER_MARGIN_UNITS), NEVER at unit 0 / the top-left corner.
   It is embedded at 1 bit per unit for maximum robustness, and it tells an
   authorised verifier (one who knows the shared secret key) where the real
   payload is and how to read it.  To an attacker without the key it is
   just 33 bytes of noise protected by an HMAC tag.

        field     size      meaning
        -------   -------   -----------------------------------------------
        MAGIC1    4 bytes   b"SVH1" - "is there a header here?" marker
        lsb       1 byte    LSBs per unit used for the capsule region (1-8)
        salt      8 bytes   random, unique per file (public)
        enc_off   8 bytes   the real start offset, XOR-encrypted with a
                            key+salt keystream
        clen      4 bytes   capsule length in bytes (big-endian)
        tag       8 bytes   HMAC-SHA256(secret_key, all the fields above)[:8]
        -------   -------
        total     33 bytes  -> 264 bits -> 264 carrier units at 1 LSB/unit

2. PAYLOAD CAPSULE  (at the secret, key-derived offset, user-selected LSBs)
   ----------------------------------------------------------------------
        MAGIC2       4 bytes             b"PLD1" - capsule marker
        payload_len  4 bytes             length of the JSON payload (BE)
        payload      payload_len bytes   the verification payload, canonical JSON
        sig_len      2 bytes             length of the signature (BE)
        signature    sig_len bytes       RSA-PSS/SHA-256 signature over the payload

This module is pure layout: pack -> bytes, unpack -> fields, plus the HMAC
tag helper.  It performs no steganography and no signing itself.
"""

from __future__ import annotations

import hmac
import hashlib
import struct

MAGIC_HEADER = b"SVH1"    # marks the start of a locator header
MAGIC_CAPSULE = b"PLD1"   # marks the start of a payload capsule

SALT_LEN = 8
ENC_OFFSET_LEN = 8
TAG_LEN = 8

# 4 (magic) + 1 (lsb) + 8 (salt) + 8 (enc offset) + 4 (clen) + 8 (tag) = 33
HEADER_LEN = 4 + 1 + SALT_LEN + ENC_OFFSET_LEN + 4 + TAG_LEN

# The header is not placed at unit 0.  It starts this many units in - a
# small, fixed, publicly-known margin that holds no secret by itself.
HEADER_MARGIN_UNITS = 16


def header_tag(secret_key: bytes, lsb: int, salt: bytes, enc_offset: bytes, clen: int) -> bytes:
    """Compute the 8-byte authentication tag over the header body.

    The tag is keyed on the shared secret, so:
      * a verifier with the wrong key computes a different tag -> "Cannot Verify"
      * an attacker who edits any header field breaks the tag  -> "Cannot Verify"
    We keep only the first 8 bytes of the 32-byte HMAC output to save space;
    8 bytes (64 bits) is still far too much to brute-force in a demo setting.
    """
    body = bytes([lsb]) + salt + enc_offset + struct.pack(">I", clen)
    return hmac.new(secret_key, MAGIC_HEADER + body, hashlib.sha256).digest()[:TAG_LEN]


def pack_header(secret_key: bytes, lsb: int, salt: bytes, enc_offset: bytes, clen: int) -> bytes:
    """Assemble the 33 raw header bytes, tag included, ready to embed."""
    tag = header_tag(secret_key, lsb, salt, enc_offset, clen)
    return MAGIC_HEADER + bytes([lsb]) + salt + enc_offset + struct.pack(">I", clen) + tag


class HeaderError(Exception):
    """Raised when the extracted bytes are not a well-formed locator header
    (usually means: no payload here, or the wrong LSB depth was tried)."""


def unpack_header(raw: bytes) -> dict:
    """Split 33 raw bytes back into the header fields.

    This only checks the *shape* and the magic marker; the caller is
    responsible for checking the HMAC tag against the secret key.
    """
    if len(raw) != HEADER_LEN:
        raise HeaderError(f"Expected {HEADER_LEN} header bytes, got {len(raw)}")

    # Bytes 0-3: magic marker.
    magic = raw[0:4]
    if magic != MAGIC_HEADER:
        raise HeaderError("Locator header magic not found (payload missing or wrong LSB depth)")

    # Byte 4: LSB depth used for the capsule.
    lsb = raw[4]

    # Bytes 5..12: salt.
    salt = raw[5:5 + SALT_LEN]

    # Next 8 bytes: encrypted start offset.
    off = 5 + SALT_LEN
    enc_offset = raw[off: off + ENC_OFFSET_LEN]
    off += ENC_OFFSET_LEN

    # Next 4 bytes: capsule length (big-endian unsigned int).
    clen = struct.unpack(">I", raw[off: off + 4])[0]
    off += 4

    # Final 8 bytes: HMAC tag.
    tag = raw[off: off + TAG_LEN]

    return {"lsb": lsb, "salt": salt, "enc_offset": enc_offset, "clen": clen, "tag": tag}


def pack_capsule(payload_bytes: bytes, signature: bytes) -> bytes:
    """Build the capsule: marker, then length-prefixed payload, then
    length-prefixed signature.  Length prefixes let the decoder split the
    two blobs apart without any separator characters.
    """
    return (
        MAGIC_CAPSULE
        + struct.pack(">I", len(payload_bytes))   # 4-byte payload length
        + payload_bytes
        + struct.pack(">H", len(signature))       # 2-byte signature length
        + signature
    )


class CapsuleError(Exception):
    """Raised when the capsule bytes are missing, truncated or corrupted."""


def parse_capsule(raw: bytes) -> tuple[bytes, bytes]:
    """Inverse of `pack_capsule`: return (payload_bytes, signature).

    Every step re-checks that there are enough bytes left, so a corrupted
    or partially-overwritten capsule fails cleanly instead of slicing
    garbage.
    """
    if len(raw) < 4 + 4 + 2:  # magic + payload_len + sig_len minimum
        raise CapsuleError("Capsule too short")

    # Marker check.
    magic = raw[0:4]
    if magic != MAGIC_CAPSULE:
        raise CapsuleError("Capsule magic not found (payload missing or wrong start location)")

    # Payload: 4-byte length then that many bytes.
    plen = struct.unpack(">I", raw[4:8])[0]
    pos = 8
    if pos + plen > len(raw):
        raise CapsuleError("Truncated payload in capsule")
    payload_bytes = raw[pos: pos + plen]
    pos += plen

    # Signature: 2-byte length then that many bytes.
    if pos + 2 > len(raw):
        raise CapsuleError("Truncated capsule (missing signature length)")
    slen = struct.unpack(">H", raw[pos:pos + 2])[0]
    pos += 2
    if pos + slen > len(raw):
        raise CapsuleError("Truncated signature in capsule")
    signature = raw[pos: pos + slen]

    return payload_bytes, signature


def capsule_total_len(payload_bytes: bytes, signature: bytes) -> int:
    """Exact capsule size for given payload + signature, without building it.
    Used up front to reserve carrier space and pick the start offset.
    4 (magic) + 4 (payload_len) + payload + 2 (sig_len) + signature.
    """
    return 4 + 4 + len(payload_bytes) + 2 + len(signature)
