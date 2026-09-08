"""
crypto_utils.py
----------------
All of the cryptography the project needs, in one place:

  * SHA-256 hashing            -> integrity "fingerprints"            (FR9)
  * RSA key-pair + sign/verify -> digital signatures                 (FR4)
  * HMAC-based keyed helpers   -> the "secret start location" design  (FR7 + FR13)

Why the start-location helpers live here:
The assignment wants the payload to begin somewhere *other* than the
top-left corner, and wants us to explain how that location is protected
against guessing.  Our design derives the location from a pre-shared
secret key, so the maths for that (an HMAC keystream) is a cryptographic
primitive and belongs next to the hashing and signing code.

Key idea for a reader:
  - The RSA private key proves *who* signed the payload (authenticity).
  - The shared secret key controls *where* the payload is hidden (location
    privacy).  Losing the secret key lets an attacker find the payload,
    but they still cannot forge it without the RSA private key.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# ==========================================================================
# 1. Hashing  (FR9 - integrity fingerprints)
# ==========================================================================

def sha256_bytes(data: bytes) -> bytes:
    """Return the raw 32-byte SHA-256 digest of `data` (used before signing)."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 digest of `data` as a 64-character hex string.

    The hex form is what we store inside the JSON payload (`cover_hash`),
    because JSON cannot hold raw bytes.
    """
    return hashlib.sha256(data).hexdigest()


# ==========================================================================
# 2. Digital signatures  (FR4 - RSA-2048 with PSS padding over SHA-256)
# ==========================================================================

def generate_keypair(private_path: str | Path, public_path: str | Path, key_size: int = 2048) -> None:
    """Create a fresh RSA key pair and write both halves as PEM files.

    private_key.pem -> used to SIGN payloads (keep secret)
    public_key.pem  -> used to VERIFY signatures (safe to share / submit)
    """
    # Generate the private key; the public key is derived from it.
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()

    # Serialise the private key to unencrypted PKCS#8 PEM text.
    # (No passphrase: this key exists only for the assignment demo.)
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Serialise the public key to standard SubjectPublicKeyInfo PEM text.
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Make sure the keys/ folder exists, then write both files.
    Path(private_path).parent.mkdir(parents=True, exist_ok=True)
    Path(private_path).write_bytes(private_bytes)
    Path(public_path).write_bytes(public_bytes)


def load_private_key(path: str | Path):
    """Read a PEM private-key file back into a usable key object."""
    data = Path(path).read_bytes()
    return serialization.load_pem_private_key(data, password=None)


def load_public_key(path: str | Path):
    """Read a PEM public-key file back into a usable key object."""
    data = Path(path).read_bytes()
    return serialization.load_pem_public_key(data)


def sign_data(private_key, data: bytes) -> bytes:
    """Produce an RSA-PSS/SHA-256 signature over `data`.

    In this project `data` is always the SHA-256 digest of the serialised
    payload, so the signature ends up covering the entire payload.
    PSS padding is the modern, randomised RSA signature scheme (each call
    produces different bytes, but all of them verify).
    """
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_signature(public_key, data: bytes, signature: bytes) -> bool:
    """Check an RSA-PSS signature.

    Returns True if `signature` was produced over `data` by the private key
    matching `public_key`, otherwise False.  The cryptography library
    *raises* on a bad signature, so we catch that and turn it into a plain
    boolean the verdict logic can branch on.
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        # Any failure (wrong key, altered data, malformed signature) => not valid.
        return False


# ==========================================================================
# 3. Keyed start-location derivation  (FR7 + FR13 innovation:
#    "Advanced start-location security")
# ==========================================================================
#
# The problem: a naive stego tool hides data at a fixed spot (e.g. byte 0),
# so an attacker just checks the start of every file.  We instead compute a
# secret, per-file start offset from:
#     * a shared SECRET KEY  (known only to sender + authorised verifier)
#     * a random SALT        (fresh per file, stored in the clear)
# The salt alone reveals nothing; you also need the secret key.

SALT_LEN = 8          # bytes of random public salt stored in the locator header
OFFSET_LEN = 8        # bytes used to represent the (encrypted) start offset


def hmac_keystream(secret_key: bytes, salt: bytes, length: int) -> bytes:
    """Derive `length` pseudo-random bytes from HMAC-SHA256(secret_key, salt || counter).

    HMAC-SHA256 only outputs 32 bytes at a time, so we call it repeatedly
    with an incrementing 4-byte counter and concatenate the blocks until we
    have enough bytes (this is a simple counter-mode KDF / stream cipher).
    The output is deterministic: same key + same salt -> same keystream,
    which is what lets the verifier reproduce the sender's choices.
    """
    out = b""
    counter = 0
    while len(out) < length:
        block = hmac.new(secret_key, salt + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]  # trim the last block to the exact requested length


def derive_start_offset(secret_key: bytes, salt: bytes, min_offset: int, capacity: int) -> int:
    """Pick the secret start position for the payload capsule.

    Returns a "unit" index (a byte for images, a low-sample-byte for audio)
    in the half-open range [min_offset, capacity):
      * min_offset keeps the capsule clear of the reserved locator-header
        region near the start of the file (so it's never at the top-left).
      * capacity is the exclusive upper bound the caller computed so the
        whole capsule still fits.

    How the number is chosen:
      1. span = how many valid positions there are.
      2. Take 8 keystream bytes derived from (secret_key, salt + "OFFSET").
      3. Interpret them as a big integer and reduce it modulo `span`.
    Without the secret key an attacker cannot reproduce step 2, so the true
    offset is one of `span` equally likely positions (hundreds of thousands
    to millions for a normal demo file).
    """
    if capacity <= min_offset:
        raise ValueError("Cover object has no usable capacity beyond the reserved header region")
    span = capacity - min_offset
    stream = hmac_keystream(secret_key, salt + b"OFFSET", 8)
    value = int.from_bytes(stream, "big")
    return min_offset + (value % span)


def encrypt_offset(secret_key: bytes, salt: bytes, offset: int) -> bytes:
    """Hide the real start offset before writing it into the locator header.

    We XOR the 8-byte big-endian offset with an independent keystream
    (domain-separated with the "ENC" tag so it differs from the "OFFSET"
    keystream).  XOR with a key-derived stream is a one-time-pad style
    cipher: an attacker who doesn't know `secret_key` just sees random bytes.
    """
    keystream = hmac_keystream(secret_key, salt + b"ENC", OFFSET_LEN)
    offset_bytes = offset.to_bytes(OFFSET_LEN, "big")
    return bytes(a ^ b for a, b in zip(offset_bytes, keystream))


def decrypt_offset(secret_key: bytes, salt: bytes, enc_offset: bytes) -> int:
    """Reverse `encrypt_offset`: XOR again with the same keystream, then
    read the bytes back as a big-endian integer.  (XOR is its own inverse.)
    """
    keystream = hmac_keystream(secret_key, salt + b"ENC", OFFSET_LEN)
    offset_bytes = bytes(a ^ b for a, b in zip(enc_offset, keystream))
    return int.from_bytes(offset_bytes, "big")


def random_salt() -> bytes:
    """Fresh cryptographically-random salt, one per protected file."""
    return os.urandom(SALT_LEN)
