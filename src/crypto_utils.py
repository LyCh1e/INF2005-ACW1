"""
crypto_utils.py
----------------
Cryptographic primitives used across the project:

  * SHA-256 hashing (integrity fingerprints)
  * RSA key-pair generation, signing and verification (digital signatures)
  * HMAC-based keyed start-location derivation and encryption
    (this is the "Advanced start-location security" innovation:
    the payload start offset is never stored in the clear inside the
    cover object -- it is encrypted with a keystream derived from a
    pre-shared secret key + a per-file random salt, so an attacker who
    does not know the secret key cannot recover the true start offset
    even if they find the tiny public locator header.)
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# --------------------------------------------------------------------------
# Hashing
# --------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> bytes:
    """Return the raw 32-byte SHA-256 digest of data."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# Digital signatures (RSA-2048 + PSS/SHA-256)
# --------------------------------------------------------------------------

def generate_keypair(private_path: str | Path, public_path: str | Path, key_size: int = 2048) -> None:
    """Generate an RSA key pair and write PEM files (private + public)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    Path(private_path).parent.mkdir(parents=True, exist_ok=True)
    Path(private_path).write_bytes(private_bytes)
    Path(public_path).write_bytes(public_bytes)


def load_private_key(path: str | Path):
    data = Path(path).read_bytes()
    return serialization.load_pem_private_key(data, password=None)


def load_public_key(path: str | Path):
    data = Path(path).read_bytes()
    return serialization.load_pem_public_key(data)


def sign_data(private_key, data: bytes) -> bytes:
    """Sign `data` (typically the SHA-256 digest of the payload) with RSA-PSS."""
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_signature(public_key, data: bytes, signature: bytes) -> bool:
    """Verify an RSA-PSS signature. Returns True/False (never raises)."""
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# Keyed start-location derivation  (innovation: FR7 / "Advanced start-
# location security" optional challenge)
# --------------------------------------------------------------------------

SALT_LEN = 8          # bytes of random public salt stored in the locator header
OFFSET_LEN = 8         # bytes used to represent the (encrypted) start offset


def hmac_keystream(secret_key: bytes, salt: bytes, length: int) -> bytes:
    """
    Derive a keystream of `length` bytes from HMAC-SHA256(secret_key, salt).
    Used both to pick the start offset and to encrypt it, so that the
    published salt on its own reveals nothing about the true offset.
    """
    out = b""
    counter = 0
    while len(out) < length:
        block = hmac.new(secret_key, salt + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def derive_start_offset(secret_key: bytes, salt: bytes, min_offset: int, capacity: int) -> int:
    """
    Deterministically derive a start offset (in "unit" positions -- e.g. bytes
    or samples) in the half-open range [min_offset, capacity), from the
    shared secret key and the per-file salt.  Without `secret_key` this
    value is computationally infeasible to guess for realistically sized
    cover objects (search space = capacity - min_offset).
    """
    if capacity <= min_offset:
        raise ValueError("Cover object has no usable capacity beyond the reserved header region")
    span = capacity - min_offset
    stream = hmac_keystream(secret_key, salt + b"OFFSET", 8)
    value = int.from_bytes(stream, "big")
    return min_offset + (value % span)


def encrypt_offset(secret_key: bytes, salt: bytes, offset: int) -> bytes:
    """XOR-encrypt the start offset with a key/salt-derived keystream."""
    keystream = hmac_keystream(secret_key, salt + b"ENC", OFFSET_LEN)
    offset_bytes = offset.to_bytes(OFFSET_LEN, "big")
    return bytes(a ^ b for a, b in zip(offset_bytes, keystream))


def decrypt_offset(secret_key: bytes, salt: bytes, enc_offset: bytes) -> int:
    keystream = hmac_keystream(secret_key, salt + b"ENC", OFFSET_LEN)
    offset_bytes = bytes(a ^ b for a, b in zip(enc_offset, keystream))
    return int.from_bytes(offset_bytes, "big")


def random_salt() -> bytes:
    return os.urandom(SALT_LEN)
