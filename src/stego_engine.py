"""
stego_engine.py
----------------
Cover-object-agnostic embedding / extraction / verification engine.
Both image_stego.py and audio_stego.py reduce their file format to a flat
bytearray "carrier" and delegate all of the actual steganography, hashing
and signature logic to this module, so the security workflow (and its
correctness) is defined and tested in exactly one place.
"""

from __future__ import annotations

import bitops
import crypto_utils
import format_spec as fmt
import payload as payload_mod

HEADER_MARGIN_UNITS = fmt.HEADER_MARGIN_UNITS
HEADER_UNITS = fmt.HEADER_LEN * 8  # 1 bit per unit for the locator header
HEADER_END_UNITS = HEADER_MARGIN_UNITS + HEADER_UNITS

VERDICT_AUTHENTIC = "Authentic"
VERDICT_TAMPERED = "Tampered"
VERDICT_SIGNATURE_INVALID = "Signature Invalid"
VERDICT_PAYLOAD_MISSING = "Payload Missing"
VERDICT_WRONG_START_LOCATION = "Wrong Start Location"
VERDICT_CANNOT_VERIFY = "Cannot Verify"


class CapacityError(Exception):
    pass


def estimate_max_message_bytes(carrier_len: int, lsb_depth: int, cover_type: str, team_id: str) -> int:
    """
    Rough usable capacity for the free-text `message` field, after
    reserving space for the locator header and the fixed capsule
    overhead (magic bytes, length fields, RSA-2048 signature = 256
    bytes, and the fixed-length JSON fields around the message).
    Used by the GUI for the mandatory capacity check (is the payload
    larger than the cover object can hold?).
    """
    if carrier_len <= HEADER_END_UNITS:
        return 0
    available_capsule_bytes = bitops.capacity_bytes(carrier_len, HEADER_END_UNITS, lsb_depth)
    fixed_capsule_overhead = 4 + 4 + 2 + 256  # magic+plen+payload...+slen+signature(2048-bit RSA)
    draft = payload_mod.build_payload(
        media_id="X" * 40, cover_type=cover_type, message="", lsb_depth=lsb_depth,
        cover_stable_hash_hex="0" * 64, team_id=team_id,
    )
    empty_payload_len = len(payload_mod.serialize_payload(draft))
    usable = available_capsule_bytes - fixed_capsule_overhead - empty_payload_len
    return max(0, usable)


def _build_capsule_for_message(
    media_id: str, cover_type: str, message: str, lsb_depth: int, team_id: str,
    cover_stable_hash_hex_placeholder: str = "0" * 64,
) -> bytes:
    """Build a draft payload+capsule using a placeholder cover hash, purely to
    determine the exact final capsule length ahead of choosing the start offset
    (a real SHA-256 hex digest is always exactly 64 hex chars, so swapping the
    placeholder for the real digest later never changes the byte length)."""
    draft_payload = payload_mod.build_payload(
        media_id=media_id, cover_type=cover_type, message=message, lsb_depth=lsb_depth,
        cover_stable_hash_hex=cover_stable_hash_hex_placeholder, team_id=team_id,
    )
    return payload_mod.serialize_payload(draft_payload)


def embed_payload(
    carrier: bytearray,
    *,
    secret_key: bytes,
    private_key,
    media_id: str,
    cover_type: str,
    message: str,
    lsb_depth: int,
    team_id: str,
    extra_metadata: dict | None = None,
) -> dict:
    """
    Full encoder-side security workflow (spec section 7, steps 1-6):
      1-2. hash a stable representation of the cover object
      3.   build the verification payload
      4.   sign it
      5.   derive a secret start location and embed payload+signature there
      6.   embed the (encrypted) locator header
    Returns a dict of stats useful for the GUI / test evidence.
    """
    if not (1 <= lsb_depth <= 8):
        raise ValueError("lsb_depth must be between 1 and 8")
    if len(carrier) <= HEADER_END_UNITS:
        raise CapacityError("Cover object is too small to hold even the locator header")

    # 1) Determine the exact payload/capsule length using a placeholder hash.
    draft_payload_bytes = _build_capsule_for_message(media_id, cover_type, message, lsb_depth, team_id)
    sig_len_estimate = private_key.key_size // 8
    capsule_len = fmt.capsule_total_len(draft_payload_bytes, b"0" * sig_len_estimate)
    units_needed = bitops.required_units(capsule_len, lsb_depth)

    if HEADER_END_UNITS + units_needed > len(carrier):
        raise CapacityError(
            f"Payload capsule needs {units_needed} carrier units but only "
            f"{len(carrier) - HEADER_END_UNITS} are available after the header "
            f"(cover object capacity too small for this payload)."
        )

    # 2) Derive a secret start offset for the capsule (never at the top-left / unit 0).
    salt = crypto_utils.random_salt()
    capacity_bound = len(carrier) - units_needed + 1  # exclusive upper bound so capsule always fits
    start_offset = crypto_utils.derive_start_offset(secret_key, salt, HEADER_END_UNITS, capacity_bound)

    # 3) Compute the stable cover hash over everything EXCEPT the header/capsule regions.
    excluded_ranges = [
        (HEADER_MARGIN_UNITS, HEADER_END_UNITS),
        (start_offset, start_offset + units_needed),
    ]
    cover_hash_hex = payload_mod.stable_cover_hash(bytes(carrier), excluded_ranges)

    # 4) Build & sign the real payload.
    real_payload = payload_mod.build_payload(
        media_id=media_id, cover_type=cover_type, message=message, lsb_depth=lsb_depth,
        cover_stable_hash_hex=cover_hash_hex, team_id=team_id, extra_metadata=extra_metadata,
    )
    payload_bytes = payload_mod.serialize_payload(real_payload)
    if len(payload_bytes) != len(draft_payload_bytes):
        raise AssertionError("Internal error: payload length changed after hashing (report this bug)")

    signature = crypto_utils.sign_data(private_key, crypto_utils.sha256_bytes(payload_bytes))
    capsule = fmt.pack_capsule(payload_bytes, signature)
    if len(capsule) != capsule_len:
        raise AssertionError("Internal error: capsule length mismatch (report this bug)")

    # 5) Embed the capsule at the derived start offset.
    bitops.embed_bits(carrier, start_offset, lsb_depth, capsule)

    # 6) Embed the locator header (always 1 LSB/unit) at the fixed public margin.
    enc_offset = crypto_utils.encrypt_offset(secret_key, salt, start_offset)
    header_bytes = fmt.pack_header(secret_key, lsb_depth, salt, enc_offset, len(capsule))
    bitops.embed_bits(carrier, HEADER_MARGIN_UNITS, 1, header_bytes)

    return {
        "media_id": media_id,
        "start_offset": start_offset,
        "capsule_len": len(capsule),
        "units_needed": units_needed,
        "lsb_depth": lsb_depth,
        "payload": real_payload,
        "signature_len": len(signature),
        "carrier_len": len(carrier),
        "capacity_bytes_used": units_needed,
        "capacity_bytes_available": bitops.capacity_bytes(len(carrier), HEADER_END_UNITS, lsb_depth),
    }


def extract_and_verify(carrier: bytes, *, secret_key: bytes, public_key) -> dict:
    """
    Full decoder-side security workflow (spec section 7, steps 7-10).
    Returns {"verdict": ..., "detail": ..., "payload": dict|None, ...}
    Never raises for expected failure modes -- always returns a verdict.
    """
    result = {"verdict": None, "detail": "", "payload": None, "start_offset": None}

    if len(carrier) <= HEADER_END_UNITS:
        result["verdict"] = VERDICT_PAYLOAD_MISSING
        result["detail"] = "Cover object too small to contain a locator header."
        return result

    header_raw = bitops.extract_bits(carrier, HEADER_MARGIN_UNITS, 1, fmt.HEADER_LEN)
    try:
        header = fmt.unpack_header(header_raw)
    except fmt.HeaderError as exc:
        result["verdict"] = VERDICT_PAYLOAD_MISSING
        result["detail"] = f"No valid locator header found: {exc}"
        return result

    expected_tag = fmt.header_tag(secret_key, header["lsb"], header["salt"], header["enc_offset"], header["clen"])
    if not _constant_time_eq(expected_tag, header["tag"]):
        result["verdict"] = VERDICT_CANNOT_VERIFY
        result["detail"] = "Locator header authentication failed (wrong secret key, or header was tampered)."
        return result

    lsb_depth = header["lsb"]
    clen = header["clen"]
    start_offset = crypto_utils.decrypt_offset(secret_key, header["salt"], header["enc_offset"])
    result["start_offset"] = start_offset

    units_needed = bitops.required_units(clen, lsb_depth)
    if (
        not (1 <= lsb_depth <= 8)
        or start_offset < HEADER_END_UNITS
        or start_offset + units_needed > len(carrier)
    ):
        result["verdict"] = VERDICT_WRONG_START_LOCATION
        result["detail"] = "Derived start location falls outside the cover object's usable range."
        return result

    capsule_raw = bitops.extract_bits(carrier, start_offset, lsb_depth, clen)
    try:
        payload_bytes, signature = fmt.parse_capsule(capsule_raw)
    except fmt.CapsuleError as exc:
        result["verdict"] = VERDICT_TAMPERED
        result["detail"] = f"Header was authentic but capsule content is corrupted: {exc}"
        return result

    sig_ok = crypto_utils.verify_signature(public_key, crypto_utils.sha256_bytes(payload_bytes), signature)
    if not sig_ok:
        result["verdict"] = VERDICT_SIGNATURE_INVALID
        result["detail"] = "Digital signature does not match the extracted payload (wrong key or payload altered)."
        return result

    try:
        payload_dict = payload_mod.deserialize_payload(payload_bytes)
    except Exception as exc:
        result["verdict"] = VERDICT_TAMPERED
        result["detail"] = f"Signed payload is not valid JSON: {exc}"
        return result
    result["payload"] = payload_dict

    excluded_ranges = [
        (HEADER_MARGIN_UNITS, HEADER_END_UNITS),
        (start_offset, start_offset + units_needed),
    ]
    recomputed_hash = payload_mod.stable_cover_hash(bytes(carrier), excluded_ranges)
    if recomputed_hash != payload_dict.get("cover_hash"):
        result["verdict"] = VERDICT_TAMPERED
        result["detail"] = "Signature is valid, but the cover object was modified outside the hidden data region."
        return result

    result["verdict"] = VERDICT_AUTHENTIC
    result["detail"] = "Signature valid and cover object hash matches -- file is authentic and untampered."
    return result


def _constant_time_eq(a: bytes, b: bytes) -> bool:
    import hmac as _hmac
    return _hmac.compare_digest(a, b)
