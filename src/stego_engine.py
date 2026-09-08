"""
stego_engine.py
----------------
The heart of the tool: the cover-object-agnostic **embed / extract /
verify** workflow.

`image_stego.py` and `audio_stego.py` only know how to turn their file
format into a flat `bytearray` carrier and back.  Everything security-
related - hashing, payload building, signing, choosing the secret start
location, writing the two hidden regions, and producing a verdict - happens
here, once, so it is defined and tested in a single place.

Map to the assignment's suggested security workflow (spec section 7):
    embed_payload()       -> steps 1-6  (protect a file)
    extract_and_verify()  -> steps 7-10 (verify a file, return a verdict)
"""

from __future__ import annotations

import bitops
import crypto_utils
import format_spec as fmt
import payload as payload_mod

# --- Carrier geometry -----------------------------------------------------
HEADER_MARGIN_UNITS = fmt.HEADER_MARGIN_UNITS          # gap before the header
HEADER_UNITS = fmt.HEADER_LEN * 8                      # header is 1 bit/unit -> 8 units per byte
HEADER_END_UNITS = HEADER_MARGIN_UNITS + HEADER_UNITS  # first unit the capsule may use

# Fixed capsule overhead around the JSON payload:
#   4 (MAGIC2) + 4 (payload_len) + 2 (sig_len) + 256 (RSA-2048 signature)
CAPSULE_FIXED_OVERHEAD = 4 + 4 + 2 + 256

# --- Verdict strings (FR10) ---------------------------------------------
VERDICT_AUTHENTIC = "Authentic"
VERDICT_TAMPERED = "Tampered"
VERDICT_SIGNATURE_INVALID = "Signature Invalid"
VERDICT_PAYLOAD_MISSING = "Payload Missing"
VERDICT_WRONG_START_LOCATION = "Wrong Start Location"
VERDICT_CANNOT_VERIFY = "Cannot Verify"


class CapacityError(Exception):
    """Raised when the payload is larger than the cover object can hold
    (the mandatory 'is payload size larger than cover object size?' check)."""


def estimate_max_message_bytes(carrier_len: int, lsb_depth: int, cover_type: str, team_id: str) -> int:
    """Approximate how many bytes the free-text `message` field may hold for
    a given cover size and LSB depth.  Used by the GUI capacity check.

    We start from the total capsule capacity and subtract everything that is
    NOT the message: the reserved header region, the fixed capsule overhead
    (magic + length fields + 256-byte RSA signature), and the fixed-size
    JSON fields around the message (built here with an empty message so we
    can measure them).
    """
    if carrier_len <= HEADER_END_UNITS:
        return 0

    # Bytes available for the whole capsule, from just after the header on.
    available_capsule_bytes = bitops.capacity_bytes(carrier_len, HEADER_END_UNITS, lsb_depth)

    # Measure the JSON payload with an empty message; every other field is
    # fixed-length (a real SHA-256 hex is always 64 chars, ids are bounded).
    draft = payload_mod.build_payload(
        media_id="X" * 40, cover_type=cover_type, message="", lsb_depth=lsb_depth,
        cover_stable_hash_hex="0" * 64, team_id=team_id,
    )
    empty_payload_len = len(payload_mod.serialize_payload(draft))

    usable = available_capsule_bytes - CAPSULE_FIXED_OVERHEAD - empty_payload_len
    return max(0, usable)


def _build_capsule_for_message(
    media_id: str, cover_type: str, message: str, lsb_depth: int, team_id: str,
    cover_stable_hash_hex_placeholder: str = "0" * 64,
) -> bytes:
    """Serialise a *draft* payload using a placeholder cover hash.

    We need the exact final payload length *before* we know the real cover
    hash, because the start offset and the reserved capsule span depend on
    that length.  A real SHA-256 hex digest is always exactly 64 characters,
    so swapping the 64-char placeholder for the real digest later never
    changes the byte count - the reservation stays correct.
    """
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
    """Encoder side (spec section 7, steps 1-6). Mutates `carrier` in place
    and returns a stats dict for the GUI / test evidence.
    """
    # --- Guard rails -----------------------------------------------------
    if not (1 <= lsb_depth <= 8):
        raise ValueError("lsb_depth must be between 1 and 8")
    if len(carrier) <= HEADER_END_UNITS:
        raise CapacityError("Cover object is too small to hold even the locator header")

    # --- Step 1: work out the exact capsule size (draft payload + a
    #             correctly-sized dummy signature) so we can reserve space.
    draft_payload_bytes = _build_capsule_for_message(media_id, cover_type, message, lsb_depth, team_id)
    sig_len_estimate = private_key.key_size // 8          # 2048-bit key -> 256 bytes
    capsule_len = fmt.capsule_total_len(draft_payload_bytes, b"0" * sig_len_estimate)
    units_needed = bitops.required_units(capsule_len, lsb_depth)

    # --- Capacity check (FR: "is payload size larger than cover object?") ---
    if HEADER_END_UNITS + units_needed > len(carrier):
        raise CapacityError(
            f"Payload capsule needs {units_needed} carrier units but only "
            f"{len(carrier) - HEADER_END_UNITS} are available after the header "
            f"(cover object capacity too small for this payload)."
        )

    # --- Step 5a: derive the SECRET start offset for the capsule.
    # salt is fresh per file; capacity_bound is exclusive and leaves exactly
    # enough room for the whole capsule, so the offset is never at unit 0.
    salt = crypto_utils.random_salt()
    capacity_bound = len(carrier) - units_needed + 1
    start_offset = crypto_utils.derive_start_offset(secret_key, salt, HEADER_END_UNITS, capacity_bound)

    # --- Steps 2-3: hash the "stable" part of the cover (everything except
    # the header region and the capsule region we are about to overwrite).
    excluded_ranges = [
        (HEADER_MARGIN_UNITS, HEADER_END_UNITS),
        (start_offset, start_offset + units_needed),
    ]
    cover_hash_hex = payload_mod.stable_cover_hash(bytes(carrier), excluded_ranges)

    # --- Step 3 (cont.) + Step 4: build the real payload and sign it.
    real_payload = payload_mod.build_payload(
        media_id=media_id, cover_type=cover_type, message=message, lsb_depth=lsb_depth,
        cover_stable_hash_hex=cover_hash_hex, team_id=team_id, extra_metadata=extra_metadata,
    )
    payload_bytes = payload_mod.serialize_payload(real_payload)
    # Sanity: real payload must be the same length as the draft (see
    # _build_capsule_for_message) or our space reservation is wrong.
    if len(payload_bytes) != len(draft_payload_bytes):
        raise AssertionError("Internal error: payload length changed after hashing (report this bug)")

    signature = crypto_utils.sign_data(private_key, crypto_utils.sha256_bytes(payload_bytes))
    capsule = fmt.pack_capsule(payload_bytes, signature)
    if len(capsule) != capsule_len:
        raise AssertionError("Internal error: capsule length mismatch (report this bug)")

    # --- Step 5b: embed the capsule at the derived offset, user's LSB depth.
    bitops.embed_bits(carrier, start_offset, lsb_depth, capsule)

    # --- Step 6: embed the locator header at the fixed margin, always 1 LSB.
    # The header stores the offset only in ENCRYPTED form, plus an HMAC tag.
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
    """Decoder side (spec section 7, steps 7-10).

    Always returns a dict with a `verdict` (one of the VERDICT_* strings) and
    a human-readable `detail`; it never raises for an expected failure mode.
    """
    result = {"verdict": None, "detail": "", "payload": None, "start_offset": None}

    # --- Is the file even big enough to contain a header? ---
    if len(carrier) <= HEADER_END_UNITS:
        result["verdict"] = VERDICT_PAYLOAD_MISSING
        result["detail"] = "Cover object too small to contain a locator header."
        return result

    # --- Step 7a: read the 33 header bytes from the fixed margin (1 LSB). ---
    header_raw = bitops.extract_bits(carrier, HEADER_MARGIN_UNITS, 1, fmt.HEADER_LEN)
    try:
        header = fmt.unpack_header(header_raw)
    except fmt.HeaderError as exc:
        # No magic marker here -> this file was never protected by our tool.
        result["verdict"] = VERDICT_PAYLOAD_MISSING
        result["detail"] = f"No valid locator header found: {exc}"
        return result

    # --- Step 7b: authenticate the header with the shared secret key. ---
    # Wrong key, or any tampering with the header fields, changes the tag.
    expected_tag = fmt.header_tag(secret_key, header["lsb"], header["salt"], header["enc_offset"], header["clen"])
    if not _constant_time_eq(expected_tag, header["tag"]):
        result["verdict"] = VERDICT_CANNOT_VERIFY
        result["detail"] = "Locator header authentication failed (wrong secret key, or header was tampered)."
        return result

    # --- Step 7c: decrypt the real start offset and range-check it. ---
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

    # --- Step 7d: read the capsule bytes and split payload / signature. ---
    capsule_raw = bitops.extract_bits(carrier, start_offset, lsb_depth, clen)
    try:
        payload_bytes, signature = fmt.parse_capsule(capsule_raw)
    except fmt.CapsuleError as exc:
        # Header was authentic but the capsule bytes themselves are broken.
        result["verdict"] = VERDICT_TAMPERED
        result["detail"] = f"Header was authentic but capsule content is corrupted: {exc}"
        return result

    # --- Step 8: verify the digital signature over the payload. ---
    sig_ok = crypto_utils.verify_signature(public_key, crypto_utils.sha256_bytes(payload_bytes), signature)
    if not sig_ok:
        result["verdict"] = VERDICT_SIGNATURE_INVALID
        result["detail"] = "Digital signature does not match the extracted payload (wrong key or payload altered)."
        return result

    # Signature is valid, so the payload JSON should parse cleanly.
    try:
        payload_dict = payload_mod.deserialize_payload(payload_bytes)
    except Exception as exc:
        result["verdict"] = VERDICT_TAMPERED
        result["detail"] = f"Signed payload is not valid JSON: {exc}"
        return result
    result["payload"] = payload_dict

    # --- Step 9: recompute the stable cover hash and compare it to the
    # value inside the signed payload.  A mismatch means the visible /
    # audible content was changed after signing.
    excluded_ranges = [
        (HEADER_MARGIN_UNITS, HEADER_END_UNITS),
        (start_offset, start_offset + units_needed),
    ]
    recomputed_hash = payload_mod.stable_cover_hash(bytes(carrier), excluded_ranges)
    if recomputed_hash != payload_dict.get("cover_hash"):
        result["verdict"] = VERDICT_TAMPERED
        result["detail"] = "Signature is valid, but the cover object was modified outside the hidden data region."
        return result

    # --- Step 10: everything checks out. ---
    result["verdict"] = VERDICT_AUTHENTIC
    result["detail"] = "Signature valid and cover object hash matches -- file is authentic and untampered."
    return result


def _constant_time_eq(a: bytes, b: bytes) -> bool:
    """Compare two byte strings without leaking, via timing, how many
    leading bytes matched.  Standard practice for comparing MAC tags."""
    import hmac as _hmac
    return _hmac.compare_digest(a, b)
