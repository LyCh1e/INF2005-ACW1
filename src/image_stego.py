"""
image_stego.py
---------------
PNG cover-object adapter: converts an image file to/from the flat "carrier"
byte array used by stego_engine.py. Every raw pixel channel byte (R,G,B[,A])
is treated as one carrier unit, in row-major left-to-right, top-to-bottom
order -- so unit 0 is the very first channel byte of the top-left pixel,
which is exactly why the locator header is never placed there (see
stego_engine.HEADER_MARGIN_UNITS).
"""

from __future__ import annotations

from PIL import Image

import stego_engine


def _load_carrier(path: str):
    img = Image.open(path)
    img.load()
    mode = img.mode
    size = img.size
    carrier = bytearray(img.tobytes())
    return img, mode, size, carrier


def _save_carrier(mode: str, size, carrier: bytes, out_path: str) -> None:
    out_img = Image.frombytes(mode, size, bytes(carrier))
    out_img.save(out_path)


def capacity_report(path: str, lsb_depth: int) -> dict:
    _, mode, size, carrier = _load_carrier(path)
    max_msg = stego_engine.estimate_max_message_bytes(len(carrier), lsb_depth, "image", "Px-x")
    return {
        "mode": mode, "size": size, "carrier_bytes": len(carrier),
        "max_message_bytes": max_msg,
    }


def embed_image(
    cover_path: str, output_path: str, *, secret_key: bytes, private_key,
    message: str, lsb_depth: int, media_id: str, team_id: str, extra_metadata: dict | None = None,
) -> dict:
    _, mode, size, carrier = _load_carrier(cover_path)
    stats = stego_engine.embed_payload(
        carrier, secret_key=secret_key, private_key=private_key, media_id=media_id,
        cover_type="image", message=message, lsb_depth=lsb_depth, team_id=team_id,
        extra_metadata=extra_metadata,
    )
    _save_carrier(mode, size, carrier, output_path)
    stats.update({"mode": mode, "size": size, "output_path": output_path})
    return stats


def extract_and_verify_image(stego_path: str, *, secret_key: bytes, public_key) -> dict:
    _, mode, size, carrier = _load_carrier(stego_path)
    result = stego_engine.extract_and_verify(bytes(carrier), secret_key=secret_key, public_key=public_key)
    result.update({"mode": mode, "size": size})
    return result
