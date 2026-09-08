"""
image_stego.py
---------------
The PNG adapter (FR1 / FR5).

It converts a PNG to/from the flat `bytearray` "carrier" that
`stego_engine` works on.  Every raw pixel-channel byte is one carrier unit,
in row-major order (left to right, top to bottom):

    unit 0 = red channel of the top-left pixel
    unit 1 = green channel of the top-left pixel
    ...

That is exactly why the locator header is not placed at unit 0 - it would
sit in the corner pixel, the first place an attacker looks.

Why PNG and not JPEG: PNG is lossless, so re-saving the pixels keeps every
LSB we wrote.  JPEG's lossy compression would scramble the hidden bits
(this limitation is documented in the README).
"""

from __future__ import annotations

from PIL import Image

import payload as payload_mod
import stego_engine


def _load_carrier(path: str):
    """Open an image and return (PIL image, mode, size, carrier bytes).

    `img.tobytes()` gives the raw pixel bytes for the current mode
    (e.g. 'RGB' -> 3 bytes/pixel, 'RGBA' -> 4).  We wrap them in a
    bytearray so `stego_engine` can modify them in place.
    """
    img = Image.open(path)
    img.load()
    mode = img.mode
    size = img.size
    carrier = bytearray(img.tobytes())
    return img, mode, size, carrier


def _save_carrier(mode: str, size, carrier: bytes, out_path: str) -> None:
    """Rebuild an image from modified carrier bytes and save it losslessly."""
    out_img = Image.frombytes(mode, size, bytes(carrier))
    out_img.save(out_path)


def capacity_report(path: str, lsb_depth: int, team_id: str = payload_mod.TEAM_ID_DEFAULT) -> dict:
    """Report the cover's pixel geometry and the largest message that fits
    at `lsb_depth`.  `team_id` is passed through because a longer team id
    makes the JSON payload slightly bigger and so reduces the message room.
    """
    _, mode, size, carrier = _load_carrier(path)
    max_msg = stego_engine.estimate_max_message_bytes(len(carrier), lsb_depth, "image", team_id)
    return {
        "mode": mode, "size": size, "carrier_bytes": len(carrier),
        "max_message_bytes": max_msg,
    }


def embed_image(
    cover_path: str, output_path: str, *, secret_key: bytes, private_key,
    message: str, lsb_depth: int, media_id: str, team_id: str, extra_metadata: dict | None = None,
) -> dict:
    """Protect a PNG: load pixels -> run the shared embed workflow -> save."""
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
    """Verify a PNG: load pixels -> run the shared verify workflow -> verdict."""
    _, mode, size, carrier = _load_carrier(stego_path)
    result = stego_engine.extract_and_verify(bytes(carrier), secret_key=secret_key, public_key=public_key)
    result.update({"mode": mode, "size": size})
    return result
