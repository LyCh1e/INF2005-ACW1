"""
audio_stego.py
---------------
The WAV/PCM adapter (FR2 / FR6).

It converts an uncompressed PCM WAV to/from the flat `bytearray` "carrier"
that `stego_engine` works on.

Carrier mapping:
  * 16-bit PCM (the usual case): each sample is two little-endian bytes
    [low, high].  We use ONLY the low byte of each sample as a carrier
    unit.  The low byte carries the least perceptual weight, so editing its
    LSBs is the least audible; leaving the high byte untouched avoids the
    loud clicks you would get from modifying it.
  * 8-bit PCM: each sample is a single byte, so every byte is a carrier unit.

Only uncompressed PCM WAV is supported (FR2 allows this for the basic
implementation).  MP3 / ADPCM / float WAV are lossy or non-linear and would
corrupt the hidden bits, exactly like JPEG does for images - see README.
"""

from __future__ import annotations

import wave

import payload as payload_mod
import stego_engine


class UnsupportedAudioFormat(Exception):
    """Raised for sample widths we do not handle (anything but 8- or 16-bit PCM)."""


def _load_carrier(path: str):
    """Open a WAV and return (params, raw frame bytes, carrier bytes).

    `params` (channels, sample width, frame rate, ...) is kept so we can
    write an identical-format file back out.  `raw` is every frame byte;
    `carrier` is the subset of bytes we are allowed to touch.
    """
    with wave.open(path, "rb") as wf:
        params = wf.getparams()
        raw = bytearray(wf.readframes(params.nframes))

    if params.sampwidth == 2:
        # raw = [lo0, hi0, lo1, hi1, ...]; raw[0::2] is every low byte.
        carrier = bytearray(raw[0::2])
    elif params.sampwidth == 1:
        carrier = bytearray(raw)  # 8-bit PCM: every byte is a whole sample
    else:
        raise UnsupportedAudioFormat(
            f"Only 8-bit or 16-bit PCM WAV is supported (got sample width = {params.sampwidth} bytes). "
            "Convert the file to 16-bit PCM WAV first."
        )
    return params, raw, carrier


def _save_carrier(params, raw: bytearray, carrier: bytes, out_path: str) -> None:
    """Splice the (possibly modified) carrier bytes back into the full frame
    buffer and write a WAV with the original parameters."""
    raw = bytearray(raw)
    if params.sampwidth == 2:
        raw[0::2] = carrier   # put the low bytes back, leave the high bytes alone
    else:
        raw[:] = carrier
    with wave.open(out_path, "wb") as wf:
        wf.setparams(params)
        wf.writeframes(bytes(raw))


def capacity_report(path: str, lsb_depth: int, team_id: str = payload_mod.TEAM_ID_DEFAULT) -> dict:
    """Report the WAV's format and the largest message that fits at `lsb_depth`."""
    params, _, carrier = _load_carrier(path)
    max_msg = stego_engine.estimate_max_message_bytes(len(carrier), lsb_depth, "audio", team_id)
    return {
        "channels": params.nchannels, "sampwidth": params.sampwidth,
        "framerate": params.framerate, "nframes": params.nframes,
        "carrier_bytes": len(carrier), "max_message_bytes": max_msg,
    }


def embed_audio(
    cover_path: str, output_path: str, *, secret_key: bytes, private_key,
    message: str, lsb_depth: int, media_id: str, team_id: str, extra_metadata: dict | None = None,
) -> dict:
    """Protect a WAV: load samples -> run the shared embed workflow -> save."""
    params, raw, carrier = _load_carrier(cover_path)
    stats = stego_engine.embed_payload(
        carrier, secret_key=secret_key, private_key=private_key, media_id=media_id,
        cover_type="audio", message=message, lsb_depth=lsb_depth, team_id=team_id,
        extra_metadata=extra_metadata,
    )
    _save_carrier(params, raw, carrier, output_path)
    stats.update({
        "channels": params.nchannels, "sampwidth": params.sampwidth,
        "framerate": params.framerate, "output_path": output_path,
    })
    return stats


def extract_and_verify_audio(stego_path: str, *, secret_key: bytes, public_key) -> dict:
    """Verify a WAV: load samples -> run the shared verify workflow -> verdict."""
    params, _, carrier = _load_carrier(stego_path)
    result = stego_engine.extract_and_verify(bytes(carrier), secret_key=secret_key, public_key=public_key)
    result.update({
        "channels": params.nchannels, "sampwidth": params.sampwidth, "framerate": params.framerate,
    })
    return result
