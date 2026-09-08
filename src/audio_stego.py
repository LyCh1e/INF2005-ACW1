"""
audio_stego.py
---------------
WAV/PCM cover-object adapter: converts a mono/stereo, 8-bit or 16-bit PCM
WAV file to/from the flat "carrier" byte array used by stego_engine.py.

For 16-bit PCM (the common case) only the LOW-ORDER byte of each
little-endian sample is used as a carrier unit -- the high-order byte is
left untouched. This keeps LSB modification confined to the byte that
already carries the least perceptual weight, instead of also touching the
high byte of the 16-bit sample (which would otherwise be interleaved into
a naive flat byte view and cause audible artefacts).
For 8-bit PCM, every sample byte is a full carrier unit.

Only uncompressed PCM WAV is supported for the basic implementation
(FR2 permits this and requires documenting the limitation, which is done
in the README: no MP3/ADPCM/float WAV support).
"""

from __future__ import annotations

import wave

import stego_engine


class UnsupportedAudioFormat(Exception):
    pass


def _load_carrier(path: str):
    with wave.open(path, "rb") as wf:
        params = wf.getparams()
        raw = bytearray(wf.readframes(params.nframes))

    if params.sampwidth == 2:
        carrier = bytearray(raw[0::2])  # low byte of every 16-bit little-endian sample
    elif params.sampwidth == 1:
        carrier = bytearray(raw)  # 8-bit PCM: every byte is a full sample
    else:
        raise UnsupportedAudioFormat(
            f"Only 8-bit or 16-bit PCM WAV is supported (got sample width = {params.sampwidth} bytes). "
            "Convert the file to 16-bit PCM WAV first."
        )
    return params, raw, carrier


def _save_carrier(params, raw: bytearray, carrier: bytes, out_path: str) -> None:
    raw = bytearray(raw)
    if params.sampwidth == 2:
        raw[0::2] = carrier
    else:
        raw[:] = carrier
    with wave.open(out_path, "wb") as wf:
        wf.setparams(params)
        wf.writeframes(bytes(raw))


def capacity_report(path: str, lsb_depth: int) -> dict:
    params, _, carrier = _load_carrier(path)
    max_msg = stego_engine.estimate_max_message_bytes(len(carrier), lsb_depth, "audio", "Px-x")
    return {
        "channels": params.nchannels, "sampwidth": params.sampwidth,
        "framerate": params.framerate, "nframes": params.nframes,
        "carrier_bytes": len(carrier), "max_message_bytes": max_msg,
    }


def embed_audio(
    cover_path: str, output_path: str, *, secret_key: bytes, private_key,
    message: str, lsb_depth: int, media_id: str, team_id: str, extra_metadata: dict | None = None,
) -> dict:
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
    params, _, carrier = _load_carrier(stego_path)
    result = stego_engine.extract_and_verify(bytes(carrier), secret_key=secret_key, public_key=public_key)
    result.update({
        "channels": params.nchannels, "sampwidth": params.sampwidth, "framerate": params.framerate,
    })
    return result
