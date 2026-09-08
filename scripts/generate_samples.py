"""
Generate original sample cover files for the demo:
  samples/originals/sample_image.png   (640x480 RGB PNG, gradient + shapes)
  samples/originals/sample_audio.wav   (5s, 44.1kHz, 16-bit mono sine sweep)

Run:  python scripts/generate_samples.py
"""

import math
import struct
import wave
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
ORIGINALS = ROOT / "samples" / "originals"
ORIGINALS.mkdir(parents=True, exist_ok=True)


def make_image(path: Path, size=(640, 480)):
    w, h = size
    arr = np.zeros((h, w, 3), dtype=np.uint8)
    for y in range(h):
        for x in range(w):
            arr[y, x] = (int(255 * x / w), int(255 * y / h), int(255 * (1 - x / w) * (1 - y / h)))
    img = Image.fromarray(arr, mode="RGB")
    draw = ImageDraw.Draw(img)
    draw.ellipse((w * 0.3, h * 0.3, w * 0.7, h * 0.7), outline=(255, 255, 255), width=6)
    draw.rectangle((20, 20, 220, 70), outline=(0, 0, 0), width=4)
    draw.text((30, 30), "INF2005 ACW1 sample cover", fill=(0, 0, 0))
    img.save(path)
    print(f"Wrote {path} ({w}x{h} RGB PNG)")


def make_audio(path: Path, duration_s=5.0, framerate=44100):
    n = int(duration_s * framerate)
    t = np.linspace(0, duration_s, n, endpoint=False)
    # gentle sine sweep 220Hz -> 880Hz plus light envelope, 16-bit mono PCM
    freq = 220 + (880 - 220) * (t / duration_s)
    phase = 2 * math.pi * np.cumsum(freq) / framerate
    envelope = 0.6 * np.sin(math.pi * t / duration_s) ** 0.5
    samples = (envelope * np.sin(phase) * 32767).astype(np.int16)

    with wave.open(str(path), "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(framerate)
        wf.writeframes(samples.tobytes())
    print(f"Wrote {path} ({duration_s}s, {framerate}Hz, 16-bit mono PCM WAV)")


if __name__ == "__main__":
    make_image(ORIGINALS / "sample_image.png")
    make_audio(ORIGINALS / "sample_audio.wav")
