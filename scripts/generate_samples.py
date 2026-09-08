"""
generate_samples.py
-------------------
Creates the original (unprotected) cover files used by the demo:

  samples/originals/sample_image.png   640x480 RGB PNG (colour gradient + shapes)
  samples/originals/sample_audio.wav   5 s, 44.1 kHz, 16-bit mono PCM sine sweep

Both are synthetic so the repo needs no third-party media and the demo is
fully reproducible.

Run:  python scripts/generate_samples.py
"""

import math
import wave
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
ORIGINALS = ROOT / "samples" / "originals"
ORIGINALS.mkdir(parents=True, exist_ok=True)


def make_image(path: Path, size=(640, 480)):
    """Draw a smooth RGB gradient, then a few outline shapes and a caption,
    so the image has both flat and detailed regions to embed into."""
    w, h = size
    arr = np.zeros((h, w, 3), dtype=np.uint8)
    # Per-pixel gradient: R rises left->right, G rises top->bottom,
    # B is bright only near the top-left corner.
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
    """Synthesise a gentle 220 Hz -> 880 Hz sine sweep with a soft fade
    in/out, as 16-bit mono PCM."""
    n = int(duration_s * framerate)
    t = np.linspace(0, duration_s, n, endpoint=False)

    # Instantaneous frequency rises linearly; phase is its running integral.
    freq = 220 + (880 - 220) * (t / duration_s)
    phase = 2 * math.pi * np.cumsum(freq) / framerate

    # Half-sine amplitude envelope so the clip fades in and out smoothly.
    envelope = 0.6 * np.sin(math.pi * t / duration_s) ** 0.5

    # Scale the [-1, 1] waveform into the 16-bit signed integer range.
    samples = (envelope * np.sin(phase) * 32767).astype(np.int16)

    with wave.open(str(path), "wb") as wf:
        wf.setnchannels(1)     # mono
        wf.setsampwidth(2)     # 16-bit
        wf.setframerate(framerate)
        wf.writeframes(samples.tobytes())
    print(f"Wrote {path} ({duration_s}s, {framerate}Hz, 16-bit mono PCM WAV)")


if __name__ == "__main__":
    make_image(ORIGINALS / "sample_image.png")
    make_audio(ORIGINALS / "sample_audio.wav")
