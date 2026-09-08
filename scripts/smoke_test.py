"""
smoke_test.py
-------------
A fast internal sanity check of the embed -> extract -> verify round trip
for both cover objects, plus the wrong-key and tampered cases.

This is a developer convenience, NOT the graded evidence - for that, see
scripts/run_demo_cases.py.  If this script prints "ALL SMOKE TESTS PASSED"
the core pipeline is healthy.

Run:  python scripts/smoke_test.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import crypto_utils  # noqa: E402
import image_stego  # noqa: E402
import audio_stego  # noqa: E402
import payload as payload_mod  # noqa: E402

PRIV = ROOT / "keys" / "private_key.pem"
PUB = ROOT / "keys" / "public_key.pem"
SECRET_KEY = b"team-shared-secret-demo-key"
TEAM_ID = payload_mod.TEAM_ID_DEFAULT


def test_image():
    """Protect and then verify a PNG - expect the Authentic verdict and the
    exact message back."""
    priv = crypto_utils.load_private_key(PRIV)
    pub = crypto_utils.load_public_key(PUB)
    src = ROOT / "samples" / "originals" / "sample_image.png"
    out = ROOT / "samples" / "protected" / "sample_image_stego.png"
    out.parent.mkdir(parents=True, exist_ok=True)

    stats = image_stego.embed_image(
        str(src), str(out), secret_key=SECRET_KEY, private_key=priv,
        message="hello from image stego test", lsb_depth=2, media_id="img-test-1", team_id=TEAM_ID,
    )
    print("embed stats:", {k: v for k, v in stats.items() if k != "payload"})

    result = image_stego.extract_and_verify_image(str(out), secret_key=SECRET_KEY, public_key=pub)
    print("verify result:", result["verdict"], "-", result["detail"])
    assert result["verdict"] == "Authentic", "expected Authentic verdict for untampered stego image"
    assert result["payload"]["message"] == "hello from image stego test"
    print("IMAGE round trip OK\n")


def test_audio():
    """Same round trip for a WAV."""
    priv = crypto_utils.load_private_key(PRIV)
    pub = crypto_utils.load_public_key(PUB)
    src = ROOT / "samples" / "originals" / "sample_audio.wav"
    out = ROOT / "samples" / "protected" / "sample_audio_stego.wav"
    out.parent.mkdir(parents=True, exist_ok=True)

    stats = audio_stego.embed_audio(
        str(src), str(out), secret_key=SECRET_KEY, private_key=priv,
        message="hello from audio stego test", lsb_depth=3, media_id="aud-test-1", team_id=TEAM_ID,
    )
    print("embed stats:", {k: v for k, v in stats.items() if k != "payload"})

    result = audio_stego.extract_and_verify_audio(str(out), secret_key=SECRET_KEY, public_key=pub)
    print("verify result:", result["verdict"], "-", result["detail"])
    assert result["verdict"] == "Authentic"
    assert result["payload"]["message"] == "hello from audio stego test"
    print("AUDIO round trip OK\n")


def test_tamper_and_wrong_key():
    """A wrong secret key must give 'Cannot Verify'; editing a pixel outside
    the hidden region must give 'Tampered'."""
    priv = crypto_utils.load_private_key(PRIV)
    pub = crypto_utils.load_public_key(PUB)
    src = ROOT / "samples" / "originals" / "sample_image.png"
    out = ROOT / "samples" / "protected" / "sample_image_stego2.png"
    image_stego.embed_image(
        str(src), str(out), secret_key=SECRET_KEY, private_key=priv,
        message="tamper test", lsb_depth=1, media_id="img-tamper-1", team_id=TEAM_ID,
    )

    # Wrong secret key -> the locator header will not authenticate.
    result = image_stego.extract_and_verify_image(str(out), secret_key=b"wrong-key", public_key=pub)
    print("wrong key verdict:", result["verdict"])
    assert result["verdict"] == "Cannot Verify"

    # Flip a pixel far from the header / capsule region -> cover hash mismatch.
    from PIL import Image
    img = Image.open(out)
    img.load()
    px = img.load()
    x, y = img.size[0] - 5, img.size[1] - 5
    r, g, b = px[x, y][:3]
    px[x, y] = (255 - r, 255 - g, 255 - b) + px[x, y][3:]
    tampered_path = str(out).replace(".png", "_tampered.png")
    img.save(tampered_path)
    result = image_stego.extract_and_verify_image(tampered_path, secret_key=SECRET_KEY, public_key=pub)
    print("tampered verdict:", result["verdict"])
    assert result["verdict"] == "Tampered"
    print("TAMPER / WRONG-KEY cases OK\n")


if __name__ == "__main__":
    test_image()
    test_audio()
    test_tamper_and_wrong_key()
    print("ALL SMOKE TESTS PASSED")
