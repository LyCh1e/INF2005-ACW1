"""
run_demo_cases.py
------------------
Regenerates ALL the positive/negative test evidence for the ACW1 demo in
one run, for BOTH cover objects (image + audio):

  * capacity check (payload larger than the cover is rejected up front)
  * three payload sizes: short (a Learning Outcome), large (the Project
    Overview paragraph), and a custom confidentiality/integrity message
  * a sender -> receiver ("party A emails, party B downloads") simulation
  * every verdict category: Authentic, Tampered, Signature Invalid,
    Payload Missing, Wrong Start Location, Cannot Verify
  * the full selectable-LSB range (1..8)

Run:  python scripts/run_demo_cases.py

Writes:
  samples/protected/...           stego files used in the cases
  samples/tampered/...            deliberately tampered copies
  samples/protected/received/...  "party B" copies for the send/receive case
  test_evidence/demo_report.md    a readable table of every case + verdict
  test_evidence/demo_report.json  the same, machine-readable
"""

import json
import shutil
import sys
import wave
from pathlib import Path

# Make src/ importable.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import crypto_utils       # noqa: E402
import image_stego        # noqa: E402
import audio_stego        # noqa: E402
import stego_engine       # noqa: E402
import format_spec as fmt  # noqa: E402
import bitops             # noqa: E402
import payload as payload_mod  # noqa: E402
from PIL import Image     # noqa: E402

# --- Key files ----------------------------------------------------------
PRIV = ROOT / "keys" / "private_key.pem"
PUB = ROOT / "keys" / "public_key.pem"
# A second, "untrusted" key pair, used only to produce the Signature Invalid
# case (a file signed by someone whose public key we do NOT trust).
OTHER_PRIV = ROOT / "keys" / "other_team_private_key.pem"
OTHER_PUB = ROOT / "keys" / "other_team_public_key.pem"

# --- Folders ----------------------------------------------------------
ORIGINALS = ROOT / "samples" / "originals"
PROTECTED = ROOT / "samples" / "protected"
TAMPERED = ROOT / "samples" / "tampered"
RECEIVED = ROOT / "samples" / "protected" / "received"
EVIDENCE = ROOT / "test_evidence"

# --- Shared demo constants ------------------------------------------
SECRET_KEY = b"team-shared-secret-demo-key"      # the legitimate shared secret
WRONG_KEY = b"an-attacker-guessed-this-key"      # used for the Cannot Verify case
TEAM_ID = payload_mod.TEAM_ID_DEFAULT

SHORT_MESSAGE = (
    "Use digital signatures to verify that a payload or file record was issued by a "
    "legitimate signer and has not been altered."
)
LARGE_MESSAGE = (
    "This undergraduate project requires student teams to design, implement and demonstrate a "
    "GUI-based LSB Replacement steganography program (window-based or web-based) that protects "
    "and verifies both image and audio cover objects using steganography, hashing and digital "
    "signatures. The project focuses on practical cybersecurity concepts: hiding a verification "
    "payload inside an image and an audio file, signing relevant verification data, extracting "
    "the hidden payload, checking the digital signature, and demonstrating positive and negative "
    "verification cases. Video as a cover object is not required for the main assignment, but "
    "may be attempted as an optional challenge."
)
CUSTOM_MESSAGE = (
    f"CONFIDENTIAL[{TEAM_ID}]: media-release-approval=TRUE; approver=TeamLead; "
    "note='Protects confidentiality+integrity of the release decision.'"
)

results = []  # every case appends one dict here


def record(case_id, cover_type, category, description, verdict, expected, extra=None):
    """Store one case result and print a PASS/FAIL line."""
    ok = verdict == expected
    results.append({
        "case_id": case_id, "cover_type": cover_type, "category": category,
        "description": description, "verdict": verdict, "expected": expected,
        "pass": ok, "extra": extra or {},
    })
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {case_id} ({cover_type}/{category}): verdict={verdict!r} expected={expected!r}")


def setup_dirs():
    """Create output folders and both key pairs if they do not exist yet."""
    for d in (PROTECTED, TAMPERED, RECEIVED, EVIDENCE):
        d.mkdir(parents=True, exist_ok=True)
    if not PRIV.exists() or not PUB.exists():
        crypto_utils.generate_keypair(PRIV, PUB)
    if not OTHER_PRIV.exists() or not OTHER_PUB.exists():
        crypto_utils.generate_keypair(OTHER_PRIV, OTHER_PUB)


# --- Tamper helpers (edit the cover OUTSIDE the hidden region) ---------
def tamper_image_pixels(path: Path, out_path: Path, corner="bottom-right", n=6):
    """Invert an n x n block of pixels in a corner of the image."""
    img = Image.open(path)
    px = img.load()
    assert px is not None
    w, h = img.size
    for dx in range(n):
        for dy in range(n):
            x, y = (w - 1 - dx, h - 1 - dy) if corner == "bottom-right" else (dx, dy)
            pixel = px[x, y]
            if isinstance(pixel, (int, float)):
                px[x, y] = int(255 - pixel)
            else:
                px[x, y] = tuple(255 - c for c in pixel[:3]) + tuple(pixel[3:])
    img.save(out_path)


def tamper_audio_tail(path: Path, out_path: Path, n=20):
    """Flip the last n bytes of frame data."""
    with wave.open(str(path), "rb") as wf:
        params = wf.getparams()
        raw = bytearray(wf.readframes(params.nframes))
    for i in range(1, n + 1):
        raw[-i] ^= 0xFF
    with wave.open(str(out_path), "wb") as wf:
        wf.setparams(params)
        wf.writeframes(bytes(raw))


# --- "Wrong Start Location" helper -----------------------------------
def _rewrite_header_with_bad_offset(carrier: bytearray, secret_key: bytes) -> None:
    """Re-embed the locator header so it (validly, with a correct HMAC tag)
    advertises a start offset that is out of range.

    We can only build a header with a valid tag because this script knows
    the secret key - a real outside attacker could not.  The point is to
    exercise the 'Wrong Start Location' verdict branch: the header
    authenticates, but the offset it decrypts to is nonsense.

    We read the header the tool just wrote and keep its real `lsb` and
    `clen` so nothing else about the file has to be hard-coded.
    """
    header_raw = bitops.extract_bits(carrier, stego_engine.HEADER_MARGIN_UNITS, 1, fmt.HEADER_LEN)
    header = fmt.unpack_header(header_raw)

    bad_offset = len(carrier) + 1000  # deliberately past the end of the carrier
    salt = crypto_utils.random_salt()
    enc_offset = crypto_utils.encrypt_offset(secret_key, salt, bad_offset)
    header_bytes = fmt.pack_header(secret_key, header["lsb"], salt, enc_offset, header["clen"])
    bitops.embed_bits(carrier, stego_engine.HEADER_MARGIN_UNITS, 1, header_bytes)


def craft_wrong_start_location_image(stego_path: Path, out_path: Path, secret_key: bytes) -> None:
    img = Image.open(stego_path)
    img.load()
    mode, size = img.mode, img.size
    carrier = bytearray(img.tobytes())
    _rewrite_header_with_bad_offset(carrier, secret_key)
    Image.frombytes(mode, size, bytes(carrier)).save(out_path)


def craft_wrong_start_location_audio(stego_path: Path, out_path: Path, secret_key: bytes) -> None:
    params, raw, carrier = audio_stego._load_carrier(str(stego_path))
    _rewrite_header_with_bad_offset(carrier, secret_key)
    audio_stego._save_carrier(params, raw, carrier, str(out_path))


# ======================================================================
# Image cases
# ======================================================================
def run_image_cases():
    ct = "image"
    priv = crypto_utils.load_private_key(PRIV)
    pub = crypto_utils.load_public_key(PUB)
    other_priv = crypto_utils.load_private_key(OTHER_PRIV)
    src = ORIGINALS / "sample_image.png"

    # --- Capacity check: an oversized message must be rejected up front. ---
    cap = image_stego.capacity_report(str(src), lsb_depth=1)
    huge_message = "X" * (cap["max_message_bytes"] + 5000)
    out_capfail = PROTECTED / "image_case_capacity_exceeded.png"
    try:
        image_stego.embed_image(
            str(src), str(out_capfail), secret_key=SECRET_KEY, private_key=priv,
            message=huge_message, lsb_depth=1, media_id="img-capacity-test", team_id=TEAM_ID,
        )
        capacity_verdict = "Embedded (unexpected)"
    except stego_engine.CapacityError as exc:
        capacity_verdict = "Rejected: Payload larger than cover object capacity"
        print(f"  capacity check message: {exc}")
    record("IMG-CAP-01", ct, "capacity-check",
           f"Cover capacity={cap['max_message_bytes']}B at 1 LSB, message={len(huge_message)}B",
           capacity_verdict, "Rejected: Payload larger than cover object capacity")

    # --- Positive 1: short message, LSB=1. ---
    out1 = PROTECTED / "image_case_positive_short_lsb1.png"
    image_stego.embed_image(str(src), str(out1), secret_key=SECRET_KEY, private_key=priv,
                            message=SHORT_MESSAGE, lsb_depth=1, media_id="img-pos-short", team_id=TEAM_ID)
    r1 = image_stego.extract_and_verify_image(str(out1), secret_key=SECRET_KEY, public_key=pub)
    record("IMG-POS-01", ct, "positive", "Short message (learning objective), LSB=1", r1["verdict"], "Authentic")

    # --- Positive 2: large message, LSB=4, plus sender(A) -> receiver(B). ---
    out2 = PROTECTED / "image_case_positive_large_lsb4.png"
    image_stego.embed_image(str(src), str(out2), secret_key=SECRET_KEY, private_key=priv,
                            message=LARGE_MESSAGE, lsb_depth=4, media_id="img-pos-large", team_id=TEAM_ID)
    received_copy = RECEIVED / out2.name
    shutil.copyfile(out2, received_copy)  # "party A emails file, party B downloads it"
    r2 = image_stego.extract_and_verify_image(str(received_copy), secret_key=SECRET_KEY, public_key=pub)
    record("IMG-POS-02", ct, "positive-send-receive",
           "Large message (project overview), LSB=4, sent A->B then verified by B",
           r2["verdict"], "Authentic")

    # --- Positive 3: custom message, LSB=8 (also exercises the max depth). ---
    out3 = PROTECTED / "image_case_positive_custom_lsb8.png"
    image_stego.embed_image(str(src), str(out3), secret_key=SECRET_KEY, private_key=priv,
                            message=CUSTOM_MESSAGE, lsb_depth=8, media_id="img-pos-custom", team_id=TEAM_ID)
    r3 = image_stego.extract_and_verify_image(str(out3), secret_key=SECRET_KEY, public_key=pub)
    record("IMG-POS-03", ct, "positive", "Custom confidential payload, LSB=8", r3["verdict"], "Authentic")

    # --- Negative 1: Tampered (pixels outside the hidden region flipped). ---
    tampered1 = TAMPERED / "image_case_tampered.png"
    tamper_image_pixels(out1, tampered1)
    r4 = image_stego.extract_and_verify_image(str(tampered1), secret_key=SECRET_KEY, public_key=pub)
    record("IMG-NEG-01", ct, "negative", "Cover pixels tampered after signing", r4["verdict"], "Tampered")

    # --- Negative 2: wrong shared secret key -> header will not authenticate. ---
    r5 = image_stego.extract_and_verify_image(str(out1), secret_key=WRONG_KEY, public_key=pub)
    record("IMG-NEG-02", ct, "negative", "Verifier supplies the wrong shared secret key",
           r5["verdict"], "Cannot Verify")

    # --- Negative 3: file signed with an untrusted key -> Signature Invalid. ---
    out_wrongsig = PROTECTED / "image_case_wrong_signature.png"
    image_stego.embed_image(str(src), str(out_wrongsig), secret_key=SECRET_KEY, private_key=other_priv,
                            message=SHORT_MESSAGE, lsb_depth=1, media_id="img-wrongsig", team_id=TEAM_ID)
    r6 = image_stego.extract_and_verify_image(str(out_wrongsig), secret_key=SECRET_KEY, public_key=pub)
    record("IMG-NEG-03", ct, "negative", "File signed with an untrusted private key",
           r6["verdict"], "Signature Invalid")

    # --- Negative 4: verify a plain, unprotected cover -> Payload Missing. ---
    r7 = image_stego.extract_and_verify_image(str(src), secret_key=SECRET_KEY, public_key=pub)
    record("IMG-NEG-04", ct, "negative", "Original cover object with no embedded payload",
           r7["verdict"], "Payload Missing")

    # --- Negative 5: engineered header advertises an out-of-range offset. ---
    out_wrongloc = PROTECTED / "image_case_wrong_start_location.png"
    craft_wrong_start_location_image(out1, out_wrongloc, SECRET_KEY)
    r8 = image_stego.extract_and_verify_image(str(out_wrongloc), secret_key=SECRET_KEY, public_key=pub)
    record("IMG-NEG-05", ct, "negative", "Header engineered to advertise an out-of-range start offset",
           r8["verdict"], "Wrong Start Location")

    # --- Selectable LSB depth matrix (1..8), each must round-trip. ---
    for depth in range(1, 9):
        out_d = PROTECTED / f"image_case_lsb_depth_{depth}.png"
        image_stego.embed_image(str(src), str(out_d), secret_key=SECRET_KEY, private_key=priv,
                                message=f"LSB depth demo = {depth}", lsb_depth=depth,
                                media_id=f"img-lsb-{depth}", team_id=TEAM_ID)
        rd = image_stego.extract_and_verify_image(str(out_d), secret_key=SECRET_KEY, public_key=pub)
        record(f"IMG-LSB-{depth}", ct, "lsb-matrix", f"Selectable LSB depth = {depth}",
               rd["verdict"], "Authentic")


# ======================================================================
# Audio cases (mirrors the image cases)
# ======================================================================
def run_audio_cases():
    ct = "audio"
    priv = crypto_utils.load_private_key(PRIV)
    pub = crypto_utils.load_public_key(PUB)
    other_priv = crypto_utils.load_private_key(OTHER_PRIV)
    src = ORIGINALS / "sample_audio.wav"

    # --- Capacity check. ---
    cap = audio_stego.capacity_report(str(src), lsb_depth=1)
    huge_message = "X" * (cap["max_message_bytes"] + 5000)
    out_capfail = PROTECTED / "audio_case_capacity_exceeded.wav"
    try:
        audio_stego.embed_audio(str(src), str(out_capfail), secret_key=SECRET_KEY, private_key=priv,
                                message=huge_message, lsb_depth=1, media_id="aud-capacity-test", team_id=TEAM_ID)
        capacity_verdict = "Embedded (unexpected)"
    except stego_engine.CapacityError as exc:
        capacity_verdict = "Rejected: Payload larger than cover object capacity"
        print(f"  capacity check message: {exc}")
    record("AUD-CAP-01", ct, "capacity-check",
           f"Cover capacity={cap['max_message_bytes']}B at 1 LSB, message={len(huge_message)}B",
           capacity_verdict, "Rejected: Payload larger than cover object capacity")

    # --- Positive 1: short message, LSB=2. ---
    out1 = PROTECTED / "audio_case_positive_short_lsb2.wav"
    audio_stego.embed_audio(str(src), str(out1), secret_key=SECRET_KEY, private_key=priv,
                            message=SHORT_MESSAGE, lsb_depth=2, media_id="aud-pos-short", team_id=TEAM_ID)
    r1 = audio_stego.extract_and_verify_audio(str(out1), secret_key=SECRET_KEY, public_key=pub)
    record("AUD-POS-01", ct, "positive", "Short message (learning objective), LSB=2", r1["verdict"], "Authentic")

    # --- Positive 2: large message, LSB=5, plus sender(A) -> receiver(B). ---
    out2 = PROTECTED / "audio_case_positive_large_lsb5.wav"
    audio_stego.embed_audio(str(src), str(out2), secret_key=SECRET_KEY, private_key=priv,
                            message=LARGE_MESSAGE, lsb_depth=5, media_id="aud-pos-large", team_id=TEAM_ID)
    received_copy = RECEIVED / out2.name
    shutil.copyfile(out2, received_copy)
    r2 = audio_stego.extract_and_verify_audio(str(received_copy), secret_key=SECRET_KEY, public_key=pub)
    record("AUD-POS-02", ct, "positive-send-receive",
           "Large message (project overview), LSB=5, sent A->B then verified by B", r2["verdict"], "Authentic")

    # --- Positive 3: custom message, LSB=8. ---
    out3 = PROTECTED / "audio_case_positive_custom_lsb8.wav"
    audio_stego.embed_audio(str(src), str(out3), secret_key=SECRET_KEY, private_key=priv,
                            message=CUSTOM_MESSAGE, lsb_depth=8, media_id="aud-pos-custom", team_id=TEAM_ID)
    r3 = audio_stego.extract_and_verify_audio(str(out3), secret_key=SECRET_KEY, public_key=pub)
    record("AUD-POS-03", ct, "positive", "Custom confidential payload, LSB=8", r3["verdict"], "Authentic")

    # --- Negative 1: Tampered samples. ---
    tampered1 = TAMPERED / "audio_case_tampered.wav"
    tamper_audio_tail(out1, tampered1)
    r4 = audio_stego.extract_and_verify_audio(str(tampered1), secret_key=SECRET_KEY, public_key=pub)
    record("AUD-NEG-01", ct, "negative", "Cover samples tampered after signing", r4["verdict"], "Tampered")

    # --- Negative 2: wrong shared secret key. ---
    r5 = audio_stego.extract_and_verify_audio(str(out1), secret_key=WRONG_KEY, public_key=pub)
    record("AUD-NEG-02", ct, "negative", "Verifier supplies the wrong shared secret key", r5["verdict"], "Cannot Verify")

    # --- Negative 3: untrusted signer. ---
    out_wrongsig = PROTECTED / "audio_case_wrong_signature.wav"
    audio_stego.embed_audio(str(src), str(out_wrongsig), secret_key=SECRET_KEY, private_key=other_priv,
                            message=SHORT_MESSAGE, lsb_depth=2, media_id="aud-wrongsig", team_id=TEAM_ID)
    r6 = audio_stego.extract_and_verify_audio(str(out_wrongsig), secret_key=SECRET_KEY, public_key=pub)
    record("AUD-NEG-03", ct, "negative", "File signed with an untrusted private key", r6["verdict"], "Signature Invalid")

    # --- Negative 4: unprotected cover -> Payload Missing. ---
    r7 = audio_stego.extract_and_verify_audio(str(src), secret_key=SECRET_KEY, public_key=pub)
    record("AUD-NEG-04", ct, "negative", "Original cover object with no embedded payload", r7["verdict"], "Payload Missing")

    # --- Negative 5: engineered out-of-range start offset (parity with image). ---
    out_wrongloc = PROTECTED / "audio_case_wrong_start_location.wav"
    craft_wrong_start_location_audio(out1, out_wrongloc, SECRET_KEY)
    r8 = audio_stego.extract_and_verify_audio(str(out_wrongloc), secret_key=SECRET_KEY, public_key=pub)
    record("AUD-NEG-05", ct, "negative", "Header engineered to advertise an out-of-range start offset",
           r8["verdict"], "Wrong Start Location")

    # --- Selectable LSB depth matrix (representative subset for audio). ---
    for depth in (1, 3, 6, 8):
        out_d = PROTECTED / f"audio_case_lsb_depth_{depth}.wav"
        audio_stego.embed_audio(str(src), str(out_d), secret_key=SECRET_KEY, private_key=priv,
                                message=f"LSB depth demo = {depth}", lsb_depth=depth,
                                media_id=f"aud-lsb-{depth}", team_id=TEAM_ID)
        rd = audio_stego.extract_and_verify_audio(str(out_d), secret_key=SECRET_KEY, public_key=pub)
        record(f"AUD-LSB-{depth}", ct, "lsb-matrix", f"Selectable LSB depth = {depth}", rd["verdict"], "Authentic")


def write_report():
    """Write the Markdown + JSON evidence files and print a summary line."""
    total = len(results)
    passed = sum(1 for r in results if r["pass"])

    EVIDENCE.joinpath("demo_report.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

    lines = [
        "# INF2005 ACW1 -- Demo Test Evidence Report",
        "",
        f"Total cases: {total}  |  Passed: {passed}  |  Failed: {total - passed}",
        "",
        "| Case ID | Cover | Category | Description | Verdict | Expected | Result |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(
            f"| {r['case_id']} | {r['cover_type']} | {r['category']} | {r['description']} "
            f"| {r['verdict']} | {r['expected']} | {'PASS' if r['pass'] else 'FAIL'} |"
        )
    EVIDENCE.joinpath("demo_report.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"\nWrote {EVIDENCE / 'demo_report.md'} and demo_report.json")
    print(f"TOTAL: {passed}/{total} cases matched expected verdict")


if __name__ == "__main__":
    setup_dirs()
    run_image_cases()
    run_audio_cases()
    write_report()
