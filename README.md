# INF2005 ACW1 -- Steganographic Image and Audio Integrity Verification with Digital Signature-Based Authentication

Team: **P6-6**

A GUI-based (Tkinter) tool that protects PNG images and WAV/PCM audio files by hiding
a signed verification payload inside them (LSB replacement steganography), and
later verifies whether a given file is authentic, tampered, or otherwise invalid.

---

## 1. Quick start

```bash
# 1. Install dependencies (Python 3.10+)
pip install -r requirements.txt

# 2. Generate the demo RSA key pair (keys/private_key.pem, keys/public_key.pem)
python scripts/generate_keys.py

# 3. Generate the original sample cover files (image + audio)
python scripts/generate_samples.py

# 4. Launch the GUI
python src/gui_app.py

# 5. (optional) Regenerate ALL required positive/negative test evidence in one go
python scripts/run_demo_cases.py
```

`scripts/run_demo_cases.py` writes every stego/tampered file used as evidence into
`samples/protected/`, `samples/tampered/` and `samples/protected/received/`, and
writes a full pass/fail report to `test_evidence/demo_report.md` (and `.json`).
On the reference machine it produces **30/30 PASS** across every required
verdict category, for both the image and the audio workflow.

A quick internal sanity check (not the graded evidence) is also available:
`python scripts/smoke_test.py`.

---

## 2. Project layout

```
ACW1/
  src/
    crypto_utils.py     # SHA-256 hashing, RSA-PSS signing/verification, keyed start-location crypto
    bitops.py            # generic N-bit (1-8) LSB replacement embed/extract over a byte array
    format_spec.py        # binary layouts: locator header + payload/signature capsule
    payload.py             # verification payload construction (media ID, timestamp, hash, nonce, metadata)
    stego_engine.py          # cover-agnostic embed / extract / verify workflow + verdict logic (FR3-FR10)
    image_stego.py            # PNG <-> carrier byte array adapter (Pillow)
    audio_stego.py             # WAV/PCM <-> carrier byte array adapter (wave module)
    gui_app.py                  # Tkinter GUI (Image tab + Audio tab)
  scripts/
    generate_keys.py     # one-time RSA key pair generation
    generate_samples.py  # generates samples/originals/sample_image.png & sample_audio.wav
    run_demo_cases.py    # generates ALL required positive/negative test evidence + report
    smoke_test.py         # quick internal round-trip sanity check (dev tool, not graded evidence)
  keys/
    private_key.pem      # demo-only signing key -- NOT for submission (see note below)
    public_key.pem        # safe to submit / distribute
  samples/
    originals/           # original, unprotected cover files
    protected/            # stego (protected) files produced by the tool
    protected/received/   # "party B" copies used in the send/receive demo case
    tampered/              # deliberately tampered copies used in negative cases
  test_evidence/
    demo_report.md        # human-readable pass/fail table for every demo case
    demo_report.json       # same, machine-readable
  requirements.txt
  README.md (this file)
```

---

## 3. Security design

### 3.1 Verification payload (FR3)

A compact JSON payload is created for every protected file:

```json
{
  "media_id": "sample_image-image",
  "cover_type": "image",
  "timestamp": "2026-09-08T03:40:13Z",
  "nonce": "0e028a479475435c810a0083adef12c2",
  "cover_hash": "<sha256 hex of the cover object's non-stego-bearing content>",
  "lsb_depth": 2,
  "message": "<the confidentiality/integrity-protected message>",
  "metadata": { "team_id": "P6-6", "tool": "INF2005-ACW1-StegoVerify" }
}
```

The payload is serialised as canonical JSON (sorted keys, no whitespace) so the
signer and verifier always hash/sign byte-identical data.

### 3.2 Digital signature (FR4)

* Algorithm: **RSA-2048 with PSS padding over SHA-256** (`cryptography` library).
* The SHA-256 digest of the serialised payload is signed with the team's
  **private key**; the **public key** is used to verify it.
* The signature (256 bytes for a 2048-bit key) travels alongside the payload
  inside the hidden "capsule" (see 3.4) -- it is never stored separately, so a
  stego file is fully self-contained and verifiable offline.

### 3.3 Hashing / integrity (FR9)

Two independent hashes protect two different things:

1. **Signature over the payload** protects the payload/signature capsule
   itself -- any single-bit change to the hidden data invalidates the
   signature (`Signature Invalid` / `Tampered`, depending on where the
   corruption is caught).
2. **`cover_hash` field inside the payload** is the SHA-256 hash of the cover
   object **with the locator-header region and the capsule region blanked
   out** (`payload.stable_cover_hash`). Because both the encoder (at embed
   time) and the verifier (at extract time, once it knows exactly which
   bytes carry the header/capsule) compute this identically, any change to
   the *visible/audible* part of the file -- e.g. an attacker repainting a
   region of the image or splicing part of the audio -- is caught as
   `Tampered`, even though the hidden payload and its signature are
   themselves untouched.

### 3.4 Embedding format (FR5 / FR6)

Every carrier byte (one PNG pixel-channel byte, or the low byte of one
16-bit PCM audio sample) is one "unit". LSB replacement is used throughout
(`bitops.embed_bits` / `extract_bits`), with a **user-selectable number of
LSBs from 1 to 8** for the hidden payload region.

Two regions are embedded:

| Region | Location | LSBs used | Contents |
|---|---|---|---|
| Locator header | fixed public margin, unit 16 (never unit 0 / top-left) | always 1 (max reliability) | magic, chosen LSB depth, random salt, **encrypted** payload offset, capsule length, HMAC tag |
| Payload capsule | **secret, key-derived offset** (see 3.5) | user-selected (1-8) | `MAGIC2 \| payload_len \| payload JSON \| sig_len \| signature` |

### 3.5 Start-location design and security (FR7 -- Learning Outcome 6)

The mandatory requirement is that the payload can start anywhere other than
the top-left corner, and that the team explain how the location is chosen,
how the decoder recovers it, and how it is protected against guessing.

**Design (also the team's declared innovation -- optional challenge
"Advanced start-location security", FR13):**

1. At embed time, a random 8-byte **salt** is generated.
2. The real start offset is derived as
   `offset = HMAC-SHA256(secret_key, salt || "OFFSET") mod usable_range`,
   where `secret_key` is a **pre-shared secret** known only to the
   sender and the authorised verifier (analogous to a symmetric key in a
   real deployment) -- never stored in the file.
3. The offset is then **encrypted** (XOR'd) with a second, independent
   HMAC-SHA256 keystream derived from `secret_key` and `salt`, before being
   written into the locator header. So even though the salt is public, an
   attacker who does not know `secret_key` sees only random-looking bytes
   and cannot recover the true offset.
4. The whole header (magic, LSB depth, salt, encrypted offset, capsule
   length) is protected by an 8-byte **HMAC tag**, also keyed on
   `secret_key`. Any tampering with the header, or an incorrect
   `secret_key` at verification time, is detected immediately
   (`Cannot Verify`) *before* the tool even attempts to read the capsule
   region -- so a wrong guess never silently reads garbage.
5. The verifier, who knows `secret_key`, reads the small fixed-position
   header, checks the HMAC tag, decrypts the offset, and jumps straight to
   the correct location -- no brute-force search is needed by a legitimate
   party.

This is deliberately **not** a fixed offset and **not** a location that can
be recovered from public metadata alone -- both are explicitly called out
as the "simplest fixed-location LSB demonstration" the assignment asks
teams to go beyond.

### 3.6 Verdicts (FR10)

`stego_engine.extract_and_verify` always returns exactly one of:

| Verdict | Meaning |
|---|---|
| `Authentic` | header + signature + cover hash all check out |
| `Tampered` | header/signature OK, but the cover object's content (outside the hidden region) or the capsule bytes themselves were altered after signing |
| `Signature Invalid` | payload extracted correctly but the signature does not verify against the team's public key (wrong/untrusted signer, or payload bytes changed) |
| `Payload Missing` | no valid locator header found (e.g. verifying an unprotected original file) |
| `Wrong Start Location` | the (key-authenticated) header decrypts to an offset outside the cover object's valid range |
| `Cannot Verify` | the locator header's HMAC tag does not match -- wrong secret key supplied, or the header itself was corrupted |

See `test_evidence/demo_report.md` for one worked example of every verdict
across both image and audio.

---

## 4. Positive and negative test cases (FR11)

Generated automatically by `scripts/run_demo_cases.py` (30 cases total,
30/30 passing on the reference run):

* **Capacity check** (image + audio): a deliberately oversized message is
  rejected with a clear `CapacityError` *before* any data is written,
  demonstrating the mandatory "is payload size larger than cover object
  size?" check.
* **Positive cases** (>=1 per cover object, 3 each in practice): short
  message (one of the Learning Outcomes), large message (the Project
  Overview paragraph), and a team-defined custom confidential payload --
  each at a different selected LSB depth.
* **Sender -> receiver simulation**: the large-message stego file is copied
  into `samples/protected/received/` (simulating "party A emails the file,
  party B downloads it to their folder") and verified from that copy,
  demonstrating end-to-end integrity/signature verification independent of
  the original embedding session.
* **Negative cases** (>=1 per cover object, 5 each in practice): tampered
  cover content, wrong shared secret key, an untrusted signer's private
  key, a plain unprotected file, and an engineered out-of-range start
  offset -- so every one of the six verdict categories is demonstrated on
  both the image and the audio cover object.
* **Selectable LSB matrix**: every LSB depth from 1 to 8 is exercised on the
  image workflow (and a representative subset on audio), each round-tripping
  to `Authentic`.

---

## 5. Innovation (FR13)

**Keyed, encrypted, HMAC-authenticated start-location derivation** (Section
3.5) is the team's declared innovation, corresponding to the optional
challenge "Advanced start-location security". Compared to the simplest
fixed-location LSB baseline:

* *Useful*: defeats the standard StegExpose-style attack of always checking
  the first N bytes/samples of a file for hidden data.
* *Meaningful*: ties the hidden data's location cryptographically to a
  secret shared between the legitimate sender and receiver, rather than to
  something derivable from the file alone (e.g. its hash, name, or size).
* *Practical*: costs only 33 extra bytes of header overhead and a few HMAC
  computations; no impact on payload capacity beyond that fixed overhead.

**Limitation, honestly stated**: this is a *shared-secret* (symmetric)
scheme layered on top of an asymmetric signature scheme -- if `secret_key`
leaks, an attacker can locate (though still not forge, thanks to the RSA
signature) the payload. A production system would instead derive the
location from an asymmetric key-agreement step or encrypt the offset under
the recipient's public key.

---

## 6. Known limitations (Learning Outcome 8 / Rubric item 7)

* **PNG re-save is required** for the image workflow (Pillow decodes to raw
  pixels and re-encodes losslessly) -- JPEG is not supported because its
  lossy DCT compression would destroy LSB-embedded data; this is why the
  spec's PNG basic-version option was used.
* **Only 8-bit/16-bit PCM WAV** is supported for audio; compressed formats
  (MP3, ADPCM) are not, because lossy compression or non-PCM encoding would
  corrupt LSB data the same way JPEG would for images.
  16-bit PCM only touches the low byte of each sample so the embedding stays
  at moderate LSB depths (audibly transparent up to 3-4 LSBs; higher depths
  are provided for demonstrating the full 1-8 range but are more audible).
* **The shared secret key is symmetric and must be pre-distributed** between
  sender and verifier out-of-band (e.g. shown once during the demo) -- this
  project does not implement a full key-exchange protocol.
  See the innovation section's stated limitation above.
  It is not a private key; the RSA private key (`keys/private_key.pem`) is
  what is used for the actual digital signature.
* **Video is not implemented** (optional challenge, not attempted).
* **Steganalysis / robustness under compression or resampling** are not
  implemented (LSB replacement is fragile to any lossy transform by
  design -- this is a known, inherent limitation of the technique, not a
  bug in this implementation).
* Capacity/offset arithmetic assumes the cover object is large enough to
  hold the fixed 33-byte header; extremely small cover files will correctly
  fail the capacity check rather than silently truncate data.

---

## 7. Keys and reproducing signature verification

* `keys/public_key.pem` -- safe to submit / share; used by `verify_signature`.
* `keys/private_key.pem` -- generated **only** for this assignment demo by
  `scripts/generate_keys.py`. Per the assignment instructions, **do not
  submit this file** unless your team has confirmed it was generated solely
  for the demo and will not be reused anywhere else.
* `keys/other_team_private_key.pem` / `other_team_public_key.pem` -- a
  second, "untrusted" key pair generated purely to produce the
  `Signature Invalid` negative test case (an attacker/other party's key
  signing a payload that is then checked against *your* public key).

To reproduce verification independently: load `public_key.pem` with
`crypto_utils.load_public_key(...)` and call
`image_stego.extract_and_verify_image(path, secret_key=..., public_key=...)`
(or the audio equivalent) with the shared secret key used at embed time.

---

## 8. Team number

The team number is **P6-6**. In code it is defined once, in
`src/payload.py` as `TEAM_ID_DEFAULT`; the GUI and the demo scripts import
that value, so there is a single place to change it if the team number ever
changes. The GUI's "Team ID" field is still editable per run.

The declaration of originality and demo plan documents (separate
team-authored submissions) must also carry `P6-6`.

---

## 9. AI-use disclosure

Generative AI (Claude, Anthropic) was used as a supplement during
development to help scaffold the cryptography/steganography modules and
this README, following the assignment's stated generative-AI guidelines.
All generated code was reviewed, run, and verified against the assignment
spec's functional requirements (see `test_evidence/demo_report.md`) by the
team before submission. *Fill in your team's specific account of what was
generated vs. hand-written/reviewed for the Declaration of Originality.*
