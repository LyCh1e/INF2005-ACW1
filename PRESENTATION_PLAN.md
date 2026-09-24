# INF2005 ACW1 — Demo Presentation Plan (Team P6-6)

**Total slot:** 25 min hard cap · **Planned content:** 22:30 · **Buffer / evaluator questions:** 2:30
**Team:** 6 members (M1–M6). Every member speaks and demos — zero marks for absence.
**Source:** ACW1 spec v5 (§5 Mandatory Scope, §7 Workflow, §11 Rubric — 40 marks).

> Member slots (M1–M6) are placeholders. Assign them to whoever **actually wrote** that part — Rubric 6 (5 marks) rewards each person explaining *their own* work and answering questions about it credibly.

---

## 1. Rubric → time map

| # | Criterion | Marks | Where it is shown | Time given |
|---|---|---|---|---|
| 1 | Security design & problem framing | 5 | Seg 2 (+ Seg 1) | 3:30 |
| 2 | Image embed / extract / cases | 9 | Seg 4, 5 | 6:30 |
| 3 | Audio embed / extract / cases | 10 | Seg 6, 7 | 7:00 |
| 4 | Hashing, signatures, failed verification | 5 | Seg 3 (+ negatives in Seg 5, 7) | 2:30 |
| 5 | Innovation | 4 | Seg 8 (mechanics in Seg 2, payoff in Seg 5, 7) | 1:30 |
| 6 | Individual technical explanation | 5 | **Every** segment ends with an "I built…" line | — |
| 7 | Limitations, ethics, AI-use | 2 | Seg 8 | 1:30 |

Time is weighted roughly to marks: image + audio are 19 of 40 marks, so ~13.5 of the 22:30 minutes are live demo.

---

## 2. Run of show (25:00)

| Time | Seg | Who | Topic | Rubric |
|---|---|---|---|---|
| 0:00 – 0:30 | 1 | M1 | Opening: scenario, what we built, order of demo, who shows what | 1 |
| 0:30 – 3:30 | 2 | M1 | Security design: payload, capsule layout, start-location design | 1, 5 |
| 3:30 – 6:00 | 3 | M2 | Hashing + RSA-PSS signature; verdict logic; first failed-signature case | 4 |
| 6:00 – 10:00 | 4 | M3 | **Image** — capacity check, encode, LSB selection, before/after, send A→B, decode | 2 |
| 10:00 – 12:30 | 5 | M4 | **Image negatives** — tampered, wrong key, no payload, wrong start location | 2, 4, 5 |
| 12:30 – 16:30 | 6 | M5 | **Audio** — capacity check, encode, LSB selection, play before/after, send A→B, decode | 3 |
| 16:30 – 19:30 | 7 | M4 | **Audio negatives** — same verdict cases on audio | 3, 4, 5 |
| 19:30 – 22:30 | 8 | M6 | Innovation evaluation, limitations, ethics, AI-use, close | 5, 7 |
| 22:30 – 25:00 | — | All | Buffer: overruns, live-demo hiccups, evaluator questions | 6 |

Each hand-off should be ≤10 s: the next presenter already has the right tab open.
Every presenter says a one-line ownership statement ("I wrote/tested X; the tricky part was Y") — that is the Rubric 6 evidence.

---

## 3. Segment scripts

### Seg 1 — Opening (M1, 0:30)
- One sentence on the scenario: protect an image and an audio file before release, verify later.
- One sentence on the approach: hash → signed payload → hidden by LSB replacement at a **secret, key-derived start location**.
- Announce the order: design → crypto → image → audio → innovation/limits.

### Seg 2 — Security design (M1, 3:00) · *Rubric 1*
Use **one slide** with the pipeline diagram; do not read the README.
1. **Payload** (FR3): show the JSON — `media_id`, `timestamp`, `nonce`, `cover_hash`, `lsb_depth`, `message`, `metadata`. Canonical JSON so signer and verifier hash identical bytes.
2. **Two regions in the cover** (README §3.4):
   - *Locator header* — small, at unit 16 (never the top-left), always 1 LSB: magic, LSB depth, salt, **encrypted** offset, capsule length, HMAC tag.
   - *Payload capsule* — at the secret offset, user-selected 1–8 LSBs: `payload_len | payload | sig_len | signature`.
3. **Start-location design** (FR7 / LO6) — answer the three questions the spec asks explicitly:
   - *How is it chosen?* `offset = HMAC(secret_key, salt‖"OFFSET") mod usable_range`; fresh random salt per file.
   - *How does the decoder find it?* Reads the header, checks the HMAC tag, decrypts the offset with a second HMAC keystream.
   - *How is it secured?* Guessing → attacker faces the whole cover capacity; wrong key → tag fails → `Cannot Verify` before any capsule read; header tampering → tag fails.
4. Ownership line.

### Seg 3 — Hashing, signatures, verdicts (M2, 2:30) · *Rubric 4*
- Two hashes, two jobs: (a) signature over the payload hash protects the hidden capsule; (b) `cover_hash` over the cover with header + capsule blanked out protects the visible/audible content.
- RSA-2048 / PSS / SHA-256; private key signs, public key verifies; signature travels inside the capsule.
- Show the six verdicts as a table (Authentic, Tampered, Signature Invalid, Payload Missing, Wrong Start Location, Cannot Verify) and which check triggers each — this is the "clear linkage between verification logic and outcomes" the rubric asks for.
- **Live:** verify `image_case_wrong_signature.png` → `Signature Invalid` (signed by the untrusted key pair). Explain: the payload decoded fine, but the signature did not verify against *our* public key.

### Seg 4 — Image workflow (M3, 4:00) · *Rubric 2*  (GUI: **Image** tab)
1. **Capacity check** — pick the cover, paste a deliberately oversized message → *Check capacity* → rejected (spec-mandated case; the report shows 114,574 B capacity vs a 119,574 B message at 1 LSB).
2. **Short payload** — a Learning Outcome as the message, **LSB = 1** → *Protect*. Point at the output: secret start offset, capsule size, payload JSON, before/after thumbnails.
3. **LSB selection** — invite the evaluator to pick an LSB depth (the Demo-plan template says the evaluator may decide) and re-protect. Say why higher depth = more capacity but more visible change.
4. **Large payload** — Project Overview paragraph, LSB 4. Then **A → B**: "A emails this file; B saves it to `samples/protected/received/`" → open that copy, *Verify* → `Authentic`, recovered message shown.
5. **Custom payload** — show the team-defined confidential payload (prepared LSB-8 file), `Authentic`.

### Seg 5 — Image negatives (M4, 2:30) · *Rubric 2, 4, 5*
Run in this order; each takes ~30 s:
1. *Tamper a protected file…* → Verify → **Tampered**.
2. Correct file, **wrong shared secret** → **Cannot Verify** (innovation payoff: the key gates the location).
3. Verify the **original** image → **Payload Missing**.
4. Prepared `image_case_wrong_start_location.png` → **Wrong Start Location** (header engineered to advertise an out-of-range offset — say plainly that this case is constructed).
5. Quick flash of the LSB 1–8 matrix from `test_evidence/demo_report.md` (all `Authentic`).

### Seg 6 — Audio workflow (M5, 4:00) · *Rubric 3*  (GUI: **Audio** tab)
Mirror Seg 4 so the evaluator can tick the same boxes:
1. Capacity check (audio: 26,936 B at 1 LSB vs a 31,936 B message → rejected).
2. Short payload, LSB 2 → Protect → **Play original, Play stego** (the spec requires the GUI to play/compare).
3. Evaluator-chosen LSB; be upfront that only the low byte of each 16-bit sample is touched, transparent up to ~3–4 LSBs, more audible above that.
4. Large payload LSB 5 → A → B via `received/` → Verify → `Authentic`.
5. Custom payload at LSB 8 (prepared), `Authentic`; play it so the audible degradation is demonstrated honestly.
6. One-line difference from image: the carrier unit is a sample's low byte, not a pixel channel; same engine, different adapter (`audio_stego.py` vs `image_stego.py`).

### Seg 7 — Audio negatives (M4, 3:00) · *Rubric 3, 4, 5*
Same verdicts on audio: **Tampered**, **Cannot Verify** (wrong key), **Payload Missing** (original WAV), **Wrong Start Location**, plus `audio_case_wrong_signature.wav` → **Signature Invalid**. State the cumulative count: all six verdicts have now been shown on both media (spec minimum: ≥2 positive, ≥3 negative overall, ≥1 of each per cover object).

### Seg 8 — Innovation, limitations, ethics, AI (M6, 3:00) · *Rubric 5, 7*
**Innovation (1:30)** — keyed, encrypted, HMAC-authenticated start location (optional challenge "Advanced start-location security"):
- *Baseline it improves on:* fixed/top-left LSB → trivially found by scanning the first N bytes.
- *Useful / meaningful / practical:* location bound to a shared secret, differs per file (salt), ~33 bytes overhead.
- *Remaining limitation (say it before they ask):* the secret is symmetric and pre-shared; if it leaks, the location is exposed (forgery is still blocked by RSA). The 33-byte header sits at a fixed public spot, so its *existence* is detectable by steganalysis even though its contents are not readable.

**Limitations, ethics, AI-use (1:30)** — Rubric 7 rewards honesty over polish:
- Technical: PNG/WAV-PCM only (JPEG/MP3 would destroy LSBs); LSB replacement is fragile to any lossy transform; no steganalysis, no robustness, no video; shared-secret distribution not solved.
- Responsible use: protecting one's own media vs. hiding data to evade inspection; demo-only keys.
- AI-use: Claude used to scaffold the crypto/stego modules and README; **state what the team reviewed, ran and verified** (30/30 cases in `demo_report.md`) — fill in the real account, consistent with the Declaration of Originality.
- Close with one sentence tying back to the scenario.

---

## 4. Text to paste into `Px-x_Demo-plan.docx`
(Replace *Px-x* with **P6-6**; add member names.)

| # | Demo name / description | Payload type | Cover object type | Remarks (member) |
|---|---|---|---|---|
| 1 | Image protect + verify (short msg, LSB 1; capacity check; evaluator-chosen LSB) | Input text (short) | Image: PNG | M3 |
| 2 | Image send A→B, large msg LSB 4, verify from received folder | Input text (large) | Image: PNG | M3 |
| 3 | Image custom confidential payload, LSB 8 | Input text (custom) | Image: PNG | M3 |
| 4 | Image negatives: Tampered / Cannot Verify / Payload Missing / Wrong Start Location / Signature Invalid | Input text | Image: PNG | M2, M4 |
| 5 | Audio protect + verify (short msg, LSB 2; capacity check; play before/after) | Input text (short) | Audio: WAV | M5 |
| 6 | Audio send A→B, large msg LSB 5, verify | Input text (large) | Audio: WAV | M5 |
| 7 | Audio custom payload LSB 8 | Input text (custom) | Audio: WAV | M5 |
| 8 | Audio negatives (same five verdicts) | Input text | Audio: WAV | M4 |
| 9 | Additional demo (innovation): keyed encrypted start location, wrong key rejected | Input text | Image + Audio | M1, M6 |

---

## 5. Suggested ownership (edit to match reality)

| Slot | Talks about | Code / artefact they should be able to defend |
|---|---|---|
| M1 | Design, payload, start-location | `format_spec.py`, `payload.py`, README §3 |
| M2 | Hashing, signature, verdicts | `crypto_utils.py`, verdict logic in `stego_engine.py` |
| M3 | Image | `image_stego.py`, `bitops.py`, GUI Image tab |
| M4 | Negative cases, tamper helper | `run_demo_cases.py`, tamper functions, `test_evidence/` |
| M5 | Audio | `audio_stego.py`, GUI Audio tab / playback |
| M6 | Innovation, limits, AI-use | Innovation section, README §5–6, 9, GUI overall |

---

## 6. Pre-demo checklist

**One day before the demo (spec p1, §9)**
- [ ] Upload the demo plan (§4 above) to xSite.
- [ ] Declaration of Originality signed by **all six**. The current `Px-x_DeclarationOfOriginality.docx` still has blank emails/student IDs for five members and an empty contribution-distribution section.
- [ ] Contribution/distribution statement (percentages sum to 100%) agreed by everyone.

**Environment (do a full dry-run on the demo machine)**
- [ ] `pip install -r requirements.txt`; keys and samples exist (`generate_keys.py`, `generate_samples.py`); `run_demo_cases.py` shows 30/30.
- [ ] GUI launches; audio **Play** works with the demo machine's speakers/volume.
- [ ] Pre-open: Image tab, Audio tab, `samples/protected/received/`, `test_evidence/demo_report.md`.
- [ ] Shared secret key noted (default `team-shared-secret-demo-key`) and a deliberately wrong one ready to type.
- [ ] Oversized message text ready to paste; three payload texts (short LO, Overview paragraph, custom) in one scratch file.
- [ ] Timed rehearsal at least twice; anyone over their slot cuts their own content, not another member's time.

**Fallbacks**
- Live GUI step fails → show the matching prepared file in `samples/` plus its row in `demo_report.md` (all 30 cases are reproducible) and keep moving.
- Running long → drop the LSB 1–8 matrix (Seg 5) and the custom-payload replay first; never cut a negative case or a member's slot.

---

## 7. Likely evaluator questions (Rubric 6 — everyone should be able to answer their own)

| Question | Short answer / owner |
|---|---|
| Why not just hide at a random offset? | The decoder needs to find it; we derive it from `HMAC(secret, salt)` so it is recoverable by the key holder and unpredictable to others (M1) |
| The header is at a fixed spot — isn't that a fixed location? | Yes, but it only holds an *encrypted* offset, HMAC-tagged; a known trade-off, and detectable by steganalysis (M1/M6) |
| Why sign the hash rather than the whole file? | The signed payload contains `cover_hash`; a constant-size signature fits the hidden capacity (M2) |
| Why RSA-PSS rather than PKCS#1 v1.5? | Randomised padding with a security proof; the standard recommendation (M2) |
| What does `cover_hash` cover, given embedding changes the cover? | The cover with header + capsule regions blanked, so embedding doesn't change the hash (M2/M1) |
| What if the attacker knows the public key? | They can verify but not forge; forging needs the private key (M2) |
| Why can't you use JPEG / MP3? | Lossy compression rewrites the low bits and destroys the payload (M3/M5) |
| Why is high-LSB audio audible? | Only the low byte of each 16-bit sample is used; at LSB 5–8 the changes are large relative to a quiet signal (M5) |
| What if the same valid file is re-sent later (replay)? | An authentic copy still verifies — **confirm against `stego_engine.py` whether the nonce is checked before answering** (M2) |
| How was AI used and how did you check it? | Scaffolding; code reviewed, run, and validated against the 30 cases (M6) |
