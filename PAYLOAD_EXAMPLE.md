# Payload Example: security design of a protected file

Real values extracted from `samples/protected/image_case_positive_short_lsb1.png`
(short Learning Outcome message, LSB depth 1, verdict **Authentic**).
Produced by reading the file back with the project's own `format_spec`, `bitops` and `crypto_utils` code. Nothing below is invented.

**The chain:**

```
Payload JSON (canonical, RSA-PSS signed)
  → capsule  payload_len | payload | sig_len | signature   at a secret offset (1–8 LSBs)
  → 33 B HMAC-tagged locator header at unit 16, carrying the encrypted, key-derived offset
    (offset = salted HMAC mod usable range)
```

Where the two hidden regions sit in the cover:

```
 pixel-byte units:  0 ... 15 | 16 ................ 279 | ... | 409,504 ............ 414,991 | ... 921,599
                    untouched | LOCATOR HEADER (33 B)  |     | PAYLOAD CAPSULE (686 B)      |
                              | fixed spot, 1 LSB      |     | secret offset, 1–8 LSBs      |
```

---

## 1. Payload JSON (canonical, RSA-PSS signed)

This is the object that gets **signed**. It is pretty-printed here so it's easier to read:

```json
{
  "cover_hash": "d9e04db94bd0df040640cad15c24fc8d9a22db340834559e08b1d720a7f957fa",
  "cover_type": "image",
  "lsb_depth": 1,
  "media_id": "img-pos-short",
  "message": "Use digital signatures to verify that a payload or file record was issued by a legitimate signer and has not been altered.",
  "metadata": {
    "team_id": "P6-6",
    "tool": "INF2005-ACW1-StegoVerify"
  },
  "nonce": "5fbcb286c31c463c9b62ad0a6d2c9e64",
  "timestamp": "2026-09-08T13:09:28Z"
}
```

| Field | Example value | Purpose |
|---|---|---|
| `media_id` | `img-pos-short` | Which media this record belongs to |
| `cover_type` | `image` | `image` or `audio` |
| `timestamp` | `2026-09-08T13:09:28Z` | UTC time of protection |
| `nonce` | `5fbcb286…9e64` (128-bit random) | Makes every payload unique, even with identical settings |
| `cover_hash` | `d9e04db9…f957fa` (SHA-256) | Hash of the cover **with the header + capsule regions blanked to 0x00**. Detects edits to the visible pixels |
| `lsb_depth` | `1` | LSBs per unit used for the capsule |
| `message` | the Learning Outcome text | The confidential message |
| `metadata` | team id + tool name | Provenance |

**Canonical form.** What is actually embedded has sorted keys, no whitespace and UTF-8 encoding, so the signer and the verifier hash byte-identical input (`payload.serialize_payload`). It is 420 bytes:

```
{"cover_hash":"d9e04db94bd0df040640cad15c24fc8d9a22db340834559e08b1d720a7f957fa","cover_type":"image","lsb_depth":1,"media_id":"img-pos-short","message":"Use digital signatures to verify that a payload or file record was issued by a legitimate signer and has not been altered.","metadata":{"team_id":"P6-6","tool":"INF2005-ACW1-StegoVerify"},"nonce":"5fbcb286c31c463c9b62ad0a6d2c9e64","timestamp":"2026-09-08T13:09:28Z"}
```

**Signing.**
- SHA-256 of those 420 bytes: `066808fdfacfa79627680479acd99d3d2595793e6b2bb2d46775d468db876f4b`
- That digest is signed with the team's **RSA-2048 private key using PSS padding**, which gives a 256-byte signature.

---

## 2. Capsule: `payload_len | payload | sig_len | signature` at a secret offset (1–8 LSBs)

`format_spec.pack_capsule` wraps the payload and signature into one block of **686 bytes**:

| Bytes | Field | Value in this file |
|---|---|---|
| 4 | Magic | `50 4C 44 31` = `"PLD1"` |
| 4 | `payload_len` (big-endian) | `00 00 01 A4` = **420** |
| 420 | `payload` (canonical JSON above) | `7B 22 63 6F …` = `{"co…` |
| 2 | `sig_len` (big-endian) | `01 00` = **256** |
| 256 | `signature` (RSA-PSS) | `14df3c09 3aa8e311 b82742a3 … 72f5ef96 9e` |

4 + 4 + 420 + 2 + 256 = **686 bytes**. The capsule is written with the user-selected LSB depth (1 here), so it covers 686 × 8 / 1 = **5,488 pixel bytes**, starting at the secret unit **409,504**.

Full signature (hex):

```
14df3c093aa8e311b82742a3cabc2bbec65bf095f6d7dc8dbbd93a130d0027a7
ddd2b94ad758a236de58acd5cb4945e74889cc6db890a3ab801a91d6e85a0d39
e996defda82995be5990f667fe5d0304b5c4ca6fcb339740fbf90ed846ef0229
67270e855e811b54ccf2901e3a61ac419850ec99fe993a0378d9d22490dc5b45
feb77a7a90e95aa7df69da9dcc773bbb90dbdab911a3115e61a26e6b7be572fe
bbb8653e6352c697fbe1d5352d3b563fcf7d24e6e6fb90862db133b2de148eeb
ae30920236f3c598f336cbab754a9c61c786b2ee1e71623e4cf819bc9a8baf5e
cade03e513fd7dff6ff09bcb88b2537aeab9d8f7ae08a847412d5a72f5ef969e
```

---

## 3. Locator header: 33 B, HMAC-tagged, at unit 16

The header tells the decoder where the capsule is. It is always written at unit 16 (never the top-left pixel) and always at 1 LSB, so it can be read before the capsule's LSB depth is known. Raw bytes read from the file:

```
53 56 48 31 | 01 | 6a 0c ee 54 7b 77 9b ad | be 3d 30 44 9a 54 e3 de | 00 00 02 ae | 16 97 02 d2 8b a4 85 b9
   magic      lsb          salt                  encrypted offset          capsule len       HMAC tag
```

| Bytes | Field | Value | Meaning |
|---|---|---|---|
| 4 | Magic | `SVH1` | "This file was protected by our tool". If it is absent the verdict is **Payload Missing** |
| 1 | LSB depth | `01` | The capsule uses 1 LSB |
| 8 | Salt | `6a0cee547b779bad` | Fresh random value for each file, so the offset changes every time |
| 8 | Encrypted offset | `be3d30449a54e3de` | The real offset XORed with an HMAC keystream. Unreadable without the secret |
| 4 | Capsule length | `00 00 02 AE` = 686 | How many bytes to read at the offset |
| 8 | HMAC tag | `169702d28ba485b9` | Authenticates lsb‖salt‖enc_offset‖len. A wrong key or an edited header gives **Cannot Verify** |

### Key-derived start offset (salted HMAC mod usable range)

`crypto_utils.derive_start_offset` and `encrypt_offset`:

```
usable range = [280, len(carrier) − units_needed + 1)       # after the header, and the whole capsule still fits
offset       = 280 + HMAC-SHA256(secret_key, salt ‖ "OFFSET") mod span
enc_offset   = offset XOR HMAC-SHA256(secret_key, salt ‖ "ENC")[:8]
```

- **Chosen by:** the shared secret plus a fresh salt for each file. The same cover protected twice lands at different offsets.
- **Found by:** the decoder reads the header, checks the HMAC tag, and then decrypts the offset. With the demo secret `team-shared-secret-demo-key`, `be3d30449a54e3de` decrypts to **409,504**, which is where the capsule above begins.
- **Secured by:** the offset is only stored encrypted, and the tag stops anyone from changing the header. A decrypted offset outside the usable range gives **Wrong Start Location**.
- **Limit:** the magic, LSB depth and capsule length are stored in the clear, and the capsule starts with `PLD1`. Someone who knows the format could still scan the cover to find it. Hiding the location beats the "check the corner" attack, and the RSA signature is what actually guarantees authenticity.

---

Audio uses the same design. The only differences are that a "unit" is the low byte of each 16-bit WAV sample instead of a pixel channel byte, and `cover_type` is `"audio"`.
