# Payload Example: what we hide inside a protected file

Every value on this page comes from a real protected image, `samples/protected/image_case_positive_short_lsb1.png`. It holds a short message, uses 1 LSB, and verifies as **Authentic**. We read the values back out of the file with our own code. Nothing is made up.

**The chain:**

```
Payload JSON (canonical, RSA-PSS signed)
  → capsule  payload_len | payload | sig_len | signature   at a secret offset (1–8 LSBs)
  → 33 B HMAC-tagged locator header at unit 16, carrying the encrypted, key-derived offset
    (offset = salted HMAC mod usable range)
```

In plain words:
1. We write a small **record** about the file and **sign** it, so nobody can fake it.
2. We pack the record and signature into a **capsule** and hide it at a **secret spot** in the file.
3. We leave a small **signpost** (the header) near the start. It says where the capsule is, but only someone with the key can read the location.

Where things sit in the image (a "unit" is one colour byte of one pixel):

```
 units:  0 ... 15 | 16 ................ 279 | ... | 409,504 ............ 414,991 | ... 921,599
         untouched | SIGNPOST (header, 33 B) |     | CAPSULE (686 B)              |
                   | always here, 1 LSB      |     | secret spot, 1–8 LSBs        |
```

---

## 1. Payload JSON: the signed record

This is the record we hide. It describes the file and carries the message:

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

| Field | What it's for |
|---|---|
| `media_id` | A name for this file |
| `cover_type` | Whether it's an image or audio |
| `timestamp` | When we protected it |
| `nonce` | A random number, so no two records are ever the same |
| `cover_hash` | A fingerprint of the picture itself. If anyone edits the picture, the fingerprint won't match any more |
| `lsb_depth` | How many bits per unit the capsule uses (1 here) |
| `message` | The secret message |
| `metadata` | Our team ID and tool name |

The fingerprint (`cover_hash`) is taken with our hidden areas blanked out first. That's because hiding the data changes those areas, and we don't want that change to count as tampering.

**Canonical form.** Before signing, we write the record the same way every time: keys in alphabetical order and no spaces. It comes to 420 bytes. This matters because the signature only checks out if the sender and the checker hash exactly the same bytes.

```
{"cover_hash":"d9e04db94bd0df040640cad15c24fc8d9a22db340834559e08b1d720a7f957fa","cover_type":"image","lsb_depth":1,"media_id":"img-pos-short","message":"Use digital signatures to verify that a payload or file record was issued by a legitimate signer and has not been altered.","metadata":{"team_id":"P6-6","tool":"INF2005-ACW1-StegoVerify"},"nonce":"5fbcb286c31c463c9b62ad0a6d2c9e64","timestamp":"2026-09-08T13:09:28Z"}
```

**Signing.**
- We hash those 420 bytes with SHA-256 and get `066808fdfacfa79627680479acd99d3d2595793e6b2bb2d46775d468db876f4b`.
- We sign that hash with our **private key** (RSA-2048, PSS), which gives a 256-byte signature. Anyone with our public key can check it, but only we can create it.

---

## 2. Capsule: the package hidden at the secret spot

The record and its signature are packed together into one 686-byte block:

| Bytes | Part | Value in this file |
|---|---|---|
| 4 | Marker | `PLD1` ("this is a capsule") |
| 4 | `payload_len` | **420**, the size of the record |
| 420 | `payload` | the record above |
| 2 | `sig_len` | **256**, the size of the signature |
| 256 | `signature` | `14df3c09 3aa8e311 b82742a3 … 72f5ef96 9e` |

4 + 4 + 420 + 2 + 256 = **686 bytes**.

The user picks how many of the lowest bits (1 to 8) in each unit to overwrite. Using more bits fits more data but changes the picture more. Here we use 1 bit per unit, so the 686 bytes (5,488 bits) take up **5,488 units**, starting at the secret spot, unit **409,504**.

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

## 3. Locator header: the signpost at unit 16

The checker needs to know where the capsule is. The header tells it. The header is always in the same place (unit 16, not the very first pixel) and always uses 1 bit per unit, so the checker can read it before it knows anything else.

Raw bytes from the file:

```
53 56 48 31 |  01  | 6a 0c ee 54 7b 77 9b ad | be 3d 30 44 9a 54 e3 de |   00 00 02 ae   | 16 97 02 d2 8b a4 85 b9
   magic      lsb          salt                  encrypted offset          capsule len            HMAC tag
```

| Bytes | Part | Value | What it means |
|---|---|---|---|
| 4 | Magic | `SVH1` | "Our tool protected this file." If it's missing, the verdict is **Payload Missing** |
| 1 | LSB depth | `1` | The capsule uses 1 bit per unit |
| 8 | Salt | `6a0cee547b779bad` | A random value, new for every file |
| 8 | Encrypted offset | `be3d30449a54e3de` | Where the capsule is, scrambled so only the key holder can read it |
| 4 | Capsule length | 686 | How many bytes to read |
| 8 | HMAC tag | `169702d28ba485b9` | A seal made with the key. A wrong key or any change to the header breaks it, and the verdict is **Cannot Verify** |

### Key-derived start offset: how the secret spot is picked

```
usable range = [280, len(carrier) − units_needed + 1)       # after the header, and the whole capsule still fits
offset       = 280 + HMAC-SHA256(secret_key, salt ‖ "OFFSET") mod span
enc_offset   = offset XOR HMAC-SHA256(secret_key, salt ‖ "ENC")[:8]
```

In plain words: we mix our secret key with the salt to get a big number, and cut it down to fit the space available. That gives the spot. Then we mix the key and salt a second way to scramble the spot before writing it into the header.

- **Chosen by:** our shared secret key plus a random salt. Because the salt is new each time, protecting the same picture twice puts the capsule in two different places.
- **Found by:** the checker reads the header, checks the seal, and unscrambles the spot with the same key. With our demo key `team-shared-secret-demo-key`, `be3d30449a54e3de` unscrambles to **409,504**, exactly where the capsule starts.
- **Secured by:** the spot is never written in plain form, and the seal stops anyone from changing the header. If the unscrambled spot falls outside the allowed range, the verdict is **Wrong Start Location**.
- **Limit:** some header fields are readable, and every capsule starts with `PLD1`. Someone who knows our format could still search the whole file for it. So the secret spot stops "just look in the corner", but it isn't what proves the file is genuine. The signature does that.

---

Audio works exactly the same way. The only difference is that a "unit" is the low byte of each sound sample instead of a colour byte of a pixel, and `cover_type` is `"audio"`.
