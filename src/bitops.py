"""
bitops.py
---------
The lowest layer of the tool: raw LSB-replacement bit packing.

Both the image and the audio engines first reduce their file to a flat,
mutable list of bytes we call the **carrier**:
    * image  -> every raw pixel-channel byte (R, G, B[, A]) in reading order
    * audio  -> the low byte of every 16-bit PCM sample (or every byte for
                8-bit PCM)

Each carrier byte is one **unit**.  "LSB replacement with N bits" means:
for each unit, throw away its lowest N bits and write N bits of our hidden
data in their place.  N (`bits_per_unit`) is user-selectable from 1 to 8
(FR5 / FR6, "selectable LSBs from bits 1 to 8").

This module only moves bits around; it knows nothing about payloads,
signatures or file formats.
"""

from __future__ import annotations


def bytes_to_bitstring(data: bytes) -> str:
    """Turn bytes into a string of '0'/'1' characters, 8 bits per byte,
    most-significant bit first.  e.g. b'\\x01' -> '00000001'.
    Working with a text string keeps the bit-slicing code below easy to read.
    """
    return "".join(f"{byte:08b}" for byte in data)


def bitstring_to_bytes(bits: str) -> bytes:
    """Inverse of `bytes_to_bitstring`.

    Only whole groups of 8 bits become bytes; any leftover trailing bits
    (which can only be padding we added during embedding) are dropped.
    """
    n = len(bits) - (len(bits) % 8)  # largest multiple of 8 <= len(bits)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, n, 8))


def required_units(num_bytes: int, bits_per_unit: int) -> int:
    """How many carrier units are needed to store `num_bytes` of data
    when each unit carries `bits_per_unit` bits.

    total_bits / bits_per_unit, always rounded UP so the last partial unit
    still counts.  `-(-a // b)` is the standard integer ceil-division trick.
    """
    total_bits = num_bytes * 8
    return -(-total_bits // bits_per_unit)


def embed_bits(carrier: bytearray, start_unit: int, bits_per_unit: int, data: bytes) -> None:
    """Write `data` into `carrier` in place, `bits_per_unit` LSBs at a time,
    starting at unit index `start_unit`.

    Steps:
      1. Validate the LSB count.
      2. Flatten `data` to a bit-string and work out how many units it needs.
      3. Bounds-check against the carrier length.
      4. Build a mask that clears the low `bits_per_unit` bits of a byte.
      5. Walk the units: for each one take the next `bits_per_unit` bits,
         clear the byte's low bits, OR the new bits in.
    """
    # 1. Only 1..8 bits per unit make sense for a single byte.
    if not (1 <= bits_per_unit <= 8):
        raise ValueError("bits_per_unit must be between 1 and 8")

    # 2. Flatten the payload to bits and compute the unit span it occupies.
    bitstring = bytes_to_bitstring(data)
    units_needed = required_units(len(data), bits_per_unit)

    # 3. Refuse to run off the end of the carrier.
    if start_unit + units_needed > len(carrier):
        raise ValueError("Cover object does not have enough capacity for this payload")

    # 4. e.g. bits_per_unit=3 -> 0b11111000: keeps the top 5 bits, zeroes the low 3.
    mask_clear = (0xFF << bits_per_unit) & 0xFF

    # 5. Consume the bit-string `bits_per_unit` characters per carrier unit.
    pos = 0
    for i in range(units_needed):
        chunk = bitstring[pos: pos + bits_per_unit]
        pos += bits_per_unit
        # The very last chunk may be short; pad it with '0' so int() is happy.
        if len(chunk) < bits_per_unit:
            chunk = chunk.ljust(bits_per_unit, "0")
        value = int(chunk, 2)                       # the new low bits, as a number
        idx = start_unit + i
        carrier[idx] = (carrier[idx] & mask_clear) | value  # clear then set


def extract_bits(carrier: bytes, start_unit: int, bits_per_unit: int, num_bytes: int) -> bytes:
    """Read `num_bytes` of hidden data back out of `carrier`, mirroring
    `embed_bits` exactly.

    For each unit we keep only its low `bits_per_unit` bits, format them as
    a fixed-width binary string, concatenate everything, cut the result to
    the exact number of bits we asked for, then repack into bytes.
    """
    if not (1 <= bits_per_unit <= 8):
        raise ValueError("bits_per_unit must be between 1 and 8")

    units_needed = required_units(num_bytes, bits_per_unit)
    if start_unit + units_needed > len(carrier):
        raise ValueError("Cannot extract: requested range exceeds carrier capacity")

    # mask = low `bits_per_unit` bits set, e.g. bits_per_unit=3 -> 0b00000111.
    mask = (1 << bits_per_unit) - 1
    bits_chunks = []
    for i in range(units_needed):
        value = carrier[start_unit + i] & mask
        bits_chunks.append(format(value, f"0{bits_per_unit}b"))  # zero-padded to width

    # Drop the padding bits from the final unit, then rebuild the bytes.
    bitstring = "".join(bits_chunks)[: num_bytes * 8]
    return bitstring_to_bytes(bitstring)


def capacity_bytes(carrier_len: int, start_unit: int, bits_per_unit: int) -> int:
    """Largest number of payload bytes that fit from `start_unit` to the end
    of the carrier at `bits_per_unit` LSBs each.

    available_units * bits_per_unit gives total usable bits; // 8 converts
    to whole bytes (rounding down - a partial byte can't be trusted).
    """
    available_units = max(0, carrier_len - start_unit)
    return (available_units * bits_per_unit) // 8
