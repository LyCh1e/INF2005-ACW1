"""
bitops.py
---------
Low-level LSB-replacement bit packing/unpacking shared by the image and
audio steganography engines. Both engines reduce their cover object to a
flat, mutable "carrier" byte array (image: raw pixel channel bytes, audio:
the low byte of each 16-bit PCM sample) and use these helpers to embed or
extract an arbitrary number of least-significant bits (1-8) per carrier
byte.
"""

from __future__ import annotations


def bytes_to_bitstring(data: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in data)


def bitstring_to_bytes(bits: str) -> bytes:
    # pad to a whole number of bytes (trailing bits, if any, are dropped)
    n = len(bits) - (len(bits) % 8)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, n, 8))


def required_units(num_bytes: int, bits_per_unit: int) -> int:
    """How many carrier bytes are needed to hold `num_bytes` at `bits_per_unit` LSBs each."""
    total_bits = num_bytes * 8
    return -(-total_bits // bits_per_unit)  # ceil division


def embed_bits(carrier: bytearray, start_unit: int, bits_per_unit: int, data: bytes) -> None:
    """
    Embed `data` into `carrier` (in place) using `bits_per_unit` LSBs of
    each carrier byte, starting at byte index `start_unit`.
    """
    if not (1 <= bits_per_unit <= 8):
        raise ValueError("bits_per_unit must be between 1 and 8")

    bitstring = bytes_to_bitstring(data)
    units_needed = required_units(len(data), bits_per_unit)
    if start_unit + units_needed > len(carrier):
        raise ValueError("Cover object does not have enough capacity for this payload")

    mask_clear = (0xFF << bits_per_unit) & 0xFF  # clears the low bits_per_unit bits
    pos = 0
    for i in range(units_needed):
        chunk = bitstring[pos: pos + bits_per_unit]
        pos += bits_per_unit
        if len(chunk) < bits_per_unit:
            chunk = chunk.ljust(bits_per_unit, "0")
        value = int(chunk, 2)
        idx = start_unit + i
        carrier[idx] = (carrier[idx] & mask_clear) | value


def extract_bits(carrier: bytes, start_unit: int, bits_per_unit: int, num_bytes: int) -> bytes:
    """Extract `num_bytes` worth of data starting at byte index `start_unit`."""
    if not (1 <= bits_per_unit <= 8):
        raise ValueError("bits_per_unit must be between 1 and 8")

    units_needed = required_units(num_bytes, bits_per_unit)
    if start_unit + units_needed > len(carrier):
        raise ValueError("Cannot extract: requested range exceeds carrier capacity")

    bits_chunks = []
    mask = (1 << bits_per_unit) - 1
    for i in range(units_needed):
        value = carrier[start_unit + i] & mask
        bits_chunks.append(format(value, f"0{bits_per_unit}b"))
    bitstring = "".join(bits_chunks)[: num_bytes * 8]
    return bitstring_to_bytes(bitstring)


def capacity_bytes(carrier_len: int, start_unit: int, bits_per_unit: int) -> int:
    """Maximum number of payload bytes that can be embedded from start_unit onward."""
    available_units = max(0, carrier_len - start_unit)
    return (available_units * bits_per_unit) // 8
