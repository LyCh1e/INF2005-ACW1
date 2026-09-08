"""
Generate the RSA key pair used to sign / verify verification payloads.

Run once:  python scripts/generate_keys.py

Produces keys/private_key.pem (KEEP SECRET, only for demo use) and
keys/public_key.pem (safe to distribute / submit).
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import crypto_utils  # noqa: E402

PRIVATE_KEY_PATH = ROOT / "keys" / "private_key.pem"
PUBLIC_KEY_PATH = ROOT / "keys" / "public_key.pem"


def main():
    if PRIVATE_KEY_PATH.exists() or PUBLIC_KEY_PATH.exists():
        answer = input(f"Key files already exist under {ROOT / 'keys'}. Overwrite? [y/N] ")
        if answer.strip().lower() != "y":
            print("Aborted.")
            return
    crypto_utils.generate_keypair(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH)
    print(f"Generated:\n  {PRIVATE_KEY_PATH}\n  {PUBLIC_KEY_PATH}")
    print("\nNOTE: private_key.pem is generated purely for this assignment demo.")
    print("Do not reuse it anywhere else; do not submit it to a real deployment.")


if __name__ == "__main__":
    main()
