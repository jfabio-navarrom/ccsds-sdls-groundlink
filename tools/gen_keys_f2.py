"""
Generates the two SDLS keys of phase 2 (AES-256): one for TC
(ground -> satellite, SPI 1) and one for TM (satellite -> ground, SPI 2).

- Saves the ground keys in ground/keys_f2.json (not pushed to GitHub).
- Prints the two lines you must paste into the satellite secrets.h.

Usage:
    py tools\\gen_keys_f2.py         (does not overwrite existing keys)
    py tools\\gen_keys_f2.py --new   (makes new keys and replaces the old ones)
"""

import argparse
import json
import os
import secrets
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ground"))

from ccsds.keystore import KEYS_PATH  # noqa: E402


def c_array(key: bytes) -> str:
    return "{" + ", ".join(f"0x{b:02x}" for b in key) + "}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Generates the phase 2 SDLS keys")
    ap.add_argument("--new", action="store_true", help="replace the existing keys")
    args = ap.parse_args(argv)

    if os.path.exists(KEYS_PATH) and not args.new:
        with open(KEYS_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        print("You already had keys in ground/keys_f2.json; I keep them (use --new to change them).")
    else:
        data = {"tc_key": secrets.token_bytes(32).hex(), "tm_key": secrets.token_bytes(32).hex()}
        with open(KEYS_PATH, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        print("New keys saved in ground/keys_f2.json (this file is NOT pushed to GitHub).")

    print()
    print("Copy these two lines into the secrets.h tab of the satellite (satellite_f2),")
    print("below WIFI_PASS:")
    print()
    print(f"#define SDLS_TC_KEY {c_array(bytes.fromhex(data['tc_key']))}")
    print(f"#define SDLS_TM_KEY {c_array(bytes.fromhex(data['tm_key']))}")
    print()
    print("Treat these keys like a password: do not paste them in chats or screenshots.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
