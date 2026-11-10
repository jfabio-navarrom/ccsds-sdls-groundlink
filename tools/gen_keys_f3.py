"""
Generates the phase 3 keys:
  - KEK (master key): only used to send new keys in flight (OTAR)
  - first TC key and TM key (ID 1)

- Saves the ground keys in ground/keys_f3.json (not pushed to GitHub).
- Prints the three lines you must paste into the satellite secrets.h.

After this, to change the traffic keys you do NOT need to generate anything
or reflash: use the 'rotate' command of the ground console.

Usage:
    py tools\\gen_keys_f3.py         (does not overwrite existing keys)
    py tools\\gen_keys_f3.py --new   (start from zero: you must reflash)
"""

import argparse
import os
import secrets
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ground"))

from ccsds.keystore import KEYS_F3_PATH, KeyStoreF3  # noqa: E402


def c_array(key: bytes) -> str:
    return "{" + ", ".join(f"0x{b:02x}" for b in key) + "}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Generates the phase 3 keys")
    ap.add_argument("--new", action="store_true", help="replace the existing keys")
    args = ap.parse_args(argv)

    if os.path.exists(KEYS_F3_PATH) and not args.new:
        print("You already had keys in ground/keys_f3.json; I keep them (use --new to start from zero).")
    else:
        KeyStoreF3.create(KEYS_F3_PATH, secrets.token_bytes(32), secrets.token_bytes(32), secrets.token_bytes(32))
        print("New keys saved in ground/keys_f3.json (this file is NOT pushed to GitHub).")
    ks = KeyStoreF3(KEYS_F3_PATH)
    if ks.active_id != 1:
        print(f"NOTE: the active key is already ID {ks.active_id} (rotated in flight). The lines below are")
        print("the KEK and the CURRENT keys; if you reflash, the satellite starts again with them.")
    tc, tm = ks.active()
    print()
    print("Copy these three lines into the secrets.h tab of the satellite (satellite_f3),")
    print("below WIFI_PASS:")
    print()
    print(f"#define SDLS_KEK {c_array(ks.kek)}")
    print(f"#define SDLS_TC_KEY {c_array(tc)}")
    print(f"#define SDLS_TM_KEY {c_array(tm)}")
    print()
    print("Treat these keys like a password: do not paste them in chats or screenshots.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
