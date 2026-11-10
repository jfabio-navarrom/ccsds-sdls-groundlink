"""
SDLS keys and IV counter of the ground station (phase 2).

- The keys live in ground/keys_f2.json. tools/gen_keys_f2.py creates this
  file and it is NEVER pushed to GitHub (.gitignore).
- The TC IV counter must always go up, also if you close the console or
  delete the state file. If an IV is repeated, the satellite rejects the
  TC as a replay (and worse, in GCM a repeated IV with the same key leaks
  information). So we use max(last_saved + 1, clock in microseconds): if
  the state file is lost, the clock is already ahead.
"""

import json
import os
import time

GROUND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
KEYS_PATH = os.path.join(GROUND_DIR, "keys_f2.json")
STATE_PATH = os.path.join(GROUND_DIR, "state_f2.json")


class KeysMissing(Exception):
    pass


def load_keys(path: str = KEYS_PATH) -> tuple:
    """Returns (tc_key, tm_key) as bytes."""
    if not os.path.exists(path):
        raise KeysMissing(
            "I can not find the SDLS keys (ground/keys_f2.json). Generate them with:\n"
            "    py tools\\gen_keys_f2.py\n"
            "and copy the two lines it prints into the satellite secrets.h.")
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return bytes.fromhex(data["tc_key"]), bytes.fromhex(data["tm_key"])


class IvCounter:
    """Monotonic counter for the TC IV, saved on disk."""

    def __init__(self, path: str = STATE_PATH):
        self.path = path
        self.last = 0
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    self.last = int(json.load(fh).get("tc_iv", 0))
            except (ValueError, OSError):
                self.last = 0

    def next(self) -> int:
        self.last = max(self.last + 1, time.time_ns() // 1000)
        try:
            with open(self.path, "w", encoding="utf-8") as fh:
                json.dump({"tc_iv": self.last}, fh)
        except OSError:
            pass
        return self.last


# ------------------------------- Phase 3 --------------------------------

KEYS_F3_PATH = os.path.join(GROUND_DIR, "keys_f3.json")
STATE_F3_PATH = os.path.join(GROUND_DIR, "state_f3.json")


class KeyStoreF3:
    """
    Phase 3 keys, in ground/keys_f3.json (NEVER pushed to GitHub):
      kek       master key: it only wraps new keys (OTAR)
      active    {id, tc, tm}: traffic keys in use
      pending   {id, tc, tm} or null: uploaded but not active yet
      retired   IDs already retired (the keys themselves are deleted)
    """

    def __init__(self, path: str = KEYS_F3_PATH):
        self.path = path
        if not os.path.exists(path):
            raise KeysMissing(
                "I can not find the phase 3 keys (ground/keys_f3.json). Generate them with:\n"
                "    py tools\\gen_keys_f3.py\n"
                "and copy the three lines it prints into the satellite secrets.h.")
        with open(path, encoding="utf-8") as fh:
            self.data = json.load(fh)

    @staticmethod
    def create(path: str, kek: bytes, tc: bytes, tm: bytes) -> None:
        data = {"kek": kek.hex(), "active": {"id": 1, "tc": tc.hex(), "tm": tm.hex()},
                "pending": None, "retired": []}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)

    def save(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=2)
        os.replace(tmp, self.path)

    @property
    def kek(self) -> bytes:
        return bytes.fromhex(self.data["kek"])

    @property
    def active_id(self) -> int:
        return self.data["active"]["id"]

    def active(self) -> tuple:
        a = self.data["active"]
        return bytes.fromhex(a["tc"]), bytes.fromhex(a["tm"])

    def pending(self):
        p = self.data.get("pending")
        if not p:
            return None
        return p["id"], bytes.fromhex(p["tc"]), bytes.fromhex(p["tm"])

    def set_pending(self, key_id: int, tc: bytes, tm: bytes) -> None:
        self.data["pending"] = {"id": key_id, "tc": tc.hex(), "tm": tm.hex()}
        self.save()

    def activate_pending(self) -> int:
        p = self.data["pending"]
        self.data["retired"].append(self.data["active"]["id"])
        self.data["active"] = p
        self.data["pending"] = None
        self.save()
        return p["id"]
