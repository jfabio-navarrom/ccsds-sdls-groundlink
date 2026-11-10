"""
COP-1 (CCSDS 232.1-B), simple version.

- FARM: the satellite side (here in Python for the simulator and the tests;
  on the board it is satellite/satellite_f3/farm.cpp).
- Control commands (BC frames) used by the ground FOP.

The FARM is not a security mechanism: it only puts frames in order and
removes duplicates. Security comes from SDLS, which runs before it.
"""

from dataclasses import dataclass

WINDOW = 10
POS_WINDOW = WINDOW // 2
NEG_WINDOW = WINDOW // 2

ACCEPT, DISCARD_AHEAD, DISCARD_DUPLICATE, LOCKOUT, DISCARD_LOCKED, CONTROL_OK, CONTROL_BAD = range(7)

RESULT_NAMES = {
    ACCEPT: "accepted",
    DISCARD_AHEAD: "ahead: one frame is missing, retransmit",
    DISCARD_DUPLICATE: "duplicate: it was already executed",
    LOCKOUT: "out of window: FARM lockout",
    DISCARD_LOCKED: "FARM in lockout: Unlock is needed",
    CONTROL_OK: "control command executed",
    CONTROL_BAD: "invalid control command",
}

# Control commands (content of a BC frame)
UNLOCK = bytes([0x00])


def set_vr(n: int) -> bytes:
    return bytes([0x82, 0x00, n & 0xFF])


@dataclass
class Farm:
    vr: int = 0
    lockout: bool = False
    wait: bool = False
    retransmit: bool = False
    farm_b: int = 0

    def on_ad(self, ns: int) -> int:
        if self.lockout:
            return DISCARD_LOCKED
        if ns == self.vr:
            self.vr = (self.vr + 1) & 0xFF
            self.retransmit = False
            return ACCEPT
        ahead = (ns - self.vr) & 0xFF
        behind = (self.vr - ns) & 0xFF
        if ahead < POS_WINDOW:
            self.retransmit = True
            return DISCARD_AHEAD
        if behind <= NEG_WINDOW:
            return DISCARD_DUPLICATE
        self.lockout = True
        return LOCKOUT

    def on_bd(self) -> int:
        self.farm_b = (self.farm_b + 1) & 0x03
        return ACCEPT

    def on_bc(self, data: bytes) -> int:
        if data == UNLOCK:
            self.lockout = self.retransmit = self.wait = False
            self.farm_b = (self.farm_b + 1) & 0x03
            return CONTROL_OK
        if len(data) == 3 and data[:2] == b"\x82\x00":
            if self.lockout:
                return CONTROL_BAD
            self.vr = data[2]
            self.retransmit = False
            self.farm_b = (self.farm_b + 1) & 0x03
            return CONTROL_OK
        return CONTROL_BAD

    def clcw(self, vcid: int = 0) -> int:
        return ((1 << 24) | ((vcid & 0x3F) << 18) | (int(self.lockout) << 13) | (int(self.wait) << 12)
                | (int(self.retransmit) << 11) | ((self.farm_b & 0x03) << 9) | self.vr)
