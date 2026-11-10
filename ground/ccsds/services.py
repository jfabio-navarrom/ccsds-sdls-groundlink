"""
"PUS-lite" services: what the packets mean.

Based on the ECSS Packet Utilization Standard (ECSS-E-ST-70-41), but cut
down to the minimum: the data field of each Space Packet starts with
2 bytes (service, subservice) and then the application data.
"""

import struct
from dataclasses import dataclass

from .frames import APID_SAT, SpacePacket, build_space_packet

# Telecommands (ground -> satellite)
TC_PING = (17, 1)        # are you alive?
TC_SET_COLOR = (8, 1)    # payload: set the screen to a color (R, G, B)
TC_REQUEST_HK = (3, 27)  # ask for a housekeeping report now
TC_OTAR_UPLOAD = (24, 1)    # phase 3: upload new keys wrapped with the KEK
TC_OTAR_ACTIVATE = (24, 2)  # phase 3: activate the uploaded keys

# Telemetry (satellite -> ground)
TM_PONG = (17, 2)
TM_ACK_OK = (1, 7)       # telecommand executed
TM_ACK_FAIL = (1, 2)     # telecommand rejected (with reason code)
TM_HK = (3, 25)          # housekeeping report
TM_SEC_EVENT = (5, 4)    # security event (phase 2): the satellite rejected a frame
TM_EVENTS_SUPPRESSED = (5, 5)  # phase 3: summary of events not sent (flood)

FAIL_CODES = {
    1: "frame too short",
    2: "wrong version",
    3: "wrong length",
    4: "bad CRC",
    5: "SCID of another spacecraft",
    6: "unknown virtual channel",
    10: "bad packet",
    11: "unknown service",
    12: "bad application data",
    20: "no SDLS or unknown SPI",
    21: "invalid MAC",
    22: "replay",
    23: "too short for SDLS",
    30: "FARM: frame is ahead, a previous one is missing (retransmit)",
    31: "FARM in lockout: 'sync' is needed",
    32: "invalid FARM control command",
    40: "OTAR: key block does not decrypt with the KEK",
    41: "OTAR: key ID is not higher than the active one (rollback)",
    42: "OTAR: no pending keys with that ID",
}

HK_FORMAT = ">IHHB3BbI"   # uptime, TC accepted, TC rejected, last sequence, R, G, B, RSSI, free heap
# Phase 2: also security rejections by reason (SPI, MAC, replay)
HK_F2_FORMAT = ">IHHHHHB3BbI"
# Security event: code, frame N(S), source IP and port, IV counter
SEC_EVENT_FORMAT = ">BB4sHQ"
# Phase 3: + FARM discards, suppressed events and active key ID
HK_F3_FORMAT = ">IHHHHHHH3BbIB"


def build_tc_packet(service: tuple, seq_count: int, app_data: bytes = b"") -> bytes:
    svc, sub = service
    return build_space_packet(1, APID_SAT, seq_count, bytes([svc, sub]) + app_data)


@dataclass
class Housekeeping:
    uptime_s: int
    tc_accepted: int
    tc_rejected: int
    last_frame_seq: int
    payload_rgb: tuple
    rssi_dbm: int
    free_heap: int


def decode_tm_packet(pkt: SpacePacket) -> str:
    """Turns a telemetry packet into a readable line."""
    if len(pkt.data) < 2:
        return f"packet without service (APID {pkt.apid:#x})"
    service = (pkt.data[0], pkt.data[1])
    app = pkt.data[2:]

    if service == TM_PONG:
        return "PONG: the satellite answers"
    if service == TM_ACK_OK and len(app) >= 2:
        seq = struct.unpack(">H", app[:2])[0]
        if seq == 0xFFFF:
            return "OK: FARM control command executed"
        return f"OK: telecommand (packet #{seq}) executed"
    if service == TM_ACK_FAIL and len(app) >= 3:
        seq, code = struct.unpack(">HB", app[:3])
        reason = FAIL_CODES.get(code, f"code {code}")
        what = "frame" if seq == 0xFFFF else f"packet #{seq}"
        return f"REJECTED: {what}, reason: {reason}"
    if service == TM_SEC_EVENT and len(app) >= struct.calcsize(SEC_EVENT_FORMAT):
        ev = decode_sec_event(app)
        return (f"SECURITY EVENT: frame rejected ({ev.reason}) from {ev.source}"
                f", N(S)={ev.frame_seq}, IV #{ev.iv_counter}")
    if service == TM_EVENTS_SUPPRESSED and len(app) >= 2:
        n = struct.unpack(">H", app[:2])[0]
        return f"FLOOD: {n} more security events, summarized in this message"
    if service == TM_HK and len(app) == struct.calcsize(HK_F3_FORMAT):
        hk = decode_hk_f3(app)
        r, g, b = hk.payload_rgb
        return (f"HK: uptime {hk.uptime_s} s | TC accepted {hk.tc_accepted} | rejected {hk.tc_rejected}"
                f" | FARM discards {hk.farm_discards} | security: SPI {hk.sec_spi}, MAC {hk.sec_mac},"
                f" replay {hk.sec_replay} (suppressed {hk.events_suppressed}) | key ID {hk.key_id}"
                f" | payload ({r},{g},{b})")
    if service == TM_HK and len(app) == struct.calcsize(HK_F2_FORMAT):
        hk = decode_hk_f2(app)
        r, g, b = hk.payload_rgb
        return (f"HK: uptime {hk.uptime_s} s | TC accepted {hk.tc_accepted} | "
                f"rejected {hk.tc_rejected} | security: SPI {hk.sec_spi}, MAC {hk.sec_mac}, "
                f"replay {hk.sec_replay} | payload ({r},{g},{b}) | RSSI {hk.rssi_dbm} dBm")
    if service == TM_HK and len(app) >= struct.calcsize(HK_FORMAT):
        hk = decode_hk(app)
        r, g, b = hk.payload_rgb
        return (f"HK: uptime {hk.uptime_s} s | TC accepted {hk.tc_accepted} | "
                f"rejected {hk.tc_rejected} | last sequence {hk.last_frame_seq} | "
                f"payload ({r},{g},{b}) | RSSI {hk.rssi_dbm} dBm | free heap {hk.free_heap} B")
    return f"unknown service {service}"


def decode_hk(app: bytes) -> Housekeeping:
    up, ok, bad, seq, r, g, b, rssi, heap = struct.unpack(HK_FORMAT, app[:struct.calcsize(HK_FORMAT)])
    return Housekeeping(up, ok, bad, seq, (r, g, b), rssi, heap)


@dataclass
class HousekeepingF2(Housekeeping):
    sec_spi: int = 0
    sec_mac: int = 0
    sec_replay: int = 0


def decode_hk_f2(app: bytes) -> HousekeepingF2:
    up, ok, bad, spi, mac, rep, seq, r, g, b, rssi, heap = struct.unpack(HK_F2_FORMAT, app)
    return HousekeepingF2(up, ok, bad, seq, (r, g, b), rssi, heap, spi, mac, rep)


@dataclass
class SecurityEvent:
    code: int
    reason: str
    frame_seq: int
    source: str
    iv_counter: int


def decode_sec_event(app: bytes) -> SecurityEvent:
    code, seq, ip, port, iv = struct.unpack(SEC_EVENT_FORMAT, app[:struct.calcsize(SEC_EVENT_FORMAT)])
    return SecurityEvent(code, FAIL_CODES.get(code, f"code {code}"), seq,
                         f"{'.'.join(str(b) for b in ip)}:{port}", iv)


@dataclass
class HousekeepingF3(HousekeepingF2):
    farm_discards: int = 0
    events_suppressed: int = 0
    key_id: int = 0


def decode_hk_f3(app: bytes) -> HousekeepingF3:
    up, ok, bad, spi, mac, rep, farm, supp, r, g, b, rssi, heap, kid = struct.unpack(HK_F3_FORMAT, app)
    return HousekeepingF3(up, ok, bad, 0, (r, g, b), rssi, heap, spi, mac, rep, farm, supp, kid)
