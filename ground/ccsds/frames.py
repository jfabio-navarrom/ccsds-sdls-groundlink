"""
CCSDS subset for the ground station (phase 1).

This is the same stack as satellite/satellite_f1/ccsds.cpp, but written
separately in Python. The interop tests check that both implementations
understand each other.

- TC Space Data Link Protocol (CCSDS 232.0-B)
- TM Space Data Link Protocol (CCSDS 132.0-B)
- Space Packet Protocol (CCSDS 133.0-B)
- CRC-16 (FECF) and CLCW (COP-1)
"""

from dataclasses import dataclass

SCID = 0x0C5        # Spacecraft ID: "C5"
VCID = 0
APID_SAT = 0x010
APID_IDLE = 0x7FF

TC_HEADER_LEN = 5
FECF_LEN = 2
TM_FRAME_LEN = 128
TM_HEADER_LEN = 6
TM_OCF_LEN = 4
TM_DATA_LEN = TM_FRAME_LEN - TM_HEADER_LEN - TM_OCF_LEN - FECF_LEN  # 116
SP_HEADER_LEN = 6


class CcsdsError(ValueError):
    """Bad frame or packet."""


def crc16(data: bytes) -> int:
    """CRC-16-CCITT (polynomial 0x1021, initial 0xFFFF): the CCSDS FECF."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


# ----------------------------- Space Packets -----------------------------

@dataclass
class SpacePacket:
    type: int            # 1 = telecommand, 0 = telemetry
    apid: int
    seq_count: int
    data: bytes
    secondary_header: bool = False
    seq_flags: int = 0b11


def build_space_packet(ptype: int, apid: int, seq_count: int, data: bytes) -> bytes:
    if not 1 <= len(data) <= 65536:
        raise CcsdsError("data field must be 1 to 65536 bytes")
    if not 0 <= apid <= 0x7FF:
        raise CcsdsError("APID out of range")
    first = ((ptype & 1) << 4) | ((apid >> 8) & 0x07)
    seq = 0xC000 | (seq_count & 0x3FFF)
    length = len(data) - 1
    return bytes([first, apid & 0xFF, seq >> 8, seq & 0xFF, length >> 8, length & 0xFF]) + data


def parse_space_packet(buf: bytes) -> SpacePacket:
    if len(buf) < SP_HEADER_LEN + 1:
        raise CcsdsError("packet too short")
    if buf[0] >> 5 != 0:
        raise CcsdsError("wrong packet version")
    data_len = ((buf[4] << 8) | buf[5]) + 1
    if SP_HEADER_LEN + data_len > len(buf):
        raise CcsdsError("wrong packet length")
    return SpacePacket(
        type=(buf[0] >> 4) & 1,
        secondary_header=bool((buf[0] >> 3) & 1),
        apid=((buf[0] & 0x07) << 8) | buf[1],
        seq_flags=buf[2] >> 6,
        seq_count=((buf[2] & 0x3F) << 8) | buf[3],
        data=bytes(buf[SP_HEADER_LEN:SP_HEADER_LEN + data_len]),
    )


# ------------------------------ TC frames -------------------------------

def build_tc_frame(data: bytes, seq: int, scid: int = SCID, vcid: int = VCID,
                   bypass: bool = False, control: bool = False) -> bytes:
    """Builds a TC frame with its CRC. data = one Space Packet."""
    total = TC_HEADER_LEN + len(data) + FECF_LEN
    if total > 1024:
        raise CcsdsError("a TC frame can not be longer than 1024 bytes")
    length = total - 1
    header = bytes([
        (int(bypass) << 5) | (int(control) << 4) | ((scid >> 8) & 0x03),
        scid & 0xFF,
        ((vcid & 0x3F) << 2) | ((length >> 8) & 0x03),
        length & 0xFF,
        seq & 0xFF,
    ])
    body = header + data
    crc = crc16(body)
    return body + bytes([crc >> 8, crc & 0xFF])


@dataclass
class TcFrame:
    bypass: bool
    control: bool
    scid: int
    vcid: int
    seq: int
    data: bytes


def parse_tc_frame(buf: bytes) -> TcFrame:
    """Used by the tests (and by an attacker listening to the link)."""
    if len(buf) < TC_HEADER_LEN + FECF_LEN + 1:
        raise CcsdsError("frame too short")
    if buf[0] >> 6 != 0:
        raise CcsdsError("wrong version")
    if (((buf[2] & 0x03) << 8) | buf[3]) + 1 != len(buf):
        raise CcsdsError("wrong length")
    if crc16(buf[:-2]) != (buf[-2] << 8) | buf[-1]:
        raise CcsdsError("bad CRC")
    return TcFrame(
        bypass=bool((buf[0] >> 5) & 1),
        control=bool((buf[0] >> 4) & 1),
        scid=((buf[0] & 0x03) << 8) | buf[1],
        vcid=buf[2] >> 2,
        seq=buf[4],
        data=bytes(buf[TC_HEADER_LEN:-FECF_LEN]),
    )


# ------------------------------ TM frames -------------------------------

@dataclass
class Clcw:
    vcid: int
    lockout: bool
    wait: bool
    retransmit: bool
    report_value: int   # V(R): next sequence number the satellite expects
    farm_b: int = 0     # counter of accepted BD/BC frames (2 bits)


def parse_clcw(word: int) -> Clcw:
    return Clcw(
        vcid=(word >> 18) & 0x3F,
        lockout=bool((word >> 13) & 1),
        wait=bool((word >> 12) & 1),
        retransmit=bool((word >> 11) & 1),
        report_value=word & 0xFF,
        farm_b=(word >> 9) & 0x03,
    )


@dataclass
class TmFrame:
    scid: int
    vcid: int
    mc_count: int
    vc_count: int
    packets: list          # useful Space Packets (idle ones removed)
    clcw: Clcw


def packets_from_data(data: bytes, fhp: int = 0) -> list:
    """Takes the useful Space Packets (no idle) out of the data field of a TM frame."""
    packets = []
    pos = fhp
    while pos + SP_HEADER_LEN < len(data):
        length = SP_HEADER_LEN + ((data[pos + 4] << 8) | data[pos + 5]) + 1
        pkt = parse_space_packet(data[pos:pos + length])
        if pkt.apid != APID_IDLE:
            packets.append(pkt)
        pos += length
    return packets


def parse_tm_frame(buf: bytes) -> TmFrame:
    if len(buf) != TM_FRAME_LEN:
        raise CcsdsError(f"a TM frame must be {TM_FRAME_LEN} bytes")
    if crc16(buf[:-2]) != (buf[-2] << 8) | buf[-1]:
        raise CcsdsError("bad CRC")
    if buf[0] >> 6 != 0:
        raise CcsdsError("wrong version")
    scid = ((buf[0] & 0x3F) << 4) | (buf[1] >> 4)
    vcid = (buf[1] >> 1) & 0x07
    ocf_present = buf[1] & 1
    fhp = ((buf[4] & 0x07) << 8) | buf[5]

    packets = packets_from_data(buf[TM_HEADER_LEN:TM_HEADER_LEN + TM_DATA_LEN], fhp)

    word = int.from_bytes(buf[TM_HEADER_LEN + TM_DATA_LEN:TM_HEADER_LEN + TM_DATA_LEN + 4], "big")
    return TmFrame(scid=scid, vcid=vcid, mc_count=buf[2], vc_count=buf[3],
                   packets=packets, clcw=parse_clcw(word) if ocf_present else None)


def build_tm_frame(packet: bytes, mc_count: int, vc_count: int, report_value: int) -> bytes:
    """Used by the tests to simulate the satellite."""
    rest = TM_DATA_LEN - len(packet)
    if rest < 0 or 0 < rest < SP_HEADER_LEN + 1:
        raise CcsdsError("packet does not fit in the frame")
    out = bytearray()
    out += bytes([(SCID >> 4) & 0x3F, ((SCID & 0x0F) << 4) | ((VCID & 0x07) << 1) | 1,
                  mc_count & 0xFF, vc_count & 0xFF, 0x18, 0x00])
    out += packet
    if rest:
        out += build_space_packet(0, APID_IDLE, 0, b"\x55" * (rest - SP_HEADER_LEN))
    clcw = (1 << 24) | ((VCID & 0x3F) << 18) | (report_value & 0xFF)
    out += clcw.to_bytes(4, "big")
    crc = crc16(bytes(out))
    out += bytes([crc >> 8, crc & 0xFF])
    return bytes(out)
