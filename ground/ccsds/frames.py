"""
Subconjunto de CCSDS para la estacion de tierra (fase 1).

Es la misma pila que satellite/satellite_f1/ccsds.cpp, escrita de forma
independiente en Python. Los tests de interoperabilidad comprueban que
las dos implementaciones se entienden.

- TC Space Data Link Protocol (CCSDS 232.0-B)
- TM Space Data Link Protocol (CCSDS 132.0-B)
- Space Packet Protocol (CCSDS 133.0-B)
- CRC-16 (FECF) y CLCW (COP-1)
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
    """Trama o paquete mal formado."""


def crc16(data: bytes) -> int:
    """CRC-16-CCITT (polinomio 0x1021, inicial 0xFFFF): el FECF de CCSDS."""
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
    type: int            # 1 = telecomando, 0 = telemetria
    apid: int
    seq_count: int
    data: bytes
    secondary_header: bool = False
    seq_flags: int = 0b11


def build_space_packet(ptype: int, apid: int, seq_count: int, data: bytes) -> bytes:
    if not 1 <= len(data) <= 65536:
        raise CcsdsError("el campo de datos debe tener entre 1 y 65536 bytes")
    if not 0 <= apid <= 0x7FF:
        raise CcsdsError("APID fuera de rango")
    first = ((ptype & 1) << 4) | ((apid >> 8) & 0x07)
    seq = 0xC000 | (seq_count & 0x3FFF)
    length = len(data) - 1
    return bytes([first, apid & 0xFF, seq >> 8, seq & 0xFF, length >> 8, length & 0xFF]) + data


def parse_space_packet(buf: bytes) -> SpacePacket:
    if len(buf) < SP_HEADER_LEN + 1:
        raise CcsdsError("paquete demasiado corto")
    if buf[0] >> 5 != 0:
        raise CcsdsError("version de paquete incorrecta")
    data_len = ((buf[4] << 8) | buf[5]) + 1
    if SP_HEADER_LEN + data_len > len(buf):
        raise CcsdsError("longitud de paquete incorrecta")
    return SpacePacket(
        type=(buf[0] >> 4) & 1,
        secondary_header=bool((buf[0] >> 3) & 1),
        apid=((buf[0] & 0x07) << 8) | buf[1],
        seq_flags=buf[2] >> 6,
        seq_count=((buf[2] & 0x3F) << 8) | buf[3],
        data=bytes(buf[SP_HEADER_LEN:SP_HEADER_LEN + data_len]),
    )


# ------------------------------ Tramas TC -------------------------------

def build_tc_frame(data: bytes, seq: int, scid: int = SCID, vcid: int = VCID,
                   bypass: bool = False, control: bool = False) -> bytes:
    """Construye una trama TC con su CRC. data = un Space Packet."""
    total = TC_HEADER_LEN + len(data) + FECF_LEN
    if total > 1024:
        raise CcsdsError("una trama TC no puede pasar de 1024 bytes")
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
    """Lo usan los tests (y un atacante que escucha el enlace)."""
    if len(buf) < TC_HEADER_LEN + FECF_LEN + 1:
        raise CcsdsError("trama demasiado corta")
    if buf[0] >> 6 != 0:
        raise CcsdsError("version incorrecta")
    if (((buf[2] & 0x03) << 8) | buf[3]) + 1 != len(buf):
        raise CcsdsError("longitud incorrecta")
    if crc16(buf[:-2]) != (buf[-2] << 8) | buf[-1]:
        raise CcsdsError("CRC incorrecto")
    return TcFrame(
        bypass=bool((buf[0] >> 5) & 1),
        control=bool((buf[0] >> 4) & 1),
        scid=((buf[0] & 0x03) << 8) | buf[1],
        vcid=buf[2] >> 2,
        seq=buf[4],
        data=bytes(buf[TC_HEADER_LEN:-FECF_LEN]),
    )


# ------------------------------ Tramas TM -------------------------------

@dataclass
class Clcw:
    vcid: int
    lockout: bool
    wait: bool
    retransmit: bool
    report_value: int   # V(R): siguiente numero de secuencia que espera el satelite


def parse_clcw(word: int) -> Clcw:
    return Clcw(
        vcid=(word >> 18) & 0x3F,
        lockout=bool((word >> 13) & 1),
        wait=bool((word >> 12) & 1),
        retransmit=bool((word >> 11) & 1),
        report_value=word & 0xFF,
    )


@dataclass
class TmFrame:
    scid: int
    vcid: int
    mc_count: int
    vc_count: int
    packets: list          # Space Packets utiles (sin los de relleno)
    clcw: Clcw


def parse_tm_frame(buf: bytes) -> TmFrame:
    if len(buf) != TM_FRAME_LEN:
        raise CcsdsError(f"una trama TM debe medir {TM_FRAME_LEN} bytes")
    if crc16(buf[:-2]) != (buf[-2] << 8) | buf[-1]:
        raise CcsdsError("CRC incorrecto")
    if buf[0] >> 6 != 0:
        raise CcsdsError("version incorrecta")
    scid = ((buf[0] & 0x3F) << 4) | (buf[1] >> 4)
    vcid = (buf[1] >> 1) & 0x07
    ocf_present = buf[1] & 1
    fhp = ((buf[4] & 0x07) << 8) | buf[5]

    data = buf[TM_HEADER_LEN:TM_HEADER_LEN + TM_DATA_LEN]
    packets = []
    pos = fhp
    while pos + SP_HEADER_LEN < len(data):
        length = SP_HEADER_LEN + ((data[pos + 4] << 8) | data[pos + 5]) + 1
        pkt = parse_space_packet(data[pos:pos + length])
        if pkt.apid != APID_IDLE:
            packets.append(pkt)
        pos += length

    word = int.from_bytes(buf[TM_HEADER_LEN + TM_DATA_LEN:TM_HEADER_LEN + TM_DATA_LEN + 4], "big")
    return TmFrame(scid=scid, vcid=vcid, mc_count=buf[2], vc_count=buf[3],
                   packets=packets, clcw=parse_clcw(word) if ocf_present else None)


def build_tm_frame(packet: bytes, mc_count: int, vc_count: int, report_value: int) -> bytes:
    """Lo usan los tests para simular al satelite."""
    rest = TM_DATA_LEN - len(packet)
    if rest < 0 or 0 < rest < SP_HEADER_LEN + 1:
        raise CcsdsError("el paquete no cabe en la trama")
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
