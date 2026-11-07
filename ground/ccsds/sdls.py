"""
Space Data Link Security (CCSDS 355.0-B), subconjunto - lado de tierra.

Es la misma logica que satellite/satellite_f2/sdls.cpp, escrita de forma
independiente en Python (con la libreria "cryptography").

Trama TC protegida (longitud variable):
    [cabecera TC 5][SPI 2][IV 12][Space Packet CIFRADO][MAC 16][FECF 2]

Trama TM protegida (128 bytes fijos):
    [cabecera TM 6][SPI 2][IV 12][datos CIFRADOS 86][MAC 16][CLCW 4][FECF 2]

AES-256-GCM. Datos autenticados (AAD) = cabecera de trama + SPI + IV.
El IV hace tambien de numero de secuencia anti-replay.
"""

from dataclasses import dataclass

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as exc:  # pragma: no cover
    raise SystemExit("Falta la libreria 'cryptography'. Instalala con:  py -m pip install cryptography") from exc

from . import frames
from .frames import (APID_IDLE, FECF_LEN, SCID, SP_HEADER_LEN, TC_HEADER_LEN, TM_FRAME_LEN,
                     TM_HEADER_LEN, TM_OCF_LEN, VCID, CcsdsError, crc16)

SPI_LEN = 2
IV_LEN = 12
MAC_LEN = 16
KEY_LEN = 32
SEC_HEADER_LEN = SPI_LEN + IV_LEN
SEC_OVERHEAD = SEC_HEADER_LEN + MAC_LEN

SPI_TC = 1
SPI_TM = 2

TM_SDLS_DATA_LEN = TM_FRAME_LEN - TM_HEADER_LEN - SEC_OVERHEAD - TM_OCF_LEN - FECF_LEN  # 86

# Codigos de rechazo / eventos de seguridad (iguales que en sdls.h)
SEC_ERR_SPI = 20
SEC_ERR_MAC = 21
SEC_ERR_REPLAY = 22
SEC_ERR_LENGTH = 23

SEC_NAMES = {
    SEC_ERR_SPI: "sin SDLS o SPI desconocido",
    SEC_ERR_MAC: "MAC invalida",
    SEC_ERR_REPLAY: "repeticion (replay)",
    SEC_ERR_LENGTH: "demasiado corta para SDLS",
}


class SdlsError(ValueError):
    def __init__(self, code: int):
        super().__init__(SEC_NAMES.get(code, f"codigo {code}"))
        self.code = code


def iv_from_counter(counter: int) -> bytes:
    return bytes(4) + counter.to_bytes(8, "big")


def iv_to_counter(iv: bytes) -> int:
    return int.from_bytes(iv[4:12], "big")


class SecurityAssociation:
    """SPI + clave + ultimo IV aceptado (anti-replay)."""

    def __init__(self, spi: int, key: bytes):
        if len(key) != KEY_LEN:
            raise ValueError("la clave AES-256 debe tener 32 bytes")
        self.spi = spi
        self.aead = AESGCM(key)
        self.last_iv = bytes(IV_LEN)


# ------------------------------ Tramas TC -------------------------------

def build_secure_tc_frame(sa: SecurityAssociation, packet: bytes, seq: int, iv_counter: int,
                          scid: int = SCID, vcid: int = VCID) -> bytes:
    """Lo usa la tierra: Space Packet -> trama TC cifrada y autenticada."""
    iv = iv_from_counter(iv_counter)
    sec_header = sa.spi.to_bytes(2, "big") + iv
    total = TC_HEADER_LEN + SEC_HEADER_LEN + len(packet) + MAC_LEN + FECF_LEN
    length = total - 1
    header = bytes([
        (scid >> 8) & 0x03,
        scid & 0xFF,
        ((vcid & 0x3F) << 2) | ((length >> 8) & 0x03),
        length & 0xFF,
        seq & 0xFF,
    ])
    sealed = sa.aead.encrypt(iv, packet, header + sec_header)  # = cifrado + MAC (16)
    body = header + sec_header + sealed
    crc = crc16(body)
    return body + bytes([crc >> 8, crc & 0xFF])


@dataclass
class SecureTc:
    frame: frames.TcFrame
    spi: int
    iv: bytes
    packet: bytes          # Space Packet descifrado


def process_secure_tc(sa: SecurityAssociation, buf: bytes) -> SecureTc:
    """Lo que hace el satelite (lo usan el simulador y los tests)."""
    f = frames.parse_tc_frame(buf)   # CcsdsError si la trama esta mal
    if len(f.data) < SEC_OVERHEAD + 1:
        raise SdlsError(SEC_ERR_LENGTH)
    spi = int.from_bytes(f.data[:2], "big")
    if spi != sa.spi:
        raise SdlsError(SEC_ERR_SPI)
    iv = f.data[SPI_LEN:SEC_HEADER_LEN]
    aad = buf[:TC_HEADER_LEN + SEC_HEADER_LEN]
    try:
        packet = sa.aead.decrypt(iv, f.data[SEC_HEADER_LEN:], aad)
    except InvalidTag:
        raise SdlsError(SEC_ERR_MAC) from None
    if iv <= sa.last_iv:
        raise SdlsError(SEC_ERR_REPLAY)
    sa.last_iv = iv
    return SecureTc(frame=f, spi=spi, iv=iv, packet=packet)


# ------------------------------ Tramas TM -------------------------------

def build_secure_tm_frame(sa: SecurityAssociation, packet: bytes, mc_count: int, vc_count: int,
                          report_value: int, iv_counter: int) -> bytes:
    """Lo que hace el satelite (lo usan el simulador y los tests)."""
    rest = TM_SDLS_DATA_LEN - len(packet)
    if rest < 0 or 0 < rest < SP_HEADER_LEN + 1:
        raise CcsdsError("el paquete no cabe en la trama")
    header = bytes([(SCID >> 4) & 0x3F, ((SCID & 0x0F) << 4) | ((VCID & 0x07) << 1) | 1,
                    mc_count & 0xFF, vc_count & 0xFF, 0x18, 0x00])
    iv = iv_from_counter(iv_counter)
    sec_header = sa.spi.to_bytes(2, "big") + iv
    plain = packet
    if rest:
        plain += frames.build_space_packet(0, APID_IDLE, 0, b"\x55" * (rest - SP_HEADER_LEN))
    sealed = sa.aead.encrypt(iv, plain, header + sec_header)
    clcw = (1 << 24) | ((VCID & 0x3F) << 18) | (report_value & 0xFF)
    body = header + sec_header + sealed + clcw.to_bytes(4, "big")
    crc = crc16(body)
    return body + bytes([crc >> 8, crc & 0xFF])


@dataclass
class SecureTm:
    frame: frames.TmFrame
    iv: bytes


def parse_secure_tm_frame(sa: SecurityAssociation, buf: bytes, check_replay: bool = True) -> SecureTm:
    """Lo usa la tierra: verifica, descifra y extrae los paquetes de una trama TM."""
    if len(buf) != TM_FRAME_LEN:
        raise CcsdsError(f"una trama TM debe medir {TM_FRAME_LEN} bytes")
    if crc16(buf[:-2]) != (buf[-2] << 8) | buf[-1]:
        raise CcsdsError("CRC incorrecto")
    if buf[0] >> 6 != 0:
        raise CcsdsError("version incorrecta")
    sh = buf[TM_HEADER_LEN:TM_HEADER_LEN + SEC_HEADER_LEN]
    if int.from_bytes(sh[:2], "big") != sa.spi:
        raise SdlsError(SEC_ERR_SPI)
    iv = sh[SPI_LEN:]
    start = TM_HEADER_LEN + SEC_HEADER_LEN
    end = start + TM_SDLS_DATA_LEN + MAC_LEN
    try:
        plain = sa.aead.decrypt(iv, buf[start:end], buf[:start])
    except InvalidTag:
        raise SdlsError(SEC_ERR_MAC) from None
    if check_replay:
        if iv <= sa.last_iv:
            raise SdlsError(SEC_ERR_REPLAY)
        sa.last_iv = iv
    fhp = ((buf[4] & 0x07) << 8) | buf[5]
    word = int.from_bytes(buf[end:end + 4], "big")
    tm = frames.TmFrame(scid=((buf[0] & 0x3F) << 4) | (buf[1] >> 4), vcid=(buf[1] >> 1) & 0x07,
                        mc_count=buf[2], vc_count=buf[3],
                        packets=frames.packets_from_data(plain, fhp), clcw=frames.parse_clcw(word))
    return SecureTm(frame=tm, iv=iv)
