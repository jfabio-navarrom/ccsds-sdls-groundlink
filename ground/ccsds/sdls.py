"""
Space Data Link Security (CCSDS 355.0-B), subset - ground side.

Same logic as satellite/satellite_f2/sdls.cpp, but written separately in
Python (with the "cryptography" library).

Protected TC frame (variable length):
    [cabecera TC 5][SPI 2][IV 12][ENCRYPTED Space Packet][MAC 16][FECF 2]

Protected TM frame (always 128 bytes):
    [cabecera TM 6][SPI 2][IV 12][ENCRYPTED data 86][MAC 16][CLCW 4][FECF 2]

AES-256-GCM. Authenticated data (AAD) = frame header + SPI + IV.
The IV is also the anti-replay sequence number.
"""

from dataclasses import dataclass

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as exc:  # pragma: no cover
    raise SystemExit("The 'cryptography' library is missing. Install it with:  py -m pip install cryptography") from exc

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

# Rejection codes / security events (same as in sdls.h)
SEC_ERR_SPI = 20
SEC_ERR_MAC = 21
SEC_ERR_REPLAY = 22
SEC_ERR_LENGTH = 23

SEC_NAMES = {
    SEC_ERR_SPI: "no SDLS or unknown SPI",
    SEC_ERR_MAC: "invalid MAC",
    SEC_ERR_REPLAY: "replay",
    SEC_ERR_LENGTH: "too short for SDLS",
}


class SdlsError(ValueError):
    def __init__(self, code: int):
        super().__init__(SEC_NAMES.get(code, f"code {code}"))
        self.code = code


def iv_from_counter(counter: int) -> bytes:
    return bytes(4) + counter.to_bytes(8, "big")


def iv_to_counter(iv: bytes) -> int:
    return int.from_bytes(iv[4:12], "big")


class SecurityAssociation:
    """SPI + key + last accepted IV (anti-replay)."""

    def __init__(self, spi: int, key: bytes):
        if len(key) != KEY_LEN:
            raise ValueError("the AES-256 key must be 32 bytes")
        self.spi = spi
        self.aead = AESGCM(key)
        self.last_iv = bytes(IV_LEN)

    def set_key(self, key: bytes) -> None:
        """Rotation: changes the key and keeps the anti-replay state."""
        if len(key) != KEY_LEN:
            raise ValueError("the AES-256 key must be 32 bytes")
        self.aead = AESGCM(key)


# ------------------------------ TC frames -------------------------------

def build_secure_tc_frame(sa: SecurityAssociation, packet: bytes, seq: int, iv_counter: int,
                          scid: int = SCID, vcid: int = VCID, bypass: bool = False,
                          control: bool = False) -> bytes:
    """Used by ground: Space Packet (or control command) -> encrypted and authenticated TC frame."""
    iv = iv_from_counter(iv_counter)
    sec_header = sa.spi.to_bytes(2, "big") + iv
    total = TC_HEADER_LEN + SEC_HEADER_LEN + len(packet) + MAC_LEN + FECF_LEN
    length = total - 1
    header = bytes([
        (int(bypass) << 5) | (int(control) << 4) | ((scid >> 8) & 0x03),
        scid & 0xFF,
        ((vcid & 0x3F) << 2) | ((length >> 8) & 0x03),
        length & 0xFF,
        seq & 0xFF,
    ])
    sealed = sa.aead.encrypt(iv, packet, header + sec_header)  # = ciphertext + MAC (16)
    body = header + sec_header + sealed
    crc = crc16(body)
    return body + bytes([crc >> 8, crc & 0xFF])


@dataclass
class SecureTc:
    frame: frames.TcFrame
    spi: int
    iv: bytes
    packet: bytes          # decrypted Space Packet


def process_secure_tc(sa: SecurityAssociation, buf: bytes) -> SecureTc:
    """What the satellite does (used by the simulator and the tests)."""
    f = frames.parse_tc_frame(buf)   # CcsdsError if the frame is bad
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


# ------------------------------ TM frames -------------------------------

def build_secure_tm_frame(sa: SecurityAssociation, packet: bytes, mc_count: int, vc_count: int,
                          report_value: int, iv_counter: int) -> bytes:
    """What the satellite does (used by the simulator and the tests)."""
    rest = TM_SDLS_DATA_LEN - len(packet)
    if rest < 0 or 0 < rest < SP_HEADER_LEN + 1:
        raise CcsdsError("packet does not fit in the frame")
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
    """Used by ground: checks, decrypts and takes the packets out of a TM frame."""
    if len(buf) != TM_FRAME_LEN:
        raise CcsdsError(f"a TM frame must be {TM_FRAME_LEN} bytes")
    if crc16(buf[:-2]) != (buf[-2] << 8) | buf[-1]:
        raise CcsdsError("bad CRC")
    if buf[0] >> 6 != 0:
        raise CcsdsError("wrong version")
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


# ---------------------------- Key management (OTAR) ----------------------------

OTAR_BLOCK_LEN = IV_LEN + 2 * KEY_LEN + MAC_LEN   # 92


def _otar_aad(key_id: int) -> bytes:
    return b"OTAR" + SCID.to_bytes(2, "big") + bytes([key_id & 0xFF])


def otar_wrap(kek: bytes, key_id: int, tc_key: bytes, tm_key: bytes, iv: bytes = None) -> bytes:
    """Wraps the new keys with the master key: [IV 12][ciphertext 64][MAC 16]."""
    import os
    iv = iv or os.urandom(IV_LEN)
    return iv + AESGCM(kek).encrypt(iv, tc_key + tm_key, _otar_aad(key_id))


def otar_unwrap(kek: bytes, key_id: int, block: bytes) -> tuple:
    if len(block) != OTAR_BLOCK_LEN:
        raise ValueError("OTAR block has wrong length")
    keys = AESGCM(kek).decrypt(block[:IV_LEN], block[IV_LEN:], _otar_aad(key_id))  # InvalidTag if not
    return keys[:KEY_LEN], keys[KEY_LEN:]


def kek_fingerprint(kek: bytes) -> bytes:
    return AESGCM(kek).encrypt(bytes(IV_LEN), bytes(16), b"FP")[16:24]
