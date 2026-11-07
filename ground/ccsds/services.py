"""
Servicios "PUS-lite": el significado de los paquetes.

Inspirado en el Packet Utilization Standard de ECSS (ECSS-E-ST-70-41),
pero reducido al minimo: el campo de datos de cada Space Packet empieza
con 2 bytes (servicio, subservicio) seguidos de los datos de aplicacion.
"""

import struct
from dataclasses import dataclass

from .frames import APID_SAT, SpacePacket, build_space_packet

# Telecomandos (tierra -> satelite)
TC_PING = (17, 1)        # ¿estas vivo?
TC_SET_COLOR = (8, 1)    # carga util: poner la pantalla de un color (R, G, B)
TC_REQUEST_HK = (3, 27)  # pedir un informe de housekeeping ya

# Telemetria (satelite -> tierra)
TM_PONG = (17, 2)
TM_ACK_OK = (1, 7)       # telecomando ejecutado
TM_ACK_FAIL = (1, 2)     # telecomando rechazado (con codigo de motivo)
TM_HK = (3, 25)          # informe de housekeeping

FAIL_CODES = {
    1: "trama demasiado corta",
    2: "version incorrecta",
    3: "longitud incorrecta",
    4: "CRC incorrecto",
    5: "SCID de otro satelite",
    6: "canal virtual desconocido",
    10: "paquete mal formado",
    11: "servicio desconocido",
    12: "datos de aplicacion incorrectos",
}

HK_FORMAT = ">IHHB3BbI"   # uptime, TC aceptados, TC rechazados, ultima secuencia, R, G, B, RSSI, memoria libre


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
    """Traduce un paquete de telemetria a una frase legible."""
    if len(pkt.data) < 2:
        return f"paquete sin servicio (APID {pkt.apid:#x})"
    service = (pkt.data[0], pkt.data[1])
    app = pkt.data[2:]

    if service == TM_PONG:
        return "PONG: el satelite responde"
    if service == TM_ACK_OK and len(app) >= 2:
        seq = struct.unpack(">H", app[:2])[0]
        return f"OK: telecomando (paquete #{seq}) ejecutado"
    if service == TM_ACK_FAIL and len(app) >= 3:
        seq, code = struct.unpack(">HB", app[:3])
        motivo = FAIL_CODES.get(code, f"codigo {code}")
        quien = "trama" if seq == 0xFFFF else f"paquete #{seq}"
        return f"RECHAZADO: {quien}, motivo: {motivo}"
    if service == TM_HK and len(app) >= struct.calcsize(HK_FORMAT):
        hk = decode_hk(app)
        r, g, b = hk.payload_rgb
        return (f"HK: uptime {hk.uptime_s} s | TC aceptados {hk.tc_accepted} | "
                f"rechazados {hk.tc_rejected} | ultima secuencia {hk.last_frame_seq} | "
                f"carga util ({r},{g},{b}) | RSSI {hk.rssi_dbm} dBm | memoria libre {hk.free_heap} B")
    return f"servicio desconocido {service}"


def decode_hk(app: bytes) -> Housekeeping:
    up, ok, bad, seq, r, g, b, rssi, heap = struct.unpack(HK_FORMAT, app[:struct.calcsize(HK_FORMAT)])
    return Housekeeping(up, ok, bad, seq, (r, g, b), rssi, heap)
