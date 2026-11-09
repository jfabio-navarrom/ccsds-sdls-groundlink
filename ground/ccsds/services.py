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
TC_OTAR_UPLOAD = (24, 1)    # fase 3: subir claves nuevas envueltas con la KEK
TC_OTAR_ACTIVATE = (24, 2)  # fase 3: activar las claves subidas

# Telemetria (satelite -> tierra)
TM_PONG = (17, 2)
TM_ACK_OK = (1, 7)       # telecomando ejecutado
TM_ACK_FAIL = (1, 2)     # telecomando rechazado (con codigo de motivo)
TM_HK = (3, 25)          # informe de housekeeping
TM_SEC_EVENT = (5, 4)    # evento de seguridad (fase 2): el satelite rechazo una trama
TM_EVENTS_SUPPRESSED = (5, 5)  # fase 3: resumen de eventos no enviados (inundacion)

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
    20: "sin SDLS o SPI desconocido",
    21: "MAC invalida",
    22: "repeticion (replay)",
    23: "demasiado corta para SDLS",
    30: "FARM: trama adelantada, falta una anterior (retransmitir)",
    31: "FARM bloqueado (lockout): hace falta 'sync'",
    32: "comando de control del FARM no valido",
    40: "OTAR: el bloque de claves no se descifra con la KEK",
    41: "OTAR: el ID de clave no es mayor que el activo (rollback)",
    42: "OTAR: no hay claves pendientes con ese ID",
}

HK_FORMAT = ">IHHB3BbI"   # uptime, TC aceptados, TC rechazados, ultima secuencia, R, G, B, RSSI, memoria libre
# Fase 2: ademas, rechazos de seguridad por motivo (SPI, MAC, replay)
HK_F2_FORMAT = ">IHHHHHB3BbI"
# Evento de seguridad: codigo, N(S) de la trama, IP y puerto de origen, contador del IV
SEC_EVENT_FORMAT = ">BB4sHQ"
# Fase 3: + descartes del FARM, eventos suprimidos e ID de la clave activa
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
    """Traduce un paquete de telemetria a una frase legible."""
    if len(pkt.data) < 2:
        return f"paquete sin servicio (APID {pkt.apid:#x})"
    service = (pkt.data[0], pkt.data[1])
    app = pkt.data[2:]

    if service == TM_PONG:
        return "PONG: el satelite responde"
    if service == TM_ACK_OK and len(app) >= 2:
        seq = struct.unpack(">H", app[:2])[0]
        if seq == 0xFFFF:
            return "OK: comando de control del FARM ejecutado"
        return f"OK: telecomando (paquete #{seq}) ejecutado"
    if service == TM_ACK_FAIL and len(app) >= 3:
        seq, code = struct.unpack(">HB", app[:3])
        motivo = FAIL_CODES.get(code, f"codigo {code}")
        quien = "trama" if seq == 0xFFFF else f"paquete #{seq}"
        return f"RECHAZADO: {quien}, motivo: {motivo}"
    if service == TM_SEC_EVENT and len(app) >= struct.calcsize(SEC_EVENT_FORMAT):
        ev = decode_sec_event(app)
        return (f"EVENTO DE SEGURIDAD: trama rechazada ({ev.reason}) desde {ev.source}"
                f", N(S)={ev.frame_seq}, IV #{ev.iv_counter}")
    if service == TM_EVENTS_SUPPRESSED and len(app) >= 2:
        n = struct.unpack(">H", app[:2])[0]
        return f"INUNDACION: {n} eventos de seguridad mas, resumidos en este aviso"
    if service == TM_HK and len(app) == struct.calcsize(HK_F3_FORMAT):
        hk = decode_hk_f3(app)
        r, g, b = hk.payload_rgb
        return (f"HK: uptime {hk.uptime_s} s | TC aceptados {hk.tc_accepted} | rechazados {hk.tc_rejected}"
                f" | FARM descartes {hk.farm_discards} | seguridad: SPI {hk.sec_spi}, MAC {hk.sec_mac},"
                f" replay {hk.sec_replay} (suprimidos {hk.events_suppressed}) | clave ID {hk.key_id}"
                f" | carga util ({r},{g},{b})")
    if service == TM_HK and len(app) == struct.calcsize(HK_F2_FORMAT):
        hk = decode_hk_f2(app)
        r, g, b = hk.payload_rgb
        return (f"HK: uptime {hk.uptime_s} s | TC aceptados {hk.tc_accepted} | "
                f"rechazados {hk.tc_rejected} | seguridad: SPI {hk.sec_spi}, MAC {hk.sec_mac}, "
                f"replay {hk.sec_replay} | carga util ({r},{g},{b}) | RSSI {hk.rssi_dbm} dBm")
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
    return SecurityEvent(code, FAIL_CODES.get(code, f"codigo {code}"), seq,
                         f"{'.'.join(str(b) for b in ip)}:{port}", iv)


@dataclass
class HousekeepingF3(HousekeepingF2):
    farm_discards: int = 0
    events_suppressed: int = 0
    key_id: int = 0


def decode_hk_f3(app: bytes) -> HousekeepingF3:
    up, ok, bad, spi, mac, rep, farm, supp, r, g, b, rssi, heap, kid = struct.unpack(HK_F3_FORMAT, app)
    return HousekeepingF3(up, ok, bad, 0, (r, g, b), rssi, heap, spi, mac, rep, farm, supp, kid)
