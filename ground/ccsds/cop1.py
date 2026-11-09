"""
COP-1 (CCSDS 232.1-B), version simplificada.

- FARM: el lado del satelite (aqui en Python para el simulador y los tests;
  en la placa es satellite/satellite_f3/farm.cpp).
- Comandos de control (tramas BC) que usa el FOP de la tierra.

El FARM no es un mecanismo de seguridad: ordena y deduplica. La seguridad
la pone SDLS, que se aplica antes.
"""

from dataclasses import dataclass

WINDOW = 10
POS_WINDOW = WINDOW // 2
NEG_WINDOW = WINDOW // 2

ACCEPT, DISCARD_AHEAD, DISCARD_DUPLICATE, LOCKOUT, DISCARD_LOCKED, CONTROL_OK, CONTROL_BAD = range(7)

RESULT_NAMES = {
    ACCEPT: "aceptada",
    DISCARD_AHEAD: "adelantada: falta una trama, retransmitir",
    DISCARD_DUPLICATE: "repetida: ya se habia ejecutado",
    LOCKOUT: "fuera de ventana: FARM bloqueado (lockout)",
    DISCARD_LOCKED: "FARM bloqueado: hace falta Unlock",
    CONTROL_OK: "comando de control ejecutado",
    CONTROL_BAD: "comando de control no valido",
}

# Comandos de control (contenido de una trama BC)
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
