"""
Satelite simulado en Python - fase 2 (CCSDS + SDLS).

Reproduce en el PC el comportamiento de satellite/satellite_f2/satellite_f2.ino
con las claves de ground/keys_f2.json. Sirve para practicar sin la placa y
lo usan los tests automaticos.

Diferencia con la placa: el estado anti-replay vive solo en memoria (la placa
lo guarda en la flash).

Uso:
    py tools\\fake_satellite_f2.py
    py ground\\gs_f2.py --sat 127.0.0.1
"""

import argparse
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ground"))

from ccsds import frames, sdls, services  # noqa: E402
from ccsds.frames import CcsdsError  # noqa: E402
from ccsds.keystore import KeysMissing, load_keys  # noqa: E402
from ccsds.sdls import SdlsError  # noqa: E402


class FakeSatellite:
    def __init__(self, tc_key: bytes, tm_key: bytes, port: int = 10025, bind: str = "127.0.0.1"):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((bind, port))
        self.sock.settimeout(0.2)
        self.tc_sa = sdls.SecurityAssociation(sdls.SPI_TC, tc_key)
        self.tm_sa = sdls.SecurityAssociation(sdls.SPI_TM, tm_key)
        self.tm_iv = 0
        self.mc = self.vc = self.tm_seq = 0
        self.accepted = self.rejected = 0
        self.sec = {sdls.SEC_ERR_SPI: 0, sdls.SEC_ERR_MAC: 0, sdls.SEC_ERR_REPLAY: 0}
        self.last_seq = 0
        self.payload = (0, 0, 0)
        self.ground = None
        self.start = time.time()
        self.last_hk = 0.0

    def send_tm(self, service, app=b""):
        if self.ground is None:
            return
        pkt = frames.build_space_packet(0, frames.APID_SAT, self.tm_seq, bytes(service) + app)
        self.tm_seq = (self.tm_seq + 1) & 0x3FFF
        self.tm_iv += 1
        frame = sdls.build_secure_tm_frame(self.tm_sa, pkt, self.mc, self.vc, (self.last_seq + 1) & 0xFF,
                                           self.tm_iv)
        self.mc = (self.mc + 1) & 0xFF
        self.vc = (self.vc + 1) & 0xFF
        self.sock.sendto(frame, self.ground)

    def send_hk(self):
        s = self.sec
        app = struct.pack(services.HK_F2_FORMAT, int(time.time() - self.start), self.accepted, self.rejected,
                          s[sdls.SEC_ERR_SPI], s[sdls.SEC_ERR_MAC], s[sdls.SEC_ERR_REPLAY],
                          self.last_seq, *self.payload, -55, 200000)
        self.send_tm(services.TM_HK, app)

    def handle(self, data, addr):
        try:
            frames.parse_tc_frame(data)
            if ((data[0] & 0x03) << 8 | data[1]) != frames.SCID or data[2] >> 2 != frames.VCID:
                raise CcsdsError("SCID o canal ajeno")
        except CcsdsError as e:
            self.rejected += 1
            print(f"[SIM] Trama descartada: {e}")
            return
        try:
            tc = sdls.process_secure_tc(self.tc_sa, data)
        except SdlsError as e:
            code = sdls.SEC_ERR_SPI if e.code == sdls.SEC_ERR_LENGTH else e.code
            self.sec[code] += 1
            iv = sdls.iv_to_counter(data[7:19]) if e.code in (sdls.SEC_ERR_MAC, sdls.SEC_ERR_REPLAY) else 0
            print(f"[SIM] SEGURIDAD: rechazada ({e}) desde {addr}. No se le responde.")
            ip = socket.inet_aton(addr[0])
            self.send_tm(services.TM_SEC_EVENT,
                         struct.pack(services.SEC_EVENT_FORMAT, e.code, data[4], ip, addr[1], iv))
            return

        self.ground = addr
        self.last_seq = tc.frame.seq
        try:
            p = frames.parse_space_packet(tc.packet)
            if len(tc.packet) != 6 + len(p.data) or p.type != 1 or p.apid != frames.APID_SAT or len(p.data) < 2:
                raise CcsdsError("paquete mal formado")
        except CcsdsError:
            self.rejected += 1
            return self.send_tm(services.TM_ACK_FAIL, struct.pack(">HB", 0xFFFF, 10))
        service, app = (p.data[0], p.data[1]), p.data[2:]
        if service == services.TC_SET_COLOR and len(app) != 3:
            self.rejected += 1
            return self.send_tm(services.TM_ACK_FAIL, struct.pack(">HB", p.seq_count, 12))
        if service not in (services.TC_PING, services.TC_SET_COLOR, services.TC_REQUEST_HK):
            self.rejected += 1
            return self.send_tm(services.TM_ACK_FAIL, struct.pack(">HB", p.seq_count, 11))

        self.accepted += 1
        print(f"[SIM] TC autenticado y aceptado: trama #{tc.frame.seq}, IV #{sdls.iv_to_counter(tc.iv)},"
              f" servicio {service}")
        if service == services.TC_PING:
            self.send_tm(services.TM_PONG)
        elif service == services.TC_SET_COLOR:
            self.payload = tuple(app)
            print(f"[SIM] Carga util: color = {self.payload}")
            self.send_tm(services.TM_ACK_OK, struct.pack(">H", p.seq_count))
        else:
            self.send_hk()

    def step(self):
        if self.ground and time.time() - self.last_hk >= 5:
            self.last_hk = time.time()
            self.send_hk()
        try:
            data, addr = self.sock.recvfrom(2048)
        except (socket.timeout, ConnectionResetError):
            return
        self.handle(data, addr)

    def run(self):
        print(f"[SIM] Satelite simulado (fase 2, SDLS) escuchando en {self.sock.getsockname()}")
        while True:
            self.step()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=10025)
    try:
        keys = load_keys()
    except KeysMissing as e:
        print(e)
        sys.exit(1)
    FakeSatellite(*keys, port=ap.parse_args().port).run()
