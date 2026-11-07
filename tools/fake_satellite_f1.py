"""
Satelite simulado en Python - fase 1.

Reproduce en el PC el comportamiento de satellite/satellite_f1/satellite_f1.ino.
Sirve para probar la consola de tierra y los ataques sin la placa, y lo usan
los tests automaticos.

Uso:
    py tools\\fake_satellite_f1.py
    py ground\\gs_f1.py --sat 127.0.0.1
"""

import argparse
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ground"))

from ccsds import frames, services  # noqa: E402
from ccsds.frames import CcsdsError  # noqa: E402

ERR_CODES = {"trama demasiado corta": 1, "version incorrecta": 2, "longitud incorrecta": 3,
             "CRC incorrecto": 4}


class FakeSatellite:
    def __init__(self, port: int = 10025, bind: str = "127.0.0.1"):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((bind, port))
        self.sock.settimeout(0.2)
        self.mc = self.vc = self.tm_seq = 0
        self.accepted = self.rejected = 0
        self.last_seq = 0
        self.payload = (0, 0, 0)
        self.ground = None
        self.start = time.time()
        self.last_hk = 0.0

    def send_tm(self, addr, service, app=b""):
        pkt = frames.build_space_packet(0, frames.APID_SAT, self.tm_seq, bytes(service) + app)
        self.tm_seq = (self.tm_seq + 1) & 0x3FFF
        frame = frames.build_tm_frame(pkt, self.mc, self.vc, (self.last_seq + 1) & 0xFF)
        self.mc = (self.mc + 1) & 0xFF
        self.vc = (self.vc + 1) & 0xFF
        self.sock.sendto(frame, addr)

    def send_hk(self):
        if self.ground is None:
            return
        app = struct.pack(services.HK_FORMAT, int(time.time() - self.start), self.accepted,
                          self.rejected, self.last_seq, *self.payload, -55, 200000)
        self.send_tm(self.ground, services.TM_HK, app)

    def reject(self, addr, pkt_seq, code, why):
        self.rejected += 1
        print(f"[SIM] TC rechazado: {why}")
        self.send_tm(addr, services.TM_ACK_FAIL, struct.pack(">HB", pkt_seq, code))

    def handle(self, data, addr):
        try:
            f = frames.parse_tc_frame(data)
        except CcsdsError as e:
            return self.reject(addr, 0xFFFF, ERR_CODES.get(str(e), 3), str(e))
        if f.scid != frames.SCID:
            return self.reject(addr, 0xFFFF, 5, "SCID de otro satelite")
        if f.vcid != frames.VCID:
            return self.reject(addr, 0xFFFF, 6, "canal virtual desconocido")
        try:
            p = frames.parse_space_packet(f.data)
            if len(f.data) != 6 + len(p.data) or p.type != 1 or p.apid != frames.APID_SAT or len(p.data) < 2:
                raise CcsdsError("paquete mal formado")
        except CcsdsError:
            return self.reject(addr, 0xFFFF, 10, "paquete mal formado")
        service, app = (p.data[0], p.data[1]), p.data[2:]
        if service == services.TC_SET_COLOR and len(app) != 3:
            return self.reject(addr, p.seq_count, 12, "color sin 3 bytes")
        if service not in (services.TC_PING, services.TC_SET_COLOR, services.TC_REQUEST_HK):
            return self.reject(addr, p.seq_count, 11, "servicio desconocido")

        self.accepted += 1
        self.last_seq = f.seq
        self.ground = addr
        print(f"[SIM] TC aceptado: trama #{f.seq}, servicio {service}, de {addr}")
        if service == services.TC_PING:
            self.send_tm(addr, services.TM_PONG)
        elif service == services.TC_SET_COLOR:
            self.payload = tuple(app)
            print(f"[SIM] Carga util: color = {self.payload}")
            self.send_tm(addr, services.TM_ACK_OK, struct.pack(">H", p.seq_count))
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
        print(f"[SIM] Satelite simulado escuchando en {self.sock.getsockname()}")
        while True:
            self.step()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=10025)
    FakeSatellite(ap.parse_args().port).run()
