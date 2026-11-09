"""
Satelite simulado en Python - fase 3 (SDLS + OTAR + FARM-1 + limite de eventos).

Reproduce en el PC el comportamiento de satellite/satellite_f3/satellite_f3.ino.
Arranca con la KEK y las claves activas de ground/keys_f3.json.

Uso:
    py tools\\fake_satellite_f3.py
    py ground\\gs_f3.py --sat 127.0.0.1
"""

import argparse
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ground"))

from cryptography.exceptions import InvalidTag  # noqa: E402

from ccsds import cop1, frames, sdls, services  # noqa: E402
from ccsds.frames import CcsdsError  # noqa: E402
from ccsds.keystore import KeysMissing, KeyStoreF3  # noqa: E402
from ccsds.sdls import SdlsError  # noqa: E402

EVENT_BURST = 3
EVENT_REFILL_S = 1.0


class FakeSatellite:
    def __init__(self, kek: bytes, tc_key: bytes, tm_key: bytes, key_id: int = 1, port: int = 10025,
                 bind: str = "127.0.0.1", verbose: bool = True):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((bind, port))
        self.sock.settimeout(0.05)
        self.verbose = verbose
        self.kek = kek
        self.tc_sa = sdls.SecurityAssociation(sdls.SPI_TC, tc_key)
        self.tm_sa = sdls.SecurityAssociation(sdls.SPI_TM, tm_key)
        self.key_id = key_id
        self.pending = None
        self.farm = cop1.Farm()
        self.tm_iv = 0
        self.mc = self.vc = self.tm_seq = 0
        self.accepted = self.rejected = self.farm_discards = 0
        self.sec = {sdls.SEC_ERR_SPI: 0, sdls.SEC_ERR_MAC: 0, sdls.SEC_ERR_REPLAY: 0}
        self.tokens = EVENT_BURST
        self.suppressed = self.suppressed_pending = 0
        self.last_refill = time.time()
        self.payload = (0, 0, 0)
        self.ground = None
        self.start = time.time()
        self.last_hk = 0.0

    def log(self, msg):
        if self.verbose:
            print(msg)

    # ----------------------------- telemetria -----------------------------
    def send_tm(self, service, app=b""):
        if self.ground is None:
            return
        pkt = frames.build_space_packet(0, frames.APID_SAT, self.tm_seq, bytes(service) + app)
        self.tm_seq = (self.tm_seq + 1) & 0x3FFF
        self.tm_iv += 1
        frame = sdls.build_secure_tm_frame(self.tm_sa, pkt, self.mc, self.vc, 0, self.tm_iv)
        # sustituimos la CLCW por la del FARM (y recalculamos el CRC)
        frame = bytearray(frame)
        frame[-6:-2] = self.farm.clcw().to_bytes(4, "big")
        crc = frames.crc16(bytes(frame[:-2]))
        frame[-2:] = bytes([crc >> 8, crc & 0xFF])
        self.mc = (self.mc + 1) & 0xFF
        self.vc = (self.vc + 1) & 0xFF
        self.sock.sendto(bytes(frame), self.ground)

    def ack(self, seq):
        self.send_tm(services.TM_ACK_OK, struct.pack(">H", seq))

    def nack(self, seq, code):
        self.send_tm(services.TM_ACK_FAIL, struct.pack(">HB", seq, code))

    def send_hk(self):
        s = self.sec
        app = struct.pack(services.HK_F3_FORMAT, int(time.time() - self.start), self.accepted, self.rejected,
                          s[sdls.SEC_ERR_SPI], s[sdls.SEC_ERR_MAC], s[sdls.SEC_ERR_REPLAY], self.farm_discards,
                          self.suppressed, *self.payload, -55, 200000, self.key_id)
        self.send_tm(services.TM_HK, app)

    def security_event(self, code, data, addr):
        if self.tokens == 0:
            self.suppressed += 1
            self.suppressed_pending += 1
            return
        self.tokens -= 1
        iv = sdls.iv_to_counter(data[7:19]) if code in (sdls.SEC_ERR_MAC, sdls.SEC_ERR_REPLAY) else 0
        self.send_tm(services.TM_SEC_EVENT,
                     struct.pack(services.SEC_EVENT_FORMAT, code, data[4], socket.inet_aton(addr[0]), addr[1], iv))

    def refill(self):
        if time.time() - self.last_refill < EVENT_REFILL_S:
            return
        self.last_refill = time.time()
        self.tokens = min(EVENT_BURST, self.tokens + 1)
        if self.suppressed_pending and self.tokens:
            self.tokens -= 1
            self.send_tm(services.TM_EVENTS_SUPPRESSED, struct.pack(">H", self.suppressed_pending))
            self.suppressed_pending = 0

    # ---------------------------- telecomandos ----------------------------
    def handle(self, data, addr):
        try:
            f = frames.parse_tc_frame(data)
            if f.scid != frames.SCID or f.vcid != frames.VCID:
                raise CcsdsError("SCID o canal ajeno")
        except CcsdsError:
            self.rejected += 1
            return
        try:
            tc = sdls.process_secure_tc(self.tc_sa, data)
        except SdlsError as e:
            code = sdls.SEC_ERR_SPI if e.code == sdls.SEC_ERR_LENGTH else e.code
            self.sec[code] += 1
            self.security_event(e.code, data, addr)
            return
        self.ground = addr

        if f.bypass and f.control:
            ok = self.farm.on_bc(tc.packet) == cop1.CONTROL_OK
            self.log(f"[SIM] BC: {'ok' if ok else 'no valido'}, V(R)={self.farm.vr}")
            return self.ack(0xFFFF) if ok else self.nack(0xFFFF, 32)
        if not f.bypass:
            r = self.farm.on_ad(f.seq)
            if r != cop1.ACCEPT:
                self.farm_discards += 1
                self.log(f"[SIM] FARM: N(S)={f.seq} {cop1.RESULT_NAMES[r]}")
                if r == cop1.DISCARD_AHEAD:
                    self.nack(0xFFFF, 30)
                elif r in (cop1.LOCKOUT, cop1.DISCARD_LOCKED):
                    self.nack(0xFFFF, 31)
                return
        else:
            self.farm.on_bd()
        self.execute(tc.packet)

    def execute(self, packet):
        try:
            p = frames.parse_space_packet(packet)
            if len(packet) != 6 + len(p.data) or p.type != 1 or p.apid != frames.APID_SAT or len(p.data) < 2:
                raise CcsdsError("paquete mal formado")
        except CcsdsError:
            self.rejected += 1
            return self.nack(0xFFFF, 10)
        service, app = (p.data[0], p.data[1]), p.data[2:]
        if service == services.TC_PING:
            self.send_tm(services.TM_PONG)
        elif service == services.TC_SET_COLOR and len(app) == 3:
            self.payload = tuple(app)
            self.log(f"[SIM] Carga util: color = {self.payload}")
            self.ack(p.seq_count)
        elif service == services.TC_REQUEST_HK:
            self.send_hk()
        elif service == services.TC_OTAR_UPLOAD:
            if len(app) != 1 + sdls.OTAR_BLOCK_LEN:
                self.rejected += 1
                return self.nack(p.seq_count, 12)
            if app[0] <= self.key_id:
                self.rejected += 1
                return self.nack(p.seq_count, 41)
            try:
                tc, tm = sdls.otar_unwrap(self.kek, app[0], app[1:])
            except InvalidTag:
                self.rejected += 1
                return self.nack(p.seq_count, 40)
            self.pending = (app[0], tc, tm)
            self.log(f"[SIM] OTAR: claves ID {app[0]} pendientes")
            self.ack(p.seq_count)
        elif service == services.TC_OTAR_ACTIVATE:
            if len(app) != 1 or not self.pending or self.pending[0] != app[0]:
                self.rejected += 1
                return self.nack(p.seq_count, 42)
            self.key_id, tc, tm = self.pending
            self.tc_sa.set_key(tc)
            self.tm_sa.set_key(tm)
            self.pending = None
            self.log(f"[SIM] Claves ID {self.key_id} activas")
            self.ack(p.seq_count)
        else:
            self.rejected += 1
            return self.nack(p.seq_count, 11 if service[0] != services.TC_SET_COLOR[0] else 12)
        self.accepted += 1

    def step(self):
        self.refill()
        if self.ground and time.time() - self.last_hk >= 5:
            self.last_hk = time.time()
            self.send_hk()
        try:
            data, addr = self.sock.recvfrom(2048)
        except (socket.timeout, ConnectionResetError):
            return
        except OSError:
            return
        self.handle(data, addr)

    def run(self):
        print(f"[SIM] Satelite simulado (fase 3) escuchando en {self.sock.getsockname()}, clave ID {self.key_id}")
        while True:
            self.step()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=10025)
    try:
        ks = KeyStoreF3()
    except KeysMissing as e:
        print(e)
        sys.exit(1)
    FakeSatellite(ks.kek, *ks.active(), key_id=ks.active_id, port=ap.parse_args().port).run()
