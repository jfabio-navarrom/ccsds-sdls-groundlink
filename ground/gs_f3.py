"""
Consola de la estacion de tierra - fase 3 (SDLS + OTAR + COP-1).

Novedades respecto a gs_f2.py:
  - FOP (el lado de tierra de COP-1): cada telecomando lleva su N(S) y la
    consola espera a que la CLCW del satelite confirme que llego. Si no
    llega, lo retransmite (misma N(S), IV nuevo).
  - 'rotar': cambia las claves de trafico en vuelo (OTAR), sin reflashear.
  - 'sync': desbloquea el FARM y alinea los contadores (Unlock + Set V(R)).
  - --perdida 0.3: simula un canal que pierde el 30 % de los telecomandos.

Antes de usarla, genera las claves:  py tools\\gen_keys_f3.py

Uso (en PowerShell, desde la carpeta del proyecto):
    py ground\\gs_f3.py --sat 192.168.33.108
    py ground\\gs_f3.py --sat 192.168.33.108 --perdida 0.3
"""

import argparse
import os
import random
import secrets
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ccsds import cop1, sdls, services  # noqa: E402
from ccsds.frames import SCID, CcsdsError  # noqa: E402
from ccsds.keystore import STATE_F3_PATH, IvCounter, KeysMissing, KeyStoreF3  # noqa: E402
from ccsds.sdls import SdlsError  # noqa: E402

TC_PORT = 10025
LOCAL_PORT = 10015
FOP_TIMEOUT = 1.5     # segundos esperando la confirmacion de cada trama
FOP_TRIES = 4         # intentos por trama (1 + 3 retransmisiones)

COLORES = {
    "verde": (0, 200, 0),
    "azul": (0, 90, 255),
    "amarillo": (255, 200, 0),
    "blanco": (255, 255, 255),
    "apagado": (0, 0, 0),
}

AYUDA = """Comandos:
  ping              comprobar que el satelite responde
  color <nombre>    verde | azul | amarillo | blanco | apagado
  hk                pedir un informe de housekeeping ahora
  estado            ver el ultimo housekeeping recibido
  rotar             cambiar las claves de trafico en vuelo (OTAR)
  sync              desbloquear el FARM y alinear los contadores
  salir             cerrar la consola"""


class GroundStation:
    def __init__(self, sat_ip: str, keystore: KeyStoreF3, sat_port: int = TC_PORT,
                 local_port: int = LOCAL_PORT, iv_counter: IvCounter = None, loss: float = 0.0,
                 rng: random.Random = None, verbose: bool = True):
        self.sat = (sat_ip, sat_port)
        self.ks = keystore
        tc, tm = keystore.active()
        self.tc_sa = sdls.SecurityAssociation(sdls.SPI_TC, tc)
        self.tm_sa = sdls.SecurityAssociation(sdls.SPI_TM, tm)
        self.pending_tm_sa = None
        self.iv = iv_counter or IvCounter(STATE_F3_PATH)
        self.loss = loss
        self.rng = rng or random.Random()
        self.verbose = verbose
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", local_port))
        self.sock.settimeout(0.3)
        self.vs = 0             # V(S): N(S) de la siguiente trama AD
        self.packet_seq = 0
        self.cond = threading.Condition()
        self.tm_count = 0
        self.last_clcw = None
        self.acks = {}          # paquete -> (ok, codigo)
        self.last_hk = None
        self.last_hk_time = None
        self.events = []
        self.suppressed = 0
        self.retransmissions = 0
        self.running = True

    def log(self, msg: str):
        if self.verbose:
            print(msg)

    # ------------------------------ envio ------------------------------
    def _send_frame(self, data: bytes, ns: int, bypass=False, control=False) -> bytes:
        frame = sdls.build_secure_tc_frame(self.tc_sa, data, seq=ns, iv_counter=self.iv.next(),
                                           bypass=bypass, control=control)
        if self.loss and self.rng.random() < self.loss:
            self.log(f"[CANAL] trama N(S)={ns} perdida por el camino (simulado)")
            return frame
        self.sock.sendto(frame, self.sat)
        kind = "BC" if control else ("BD" if bypass else "AD")
        self.log(f"[AIRE] TC {kind} N(S)={ns} cifrado ({len(frame)} bytes): {frame.hex()}")
        return frame

    def _wait(self, predicate, timeout: float) -> bool:
        with self.cond:
            return self.cond.wait_for(predicate, timeout)

    def send_ad(self, service: tuple, app: bytes = b""):
        """FOP: envia una trama AD y la retransmite hasta que la CLCW la confirma.
        Devuelve el numero de paquete si se confirmo, o None."""
        pkt_seq = self.packet_seq
        self.packet_seq = (self.packet_seq + 1) & 0x3FFF
        pkt = services.build_tc_packet(service, pkt_seq, app)
        ns = self.vs
        for attempt in range(1, FOP_TRIES + 1):
            if attempt > 1:
                self.retransmissions += 1
                self.log(f"[FOP] Sin confirmacion de N(S)={ns}: retransmito (intento {attempt}, IV nuevo)")
            start = self.tm_count
            self._send_frame(pkt, ns)
            confirmed = self._wait(
                lambda: self.tm_count > start and self.last_clcw is not None and
                (self.last_clcw.report_value == (ns + 1) & 0xFF or self.last_clcw.lockout),
                FOP_TIMEOUT)
            if confirmed and self.last_clcw.lockout:
                self.log("[FOP] El FARM del satelite esta BLOQUEADO (lockout). Escribe 'sync'.")
                return None
            if confirmed:
                self.vs = (ns + 1) & 0xFF
                return pkt_seq
        self.log(f"[FOP] La trama N(S)={ns} no se confirmo tras {FOP_TRIES} intentos.")
        return None

    def send_bc(self, command: bytes) -> bool:
        """Comando de control del FARM (trama BC), esperando su confirmacion."""
        for _ in range(FOP_TRIES):
            start = self.tm_count
            self._send_frame(command, 0, bypass=True, control=True)
            if self._wait(lambda: self.tm_count > start and 0xFFFF in self.acks, FOP_TIMEOUT):
                ok, _ = self.acks.pop(0xFFFF)
                return ok
        return False

    def sync(self) -> bool:
        ok = self.send_bc(cop1.UNLOCK) and self.send_bc(cop1.set_vr(self.vs))
        self.log("[FOP] FARM desbloqueado y alineado: V(R) = %d" % self.vs if ok else
                 "[FOP] No se pudo sincronizar el FARM")
        return ok

    def wait_ack(self, pkt_seq, timeout: float = 2.0):
        if pkt_seq is None:
            return None
        if self._wait(lambda: pkt_seq in self.acks, timeout):
            return self.acks.pop(pkt_seq)
        return None

    # --------------------------- rotacion ------------------------------
    def rotate(self) -> bool:
        new_id = max([self.ks.active_id] + self.ks.data["retired"]) + 1
        tc_new, tm_new = secrets.token_bytes(32), secrets.token_bytes(32)
        self.ks.set_pending(new_id, tc_new, tm_new)   # guardadas antes de enviarlas
        block = sdls.otar_wrap(self.ks.kek, new_id, tc_new, tm_new)
        self.log(f"[OTAR] Subo las claves ID {new_id}, envueltas con la KEK ({len(block)} bytes)")
        ack = self.wait_ack(self.send_ad(services.TC_OTAR_UPLOAD, bytes([new_id]) + block))
        if not ack or not ack[0]:
            motivo = services.FAIL_CODES.get(ack[1], "") if ack else "sin respuesta"
            self.log(f"[OTAR] El satelite no acepto las claves: {motivo}")
            return False
        self.pending_tm_sa = sdls.SecurityAssociation(sdls.SPI_TM, tm_new)
        self.pending_tm_sa.last_iv = self.tm_sa.last_iv
        self.log(f"[OTAR] Claves recibidas a bordo. Las activo (ID {new_id})")
        ack = self.wait_ack(self.send_ad(services.TC_OTAR_ACTIVATE, bytes([new_id])))
        if not ack or not ack[0] or self.pending_tm_sa is not None:
            self.log("[OTAR] No se confirmo la activacion. Revisa 'estado'.")
            return False
        return True

    def _commit_rotation(self):
        """El satelite ya habla con la clave nueva: la tierra cambia tambien."""
        key_id, tc_new, tm_new = self.ks.pending()
        self.tm_sa.set_key(tm_new)
        self.tm_sa.last_iv = self.pending_tm_sa.last_iv
        self.tc_sa.set_key(tc_new)
        self.pending_tm_sa = None
        self.ks.activate_pending()
        self.log(f"[OTAR] Rotacion completada: clave ID {key_id} activa. La anterior queda retirada.")

    # ----------------------------- recepcion ---------------------------
    def handle_datagram(self, data: bytes, show_hk: bool = False):
        try:
            tm = sdls.parse_secure_tm_frame(self.tm_sa, data)
        except (CcsdsError, SdlsError) as first:
            if self.pending_tm_sa is None:
                self.log(f"\n[TM] trama descartada ({first}): no viene del satelite o esta manipulada")
                return
            try:
                tm = sdls.parse_secure_tm_frame(self.pending_tm_sa, data)
            except (CcsdsError, SdlsError):
                self.log(f"\n[TM] trama descartada ({first})")
                return
            self._commit_rotation()
        with self.cond:
            for pkt in tm.frame.packets:
                self._handle_packet(pkt, tm.frame.mc_count, show_hk)
            self.last_clcw = tm.frame.clcw
            self.tm_count += 1
            self.cond.notify_all()

    def _handle_packet(self, pkt, mc: int, show_hk: bool):
        service = (pkt.data[0], pkt.data[1]) if len(pkt.data) >= 2 else None
        app = pkt.data[2:]
        if service == services.TM_HK and len(app) == 27:
            self.last_hk = services.decode_hk_f3(app)
            self.last_hk_time = time.time()
            if not show_hk:
                return
        elif service == services.TM_ACK_OK:
            self.acks[int.from_bytes(app[:2], "big")] = (True, 0)
        elif service == services.TM_ACK_FAIL:
            self.acks[int.from_bytes(app[:2], "big")] = (False, app[2])
        elif service == services.TM_SEC_EVENT:
            self.events.append(services.decode_sec_event(app))
            self.log(f"\n[SEGURIDAD] {services.decode_tm_packet(pkt)}")
            return
        elif service == services.TM_EVENTS_SUPPRESSED:
            self.suppressed += int.from_bytes(app[:2], "big")
            self.log(f"\n[SEGURIDAD] {services.decode_tm_packet(pkt)}")
            return
        self.log(f"\n[TM #{mc}] {services.decode_tm_packet(pkt)}")

    def receive_loop(self, show_hk: bool = False):
        while self.running:
            try:
                data, _ = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except (ConnectionResetError, OSError):
                if not self.running:
                    return
                continue
            self.handle_datagram(data, show_hk)

    def print_status(self):
        if self.last_hk is None:
            print("Todavia no ha llegado ningun housekeeping. Prueba con 'hk'.")
            return
        hk = self.last_hk
        age = time.time() - self.last_hk_time
        print(f"Ultimo HK autenticado (hace {age:.0f} s):")
        print(f"  tiempo encendido     {hk.uptime_s} s")
        print(f"  clave activa         ID {hk.key_id} (tierra: ID {self.ks.active_id})")
        print(f"  TC aceptados         {hk.tc_accepted}")
        print(f"  tramas rotas         {hk.tc_rejected}")
        print(f"  descartes del FARM   {hk.farm_discards}")
        print(f"  rechazos seguridad   sin SDLS/SPI {hk.sec_spi} | MAC invalida {hk.sec_mac}"
              f" | replay {hk.sec_replay} | eventos resumidos {hk.events_suppressed}")
        print(f"  carga util (RGB)     {hk.payload_rgb}")
        print(f"  RSSI Wi-Fi           {hk.rssi_dbm} dBm")
        if self.last_clcw is not None:
            c = self.last_clcw
            estado = "BLOQUEADO" if c.lockout else ("pide retransmision" if c.retransmit else "normal")
            print(f"  FARM (CLCW)          espera N(S)={c.report_value}, estado {estado}")
        print(f"  FOP                  siguiente N(S)={self.vs}, retransmisiones {self.retransmissions}")
        if age > 12:
            print("  AVISO: hace rato que no llega HK. Comprueba que el satelite sigue encendido.")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Estacion de tierra (fase 3: SDLS + OTAR + COP-1)")
    p.add_argument("--sat", required=True, help="IP del C5 (la ves en el Monitor Serie)")
    p.add_argument("--sat-port", type=int, default=TC_PORT, help=argparse.SUPPRESS)
    p.add_argument("--local-port", type=int, default=LOCAL_PORT, help=argparse.SUPPRESS)
    p.add_argument("--ver-hk", action="store_true", help="mostrar cada HK periodico (cada 5 s)")
    p.add_argument("--perdida", type=float, default=0.0,
                   help="probabilidad de perder cada telecomando (0 a 0.9), para ver el FOP en accion")
    args = p.parse_args(argv)

    try:
        ks = KeyStoreF3()
    except KeysMissing as e:
        print(e)
        return 1
    try:
        gs = GroundStation(args.sat, ks, args.sat_port, args.local_port, loss=min(max(args.perdida, 0), 0.9))
    except OSError:
        print(f"El puerto {args.local_port} ya esta en uso: seguramente tienes otra consola de tierra"
              " abierta. Cierrala (escribe 'salir' o pulsa Ctrl+C) o usa otro puerto:"
              f" --local-port {args.local_port + 1}")
        return 1
    threading.Thread(target=gs.receive_loop, args=(args.ver_hk,), daemon=True).start()

    print(f"Estacion de tierra lista. Satelite en {args.sat}:{args.sat_port}, SCID 0x{SCID:03X}.")
    print(f"Fase 3: SDLS + OTAR + COP-1. Clave activa: ID {ks.active_id}.")
    if args.perdida:
        print(f"Canal simulado: se pierde el {args.perdida:.0%} de los telecomandos.")
    print(AYUDA)
    gs.sync()
    gs.send_ad(services.TC_PING)

    while True:
        try:
            line = input("\ntierra> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        parts = line.split()
        cmd = parts[0]
        if cmd == "salir":
            break
        elif cmd == "ayuda":
            print(AYUDA)
        elif cmd == "ping":
            gs.send_ad(services.TC_PING)
        elif cmd == "hk":
            gs.send_ad(services.TC_REQUEST_HK)
            time.sleep(0.3)
            gs.print_status()
        elif cmd == "estado":
            gs.print_status()
        elif cmd == "sync":
            gs.sync()
        elif cmd == "rotar":
            gs.rotate()
        elif cmd == "color" and len(parts) == 2 and parts[1] in COLORES:
            gs.send_ad(services.TC_SET_COLOR, bytes(COLORES[parts[1]]))
        else:
            print("No entiendo ese comando. Escribe 'ayuda'.")
        time.sleep(0.2)

    gs.running = False
    print("Estacion de tierra cerrada.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
