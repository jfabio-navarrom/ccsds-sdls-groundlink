"""
Consola de la estacion de tierra - fase 2 (CCSDS + SDLS, AES-256-GCM).

Igual que gs_f1.py, pero cada TC sale cifrado y autenticado, y solo se
acepta telemetria que demuestre venir del satelite (MAC valida con la
clave TM). Ademas muestra los EVENTOS DE SEGURIDAD que envia el satelite
cuando rechaza una trama.

Antes de usarla, genera las claves:  py tools\\gen_keys_f2.py

Uso (en PowerShell, desde la carpeta del proyecto):
    py ground\\gs_f2.py --sat 192.168.33.105
"""

import argparse
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ccsds import sdls, services  # noqa: E402
from ccsds.frames import SCID, CcsdsError  # noqa: E402
from ccsds.keystore import IvCounter, KeysMissing, load_keys  # noqa: E402
from ccsds.sdls import SdlsError  # noqa: E402

TC_PORT = 10025
LOCAL_PORT = 10015

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
  salir             cerrar la consola"""


class GroundStation:
    def __init__(self, sat_ip: str, tc_key: bytes, tm_key: bytes, sat_port: int = TC_PORT,
                 local_port: int = LOCAL_PORT, iv_counter: IvCounter = None):
        self.sat = (sat_ip, sat_port)
        self.tc_sa = sdls.SecurityAssociation(sdls.SPI_TC, tc_key)
        self.tm_sa = sdls.SecurityAssociation(sdls.SPI_TM, tm_key)
        self.iv = iv_counter or IvCounter()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", local_port))
        self.sock.settimeout(0.5)
        self.frame_seq = 0
        self.packet_seq = 0
        self.last_hk = None
        self.last_hk_time = None
        self.last_clcw = None
        self.events = []
        self.discarded = 0
        self.running = True
        self.lock = threading.Lock()

    # ---------- envio ----------
    def send(self, service: tuple, app_data: bytes = b"") -> bytes:
        with self.lock:
            pkt = services.build_tc_packet(service, self.packet_seq, app_data)
            frame = sdls.build_secure_tc_frame(self.tc_sa, pkt, seq=self.frame_seq, iv_counter=self.iv.next())
            self.packet_seq = (self.packet_seq + 1) & 0x3FFF
            self.frame_seq = (self.frame_seq + 1) & 0xFF
        self.sock.sendto(frame, self.sat)
        print(f"[AIRE] TC cifrado enviado ({len(frame)} bytes): {frame.hex()}")
        return frame

    # ---------- recepcion ----------
    def handle_datagram(self, data: bytes, show_hk: bool = False):
        try:
            tm = sdls.parse_secure_tm_frame(self.tm_sa, data)
        except (CcsdsError, SdlsError) as e:
            self.discarded += 1
            print(f"\n[TM] trama descartada ({e}): no viene del satelite o esta manipulada")
            return
        self.last_clcw = tm.frame.clcw
        for pkt in tm.frame.packets:
            service = (pkt.data[0], pkt.data[1]) if len(pkt.data) >= 2 else None
            if service == services.TM_HK and len(pkt.data) - 2 == 23:
                self.last_hk = services.decode_hk_f2(pkt.data[2:])
                self.last_hk_time = time.time()
                if not show_hk:
                    continue
            if service == services.TM_SEC_EVENT:
                self.events.append(services.decode_sec_event(pkt.data[2:]))
                print(f"\n[SEGURIDAD] {services.decode_tm_packet(pkt)}")
                continue
            print(f"\n[TM #{tm.frame.mc_count}] {services.decode_tm_packet(pkt)}")

    def receive_loop(self, show_hk: bool = False):
        while self.running:
            try:
                data, _ = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except (ConnectionResetError, OSError):
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
        print(f"  TC aceptados         {hk.tc_accepted}")
        print(f"  tramas mal formadas  {hk.tc_rejected}")
        print(f"  rechazos seguridad   sin SDLS/SPI {hk.sec_spi} | MAC invalida {hk.sec_mac}"
              f" | replay {hk.sec_replay}")
        print(f"  carga util (RGB)     {hk.payload_rgb}")
        print(f"  RSSI Wi-Fi           {hk.rssi_dbm} dBm")
        print(f"  memoria libre        {hk.free_heap} bytes")
        if self.last_clcw is not None:
            print(f"  CLCW: el satelite espera la trama #{self.last_clcw.report_value}")
        if self.events:
            print(f"  eventos de seguridad recibidos en esta sesion: {len(self.events)}")
        if age > 12:
            print("  AVISO: hace rato que no llega HK. Comprueba que el satelite sigue encendido.")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Estacion de tierra (fase 2, CCSDS + SDLS)")
    p.add_argument("--sat", required=True, help="IP del C5 (la ves en el Monitor Serie)")
    p.add_argument("--sat-port", type=int, default=TC_PORT, help=argparse.SUPPRESS)
    p.add_argument("--local-port", type=int, default=LOCAL_PORT, help=argparse.SUPPRESS)
    p.add_argument("--ver-hk", action="store_true", help="mostrar cada HK periodico (cada 5 s)")
    args = p.parse_args(argv)

    try:
        tc_key, tm_key = load_keys()
    except KeysMissing as e:
        print(e)
        return 1
    try:
        gs = GroundStation(args.sat, tc_key, tm_key, args.sat_port, args.local_port)
    except OSError:
        print(f"El puerto {args.local_port} ya esta en uso: seguramente tienes otra consola de tierra"
              " abierta. Cierrala (escribe 'salir' o pulsa Ctrl+C) o usa otro puerto:"
              f" --local-port {args.local_port + 1}")
        return 1
    threading.Thread(target=gs.receive_loop, args=(args.ver_hk,), daemon=True).start()

    print(f"Estacion de tierra lista. Satelite en {args.sat}:{args.sat_port}, SCID 0x{SCID:03X}.")
    print("Fase 2: enlace protegido con SDLS (AES-256-GCM, anti-replay).")
    print(AYUDA)
    gs.send(services.TC_PING)

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
            gs.send(services.TC_PING)
        elif cmd == "hk":
            gs.send(services.TC_REQUEST_HK)
            time.sleep(0.5)
            gs.print_status()
        elif cmd == "estado":
            gs.print_status()
        elif cmd == "color" and len(parts) == 2 and parts[1] in COLORES:
            gs.send(services.TC_SET_COLOR, bytes(COLORES[parts[1]]))
        else:
            print("No entiendo ese comando. Escribe 'ayuda'.")
        time.sleep(0.3)

    gs.running = False
    print("Estacion de tierra cerrada.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
