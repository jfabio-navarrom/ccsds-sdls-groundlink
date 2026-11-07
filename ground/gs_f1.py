"""
Consola de la estacion de tierra - fase 1 (CCSDS, SIN seguridad).

Envia telecomandos como tramas TC CCSDS reales y muestra la telemetria
(tramas TM) que devuelve el satelite.

Uso (en PowerShell, desde la carpeta del proyecto):
    py ground\\gs_f1.py --sat 192.168.33.105

Comandos dentro de la consola:
    ping              comprobar que el satelite responde
    color <nombre>    poner la carga util de un color (verde, azul, amarillo, blanco, apagado)
    hk                pedir un informe de housekeeping ahora
    estado            ver el ultimo housekeeping recibido
    ayuda             ver esta lista
    salir             cerrar la consola
"""

import argparse
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ccsds import frames, services  # noqa: E402
from ccsds.frames import CcsdsError  # noqa: E402

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
    def __init__(self, sat_ip: str, sat_port: int = TC_PORT, local_port: int = LOCAL_PORT):
        self.sat = (sat_ip, sat_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", local_port))
        self.sock.settimeout(0.5)
        self.frame_seq = 0      # N(S): numero de secuencia de trama TC
        self.packet_seq = 0     # contador de paquetes TC
        self.last_hk = None
        self.last_hk_time = None
        self.last_clcw = None
        self.running = True
        self.lock = threading.Lock()

    # ---------- envio ----------
    def send(self, service: tuple, app_data: bytes = b"") -> bytes:
        with self.lock:
            pkt = services.build_tc_packet(service, self.packet_seq, app_data)
            frame = frames.build_tc_frame(pkt, seq=self.frame_seq)
            self.packet_seq = (self.packet_seq + 1) & 0x3FFF
            self.frame_seq = (self.frame_seq + 1) & 0xFF
        self.sock.sendto(frame, self.sat)
        print(f"[AIRE] TC enviado ({len(frame)} bytes): {frame.hex()}")
        return frame

    # ---------- recepcion ----------
    def receive_loop(self, show_hk: bool = False):
        while self.running:
            try:
                data, _ = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except (ConnectionResetError, OSError):
                # En Windows, un ICMP "puerto inalcanzable" llega como error: lo ignoramos
                continue
            try:
                tm = frames.parse_tm_frame(data)
            except CcsdsError as e:
                print(f"\n[TM] trama descartada: {e}")
                continue
            self.last_clcw = tm.clcw
            for pkt in tm.packets:
                service = (pkt.data[0], pkt.data[1]) if len(pkt.data) >= 2 else None
                if service == services.TM_HK:
                    self.last_hk = services.decode_hk(pkt.data[2:])
                    self.last_hk_time = time.time()
                    if not show_hk:
                        continue
                print(f"\n[TM #{tm.mc_count}] {services.decode_tm_packet(pkt)}")

    def print_status(self):
        if self.last_hk is None:
            print("Todavia no ha llegado ningun housekeeping. Prueba con 'hk'.")
            return
        hk = self.last_hk
        age = time.time() - self.last_hk_time
        print(f"Ultimo HK (hace {age:.0f} s):")
        print(f"  tiempo encendido   {hk.uptime_s} s")
        print(f"  TC aceptados       {hk.tc_accepted}")
        print(f"  TC rechazados      {hk.tc_rejected}")
        print(f"  ultima secuencia   {hk.last_frame_seq}")
        print(f"  carga util (RGB)   {hk.payload_rgb}")
        print(f"  RSSI Wi-Fi         {hk.rssi_dbm} dBm")
        print(f"  memoria libre      {hk.free_heap} bytes")
        if self.last_clcw is not None:
            print(f"  CLCW: el satelite espera la trama #{self.last_clcw.report_value}")
        if age > 12:
            print("  AVISO: hace rato que no llega HK. ¿Alguien ha suplantado a la tierra?"
                  " Envia cualquier comando para recuperar la telemetria.")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Estacion de tierra (fase 1, CCSDS)")
    p.add_argument("--sat", required=True, help="IP del C5 (la ves en el Monitor Serie)")
    p.add_argument("--sat-port", type=int, default=TC_PORT, help=argparse.SUPPRESS)
    p.add_argument("--local-port", type=int, default=LOCAL_PORT, help=argparse.SUPPRESS)
    p.add_argument("--ver-hk", action="store_true", help="mostrar cada HK periodico (cada 5 s)")
    args = p.parse_args(argv)

    gs = GroundStation(args.sat, args.sat_port, args.local_port)
    threading.Thread(target=gs.receive_loop, args=(args.ver_hk,), daemon=True).start()

    print(f"Estacion de tierra lista. Satelite en {args.sat}:{args.sat_port}, SCID 0x{frames.SCID:03X}.")
    print("AVISO: fase 1, enlace SIN seguridad.")
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
        time.sleep(0.3)  # deja que llegue la respuesta antes del siguiente prompt

    gs.running = False
    print("Estacion de tierra cerrada.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
