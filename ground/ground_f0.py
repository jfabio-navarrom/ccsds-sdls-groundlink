"""
Ground station - phase 0 (NO security).

Sends telecommands over UDP to the "satellite" (ESP32-C5) and shows its answer.
It only uses the Python standard library: nothing to install.

Usage (in PowerShell, inside the project folder):
    py ground/ground_f0.py --sat 192.168.1.50 ping
    py ground/ground_f0.py --sat 192.168.1.50 led green
    py ground/ground_f0.py --sat 192.168.1.50 led off
"""

import argparse
import socket
import sys

TC_PORT = 10025

# Colors the ground station can put on the screen (the payload).
# Bright red is kept for the attacker in the demo.
COLORS = {
    "green": (0, 200, 0),
    "blue": (0, 90, 255),
    "yellow": (255, 200, 0),
    "white": (255, 255, 255),
    "off": (0, 0, 0),
}


def send_tc(ip: str, text: str, port: int = TC_PORT, timeout: float = 2.0):
    """Sends a telecommand and waits for the answer. Returns the text or None."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(text.encode("ascii"), (ip, port))
        try:
            data, _ = s.recvfrom(256)
            return data.decode("ascii", errors="replace")
        except (socket.timeout, ConnectionResetError):
            # On Windows, if nobody listens on that port, we get a
            # ConnectionResetError instead of a timeout
            return None


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Ground station (phase 0)")
    p.add_argument("--sat", required=True, help="IP of the C5 (you see it in the Serial Monitor)")
    p.add_argument("--port", type=int, default=TC_PORT, help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("ping", help="check that the satellite answers")
    led = sub.add_parser("led", help="change the screen color (payload)")
    led.add_argument("color", choices=sorted(COLORS))
    args = p.parse_args(argv)

    if args.cmd == "ping":
        tc = "PING"
    else:
        r, g, b = COLORS[args.color]
        tc = f"LED {r} {g} {b}"

    print(f"[GROUND] Sending TC -> {args.sat}:{args.port}  \"{tc}\"")
    answer = send_tc(args.sat, tc, port=args.port)
    if answer is None:
        print("[GROUND] No answer in 2 s. Check the IP, that the C5 is on "
              "and that both are on the same Wi-Fi.")
        return 1
    print(f"[GROUND] Satellite answer: {answer}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
