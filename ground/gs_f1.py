"""
Ground station console - phase 1 (CCSDS, NO security).

Sends telecommands as real CCSDS TC frames and shows the telemetry
(TM frames) that the satellite sends back.

Usage (in PowerShell, from the project folder):
    py ground\\gs_f1.py --sat 192.168.33.105

Commands inside the console:
    ping              check that the satellite answers
    color <name>      set the payload to a color (green, blue, yellow, white, off)
    hk                ask for a housekeeping report now
    status            show the last housekeeping received
    help              show this list
    quit              close the console
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

COLORS = {
    "green": (0, 200, 0),
    "blue": (0, 90, 255),
    "yellow": (255, 200, 0),
    "white": (255, 255, 255),
    "off": (0, 0, 0),
}

HELP = """Commands:
  ping              check that the satellite answers
  color <name>      green | blue | yellow | white | off
  hk                ask for a housekeeping report now
  status            show the last housekeeping received
  quit              close the console"""


class GroundStation:
    def __init__(self, sat_ip: str, sat_port: int = TC_PORT, local_port: int = LOCAL_PORT):
        self.sat = (sat_ip, sat_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", local_port))
        self.sock.settimeout(0.5)
        self.frame_seq = 0      # N(S): TC frame sequence number
        self.packet_seq = 0     # TC packet counter
        self.last_hk = None
        self.last_hk_time = None
        self.last_clcw = None
        self.running = True
        self.lock = threading.Lock()

    # ---------- sending ----------
    def send(self, service: tuple, app_data: bytes = b"") -> bytes:
        with self.lock:
            pkt = services.build_tc_packet(service, self.packet_seq, app_data)
            frame = frames.build_tc_frame(pkt, seq=self.frame_seq)
            self.packet_seq = (self.packet_seq + 1) & 0x3FFF
            self.frame_seq = (self.frame_seq + 1) & 0xFF
        self.sock.sendto(frame, self.sat)
        print(f"[AIR] TC sent ({len(frame)} bytes): {frame.hex()}")
        return frame

    # ---------- receiving ----------
    def receive_loop(self, show_hk: bool = False):
        while self.running:
            try:
                data, _ = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except (ConnectionResetError, OSError):
                # On Windows an ICMP "port unreachable" comes back as an error: ignore it
                continue
            try:
                tm = frames.parse_tm_frame(data)
            except CcsdsError as e:
                print(f"\n[TM] frame discarded: {e}")
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
            print("No housekeeping received yet. Try 'hk'.")
            return
        hk = self.last_hk
        age = time.time() - self.last_hk_time
        print(f"Last HK ({age:.0f} s ago):")
        print(f"  uptime             {hk.uptime_s} s")
        print(f"  TC accepted        {hk.tc_accepted}")
        print(f"  TC rejected        {hk.tc_rejected}")
        print(f"  last sequence      {hk.last_frame_seq}")
        print(f"  payload (RGB)      {hk.payload_rgb}")
        print(f"  Wi-Fi RSSI         {hk.rssi_dbm} dBm")
        print(f"  free heap          {hk.free_heap} bytes")
        if self.last_clcw is not None:
            print(f"  CLCW: the satellite expects frame #{self.last_clcw.report_value}")
        if age > 12:
            print("  WARNING: no HK for a while. Did someone impersonate the ground station?"
                  " Send any command to get the telemetry back.")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Ground station (phase 1, CCSDS)")
    p.add_argument("--sat", required=True, help="IP of the C5 (you see it in the Serial Monitor)")
    p.add_argument("--sat-port", type=int, default=TC_PORT, help=argparse.SUPPRESS)
    p.add_argument("--local-port", type=int, default=LOCAL_PORT, help=argparse.SUPPRESS)
    p.add_argument("--show-hk", action="store_true", help="show every periodic HK (every 5 s)")
    args = p.parse_args(argv)

    try:
        gs = GroundStation(args.sat, args.sat_port, args.local_port)
    except OSError:
        print(f"Port {args.local_port} is already in use: probably another ground console is"
              " open. Close it (type 'quit' or press Ctrl+C) or use another port:"
              f" --local-port {args.local_port + 1}")
        return 1
    threading.Thread(target=gs.receive_loop, args=(args.show_hk,), daemon=True).start()

    print(f"Ground station ready. Satellite at {args.sat}:{args.sat_port}, SCID 0x{frames.SCID:03X}.")
    print("WARNING: phase 1, link with NO security.")
    print(HELP)
    gs.send(services.TC_PING)

    while True:
        try:
            line = input("\nground> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        parts = line.split()
        cmd = parts[0]
        if cmd == "quit":
            break
        elif cmd == "help":
            print(HELP)
        elif cmd == "ping":
            gs.send(services.TC_PING)
        elif cmd == "hk":
            gs.send(services.TC_REQUEST_HK)
            time.sleep(0.5)
            gs.print_status()
        elif cmd == "status":
            gs.print_status()
        elif cmd == "color" and len(parts) == 2 and parts[1] in COLORS:
            gs.send(services.TC_SET_COLOR, bytes(COLORS[parts[1]]))
        else:
            print("I don't know that command. Type 'help'.")
        time.sleep(0.3)  # let the answer arrive before the next prompt

    gs.running = False
    print("Ground station closed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
