"""
Ground station console - phase 2 (CCSDS + SDLS, AES-256-GCM).

Same as gs_f1.py, but every TC goes out encrypted and authenticated, and
it only accepts telemetry that proves it comes from the satellite (valid
MAC with the TM key). It also shows the SECURITY EVENTS that the satellite
sends when it rejects a frame.

Before using it, generate the keys:  py tools\\gen_keys_f2.py

Usage (in PowerShell, from the project folder):
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

    # ---------- sending ----------
    def send(self, service: tuple, app_data: bytes = b"") -> bytes:
        with self.lock:
            pkt = services.build_tc_packet(service, self.packet_seq, app_data)
            frame = sdls.build_secure_tc_frame(self.tc_sa, pkt, seq=self.frame_seq, iv_counter=self.iv.next())
            self.packet_seq = (self.packet_seq + 1) & 0x3FFF
            self.frame_seq = (self.frame_seq + 1) & 0xFF
        self.sock.sendto(frame, self.sat)
        print(f"[AIR] encrypted TC sent ({len(frame)} bytes): {frame.hex()}")
        return frame

    # ---------- receiving ----------
    def handle_datagram(self, data: bytes, show_hk: bool = False):
        try:
            tm = sdls.parse_secure_tm_frame(self.tm_sa, data)
        except (CcsdsError, SdlsError) as e:
            self.discarded += 1
            print(f"\n[TM] frame discarded ({e}): not from the satellite, or modified")
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
                print(f"\n[SECURITY] {services.decode_tm_packet(pkt)}")
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
            print("No housekeeping received yet. Try 'hk'.")
            return
        hk = self.last_hk
        age = time.time() - self.last_hk_time
        print(f"Last authenticated HK ({age:.0f} s ago):")
        print(f"  uptime               {hk.uptime_s} s")
        print(f"  TC accepted          {hk.tc_accepted}")
        print(f"  bad frames           {hk.tc_rejected}")
        print(f"  security rejections  no SDLS/SPI {hk.sec_spi} | invalid MAC {hk.sec_mac}"
              f" | replay {hk.sec_replay}")
        print(f"  payload (RGB)        {hk.payload_rgb}")
        print(f"  Wi-Fi RSSI           {hk.rssi_dbm} dBm")
        print(f"  free heap            {hk.free_heap} bytes")
        if self.last_clcw is not None:
            print(f"  CLCW: the satellite expects frame #{self.last_clcw.report_value}")
        if self.events:
            print(f"  security events received in this session: {len(self.events)}")
        if age > 12:
            print("  WARNING: no HK for a while. Check that the satellite is still on.")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Ground station (phase 2, CCSDS + SDLS)")
    p.add_argument("--sat", required=True, help="IP of the C5 (you see it in the Serial Monitor)")
    p.add_argument("--sat-port", type=int, default=TC_PORT, help=argparse.SUPPRESS)
    p.add_argument("--local-port", type=int, default=LOCAL_PORT, help=argparse.SUPPRESS)
    p.add_argument("--show-hk", action="store_true", help="show every periodic HK (every 5 s)")
    args = p.parse_args(argv)

    try:
        tc_key, tm_key = load_keys()
    except KeysMissing as e:
        print(e)
        return 1
    try:
        gs = GroundStation(args.sat, tc_key, tm_key, args.sat_port, args.local_port)
    except OSError:
        print(f"Port {args.local_port} is already in use: probably another ground console is"
              " open. Close it (type 'quit' or press Ctrl+C) or use another port:"
              f" --local-port {args.local_port + 1}")
        return 1
    threading.Thread(target=gs.receive_loop, args=(args.show_hk,), daemon=True).start()

    print(f"Ground station ready. Satellite at {args.sat}:{args.sat_port}, SCID 0x{SCID:03X}.")
    print("Phase 2: link protected with SDLS (AES-256-GCM, anti-replay).")
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
        time.sleep(0.3)

    gs.running = False
    print("Ground station closed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
