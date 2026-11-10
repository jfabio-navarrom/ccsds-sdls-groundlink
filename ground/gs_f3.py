"""
Ground station console - phase 3 (SDLS + OTAR + COP-1).

New compared to gs_f2.py:
  - FOP (the ground side of COP-1): every telecommand has its N(S) and the
    console waits until the satellite CLCW confirms it arrived. If it does
    not arrive, it is sent again (same N(S), new IV).
  - 'rotate': changes the traffic keys in flight (OTAR), no reflash needed.
  - 'sync': unlocks the FARM and aligns the counters (Unlock + Set V(R)).
  - --loss 0.3: simulates a channel that loses 30 % of the telecommands.

Before using it, generate the keys:  py tools\\gen_keys_f3.py

Usage (in PowerShell, from the project folder):
    py ground\\gs_f3.py --sat 192.168.33.108
    py ground\\gs_f3.py --sat 192.168.33.108 --loss 0.3
"""

import argparse
import os
import random
import secrets
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ccsds import cop1, sdls, services  # noqa: E402
from ccsds.frames import SCID, CcsdsError  # noqa: E402
from ccsds.keystore import STATE_F3_PATH, IvCounter, KeysMissing, KeyStoreF3  # noqa: E402
from ccsds.sdls import SdlsError  # noqa: E402

TC_PORT = 10025
LOCAL_PORT = 10015
FOP_TIMEOUT = 1.5     # seconds waiting for the confirmation of each frame
FOP_TRIES = 4         # tries per frame (1 + 3 retransmissions)

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
  rotate            change the traffic keys in flight (OTAR)
  sync              unlock the FARM and align the counters
  quit              close the console"""


class GroundStation:
    def __init__(self, sat_ip: str, keystore: KeyStoreF3, sat_port: int = TC_PORT,
                 local_port: int = LOCAL_PORT, iv_counter: IvCounter = None, loss: float = 0.0,
                 rng: random.Random = None, verbose: bool = True):
        self.sat = (sat_ip, sat_port)
        self.ks = keystore
        tc, tm = keystore.active()
        self.tc_sa = sdls.SecurityAssociation(sdls.SPI_TC, tc)
        self.tm_sa = sdls.SecurityAssociation(sdls.SPI_TM, tm)
        self.pending_tm_sa = None
        self.iv = iv_counter or IvCounter(STATE_F3_PATH)
        self.loss = loss
        self.rng = rng or random.Random()
        self.verbose = verbose
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", local_port))
        self.sock.settimeout(0.3)
        self.vs = 0             # V(S): N(S) of the next AD frame
        self.packet_seq = 0
        self.cond = threading.Condition()
        self.tm_count = 0
        self.last_clcw = None
        self.acks = {}          # packet -> (ok, code)
        self.last_hk = None
        self.last_hk_time = None
        self.events = []
        self.suppressed = 0
        self.retransmissions = 0
        self.running = True

    def log(self, msg: str):
        if self.verbose:
            print(msg)

    # ------------------------------ sending ----------------------------
    def _send_frame(self, data: bytes, ns: int, bypass=False, control=False) -> bytes:
        frame = sdls.build_secure_tc_frame(self.tc_sa, data, seq=ns, iv_counter=self.iv.next(),
                                           bypass=bypass, control=control)
        if self.loss and self.rng.random() < self.loss:
            self.log(f"[CHANNEL] frame N(S)={ns} lost on the way (simulated)")
            return frame
        self.sock.sendto(frame, self.sat)
        kind = "BC" if control else ("BD" if bypass else "AD")
        self.log(f"[AIR] TC {kind} N(S)={ns} encrypted ({len(frame)} bytes): {frame.hex()}")
        return frame

    def _wait(self, predicate, timeout: float) -> bool:
        with self.cond:
            return self.cond.wait_for(predicate, timeout)

    def send_ad(self, service: tuple, app: bytes = b""):
        """FOP: sends an AD frame and retransmits it until the CLCW confirms it.
        Returns the packet number if confirmed, or None."""
        pkt_seq = self.packet_seq
        self.packet_seq = (self.packet_seq + 1) & 0x3FFF
        pkt = services.build_tc_packet(service, pkt_seq, app)
        ns = self.vs
        for attempt in range(1, FOP_TRIES + 1):
            if attempt > 1:
                self.retransmissions += 1
                self.log(f"[FOP] No confirmation for N(S)={ns}: sending again (try {attempt}, new IV)")
            start = self.tm_count
            self._send_frame(pkt, ns)
            confirmed = self._wait(
                lambda: self.tm_count > start and self.last_clcw is not None and
                (self.last_clcw.report_value == (ns + 1) & 0xFF or self.last_clcw.lockout),
                FOP_TIMEOUT)
            if confirmed and self.last_clcw.lockout:
                self.log("[FOP] The satellite FARM is in LOCKOUT. Type 'sync'.")
                return None
            if confirmed:
                self.vs = (ns + 1) & 0xFF
                return pkt_seq
        self.log(f"[FOP] Frame N(S)={ns} was not confirmed after {FOP_TRIES} tries.")
        return None

    def send_bc(self, command: bytes) -> bool:
        """FARM control command (BC frame), waiting for its confirmation."""
        for _ in range(FOP_TRIES):
            start = self.tm_count
            self._send_frame(command, 0, bypass=True, control=True)
            if self._wait(lambda: self.tm_count > start and 0xFFFF in self.acks, FOP_TIMEOUT):
                ok, _ = self.acks.pop(0xFFFF)
                return ok
        return False

    def sync(self) -> bool:
        ok = self.send_bc(cop1.UNLOCK) and self.send_bc(cop1.set_vr(self.vs))
        self.log("[FOP] FARM unlocked and aligned: V(R) = %d" % self.vs if ok else
                 "[FOP] Could not sync the FARM")
        return ok

    def wait_ack(self, pkt_seq, timeout: float = 2.0):
        if pkt_seq is None:
            return None
        if self._wait(lambda: pkt_seq in self.acks, timeout):
            return self.acks.pop(pkt_seq)
        return None

    # --------------------------- rotation ------------------------------
    def rotate(self) -> bool:
        new_id = max([self.ks.active_id] + self.ks.data["retired"]) + 1
        tc_new, tm_new = secrets.token_bytes(32), secrets.token_bytes(32)
        self.ks.set_pending(new_id, tc_new, tm_new)   # saved before sending them
        block = sdls.otar_wrap(self.ks.kek, new_id, tc_new, tm_new)
        self.log(f"[OTAR] Uploading keys ID {new_id}, wrapped with the KEK ({len(block)} bytes)")
        ack = self.wait_ack(self.send_ad(services.TC_OTAR_UPLOAD, bytes([new_id]) + block))
        if not ack or not ack[0]:
            reason = services.FAIL_CODES.get(ack[1], "") if ack else "no answer"
            self.log(f"[OTAR] The satellite did not accept the keys: {reason}")
            return False
        self.pending_tm_sa = sdls.SecurityAssociation(sdls.SPI_TM, tm_new)
        self.pending_tm_sa.last_iv = self.tm_sa.last_iv
        self.log(f"[OTAR] Keys received on board. Activating them (ID {new_id})")
        ack = self.wait_ack(self.send_ad(services.TC_OTAR_ACTIVATE, bytes([new_id])))
        if not ack or not ack[0] or self.pending_tm_sa is not None:
            self.log("[OTAR] Activation was not confirmed. Check 'status'.")
            return False
        return True

    def _commit_rotation(self):
        """The satellite already uses the new key: ground changes too."""
        key_id, tc_new, tm_new = self.ks.pending()
        self.tm_sa.set_key(tm_new)
        self.tm_sa.last_iv = self.pending_tm_sa.last_iv
        self.tc_sa.set_key(tc_new)
        self.pending_tm_sa = None
        self.ks.activate_pending()
        self.log(f"[OTAR] Rotation done: key ID {key_id} is active. The old one is retired.")

    # ----------------------------- receiving ---------------------------
    def handle_datagram(self, data: bytes, show_hk: bool = False):
        try:
            tm = sdls.parse_secure_tm_frame(self.tm_sa, data)
        except (CcsdsError, SdlsError) as first:
            if self.pending_tm_sa is None:
                self.log(f"\n[TM] frame discarded ({first}): not from the satellite, or modified")
                return
            try:
                tm = sdls.parse_secure_tm_frame(self.pending_tm_sa, data)
            except (CcsdsError, SdlsError):
                self.log(f"\n[TM] frame discarded ({first})")
                return
            self._commit_rotation()
        with self.cond:
            for pkt in tm.frame.packets:
                self._handle_packet(pkt, tm.frame.mc_count, show_hk)
            self.last_clcw = tm.frame.clcw
            self.tm_count += 1
            self.cond.notify_all()

    def _handle_packet(self, pkt, mc: int, show_hk: bool):
        service = (pkt.data[0], pkt.data[1]) if len(pkt.data) >= 2 else None
        app = pkt.data[2:]
        if service == services.TM_HK and len(app) == 27:
            self.last_hk = services.decode_hk_f3(app)
            self.last_hk_time = time.time()
            if not show_hk:
                return
        elif service == services.TM_ACK_OK:
            self.acks[int.from_bytes(app[:2], "big")] = (True, 0)
        elif service == services.TM_ACK_FAIL:
            self.acks[int.from_bytes(app[:2], "big")] = (False, app[2])
        elif service == services.TM_SEC_EVENT:
            self.events.append(services.decode_sec_event(app))
            self.log(f"\n[SECURITY] {services.decode_tm_packet(pkt)}")
            return
        elif service == services.TM_EVENTS_SUPPRESSED:
            self.suppressed += int.from_bytes(app[:2], "big")
            self.log(f"\n[SECURITY] {services.decode_tm_packet(pkt)}")
            return
        self.log(f"\n[TM #{mc}] {services.decode_tm_packet(pkt)}")

    def receive_loop(self, show_hk: bool = False):
        while self.running:
            try:
                data, _ = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except (ConnectionResetError, OSError):
                if not self.running:
                    return
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
        print(f"  active key           ID {hk.key_id} (ground: ID {self.ks.active_id})")
        print(f"  TC accepted          {hk.tc_accepted}")
        print(f"  broken frames        {hk.tc_rejected}")
        print(f"  FARM discards        {hk.farm_discards}")
        print(f"  security rejections  no SDLS/SPI {hk.sec_spi} | invalid MAC {hk.sec_mac}"
              f" | replay {hk.sec_replay} | summarized events {hk.events_suppressed}")
        print(f"  payload (RGB)        {hk.payload_rgb}")
        print(f"  Wi-Fi RSSI           {hk.rssi_dbm} dBm")
        if self.last_clcw is not None:
            c = self.last_clcw
            state = "LOCKOUT" if c.lockout else ("asks for retransmit" if c.retransmit else "normal")
            print(f"  FARM (CLCW)          expects N(S)={c.report_value}, state {state}")
        print(f"  FOP                  next N(S)={self.vs}, retransmissions {self.retransmissions}")
        if age > 12:
            print("  WARNING: no HK for a while. Check that the satellite is still on.")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Ground station (phase 3: SDLS + OTAR + COP-1)")
    p.add_argument("--sat", required=True, help="IP of the C5 (you see it in the Serial Monitor)")
    p.add_argument("--sat-port", type=int, default=TC_PORT, help=argparse.SUPPRESS)
    p.add_argument("--local-port", type=int, default=LOCAL_PORT, help=argparse.SUPPRESS)
    p.add_argument("--show-hk", action="store_true", help="show every periodic HK (every 5 s)")
    p.add_argument("--loss", type=float, default=0.0,
                   help="chance to lose each telecommand (0 to 0.9), to see the FOP working")
    args = p.parse_args(argv)

    try:
        ks = KeyStoreF3()
    except KeysMissing as e:
        print(e)
        return 1
    try:
        gs = GroundStation(args.sat, ks, args.sat_port, args.local_port, loss=min(max(args.loss, 0), 0.9))
    except OSError:
        print(f"Port {args.local_port} is already in use: probably another ground console is"
              " open. Close it (type 'quit' or press Ctrl+C) or use another port:"
              f" --local-port {args.local_port + 1}")
        return 1
    threading.Thread(target=gs.receive_loop, args=(args.show_hk,), daemon=True).start()

    print(f"Ground station ready. Satellite at {args.sat}:{args.sat_port}, SCID 0x{SCID:03X}.")
    print(f"Phase 3: SDLS + OTAR + COP-1. Active key: ID {ks.active_id}.")
    if args.loss:
        print(f"Simulated channel: {args.loss:.0%} of the telecommands are lost.")
    print(HELP)
    gs.sync()
    gs.send_ad(services.TC_PING)

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
            gs.send_ad(services.TC_PING)
        elif cmd == "hk":
            gs.send_ad(services.TC_REQUEST_HK)
            time.sleep(0.3)
            gs.print_status()
        elif cmd == "status":
            gs.print_status()
        elif cmd == "sync":
            gs.sync()
        elif cmd == "rotate":
            gs.rotate()
        elif cmd == "color" and len(parts) == 2 and parts[1] in COLORS:
            gs.send_ad(services.TC_SET_COLOR, bytes(COLORS[parts[1]]))
        else:
            print("I don't know that command. Type 'help'.")
        time.sleep(0.2)

    gs.running = False
    print("Ground station closed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
