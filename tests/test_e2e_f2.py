"""
End to end test of phase 2 with the simulated satellite:
ground works as normal, and the four attacks fail and are reported.
"""

import io
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "ground"))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.join(ROOT, "attacks"))

import attack_f2  # noqa: E402
import fake_satellite_f2  # noqa: E402
import gs_f2  # noqa: E402
from ccsds import sdls, services  # noqa: E402
from ccsds.keystore import IvCounter  # noqa: E402

KEY_TC, KEY_TM = bytes(range(32)), bytes(range(1, 33))


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestEndToEndF2(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.sat_port = free_port()
        self.sat = fake_satellite_f2.FakeSatellite(KEY_TC, KEY_TM, port=self.sat_port)
        self.stop = False
        threading.Thread(target=self._run_sat, daemon=True).start()
        self.gs = gs_f2.GroundStation("127.0.0.1", KEY_TC, KEY_TM, self.sat_port, free_port(),
                                      IvCounter(os.path.join(self.tmp.name, "s.json")))
        threading.Thread(target=self.gs.receive_loop, daemon=True).start()
        attack_f2.send_and_listen.__defaults__ = (0.2,)

    def _run_sat(self):
        while not self.stop:
            self.sat.step()

    def tearDown(self):
        self.stop = True
        self.gs.running = False
        time.sleep(0.3)
        self.sat.sock.close()
        self.gs.sock.close()
        self.tmp.cleanup()

    def quiet(self, fn, *args):
        with redirect_stdout(io.StringIO()):
            return fn(*args)

    def wait_events(self, n):
        for _ in range(40):
            if len(self.gs.events) >= n:
                return
            time.sleep(0.05)

    def test_operation_and_attacks(self):
        sat = ["--sat", "127.0.0.1", "--port", str(self.sat_port)]
        self.quiet(self.gs.send, services.TC_PING)
        green = self.quiet(self.gs.send, services.TC_SET_COLOR, bytes([0, 200, 0]))
        time.sleep(0.3)
        self.assertEqual(self.sat.payload, (0, 200, 0))

        self.quiet(attack_f2.main, sat + ["inject"])
        self.quiet(attack_f2.main, sat + ["forge"])
        self.quiet(attack_f2.main, sat + ["replay", green.hex()])
        self.quiet(attack_f2.main, sat + ["tamper", green.hex()])
        self.wait_events(4)

        self.assertEqual(self.sat.payload, (0, 200, 0), "no attack should change the payload")
        self.assertEqual([e.code for e in self.gs.events],
                         [sdls.SEC_ERR_LENGTH, sdls.SEC_ERR_MAC, sdls.SEC_ERR_REPLAY, sdls.SEC_ERR_MAC])

        # Ground is still in control: the huge IV of 'forge' did not block the window
        self.quiet(self.gs.send, services.TC_SET_COLOR, bytes([0, 90, 255]))
        time.sleep(0.3)
        self.assertEqual(self.sat.payload, (0, 90, 255))
        self.assertEqual(self.sat.ground[1], self.gs.sock.getsockname()[1], "TM still goes to the ground station")


if __name__ == "__main__":
    unittest.main()
