"""
End to end test of phase 3 with the simulated satellite:
FOP with losses, key rotation, leaked key, bypass and flood.
"""

import io
import os
import random
import socket
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
for sub in ("ground", "tools", "attacks"):
    sys.path.insert(0, os.path.join(ROOT, sub))

import attack_f3  # noqa: E402
import fake_satellite_f3  # noqa: E402
import gs_f3  # noqa: E402
from ccsds import sdls, services  # noqa: E402
from ccsds.keystore import IvCounter, KeyStoreF3  # noqa: E402

KEK, TC, TM = bytes(range(32)), bytes(range(1, 33)), bytes(range(2, 34))


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestEndToEndF3(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        path = os.path.join(self.tmp.name, "k.json")
        KeyStoreF3.create(path, KEK, TC, TM)
        self.port = free_port()
        self.sat = fake_satellite_f3.FakeSatellite(KEK, TC, TM, port=self.port, verbose=False)
        self.stop = False
        threading.Thread(target=self._run, daemon=True).start()
        self.gs = gs_f3.GroundStation("127.0.0.1", KeyStoreF3(path), self.port, free_port(),
                                      IvCounter(os.path.join(self.tmp.name, "s.json")), verbose=False)
        threading.Thread(target=self.gs.receive_loop, daemon=True).start()
        self.target = ["--sat", "127.0.0.1", "--port", str(self.port)]

    def _run(self):
        while not self.stop:
            self.sat.step()

    def tearDown(self):
        self.stop = True
        self.gs.running = False
        time.sleep(0.4)
        self.sat.sock.close()
        self.gs.sock.close()
        self.tmp.cleanup()

    def attack(self, *args):
        with redirect_stdout(io.StringIO()) as out:
            attack_f3.main(self.target + list(args))
        return out.getvalue()

    def test_fop_with_losses(self):
        self.assertTrue(self.gs.sync())
        self.gs.loss, self.gs.rng = 0.4, random.Random(3)
        for color in ([0, 200, 0], [0, 90, 255], [255, 200, 0], [255, 255, 255], [9, 9, 9]):
            self.assertIsNotNone(self.gs.send_ad(services.TC_SET_COLOR, bytes(color)))
        self.assertEqual(self.sat.payload, (9, 9, 9))
        self.assertGreater(self.gs.retransmissions, 0)
        self.assertEqual(self.sat.farm.vr, 5)

    def test_lockout_and_sync(self):
        self.gs.sync()
        self.gs.vs = 100   # ground out of sync (for example after a satellite reset)
        self.assertIsNone(self.gs.send_ad(services.TC_PING))
        self.assertTrue(self.sat.farm.lockout)
        self.assertTrue(self.gs.sync())
        self.assertIsNotNone(self.gs.send_ad(services.TC_PING))

    def test_rotation_and_leaked_key(self):
        self.gs.sync()
        self.assertIn("ACCEPTED", self.attack("leaked", TC.hex()))
        self.assertEqual(self.sat.payload, (255, 0, 0))
        self.assertIsNotNone(self.gs.send_ad(services.TC_PING))   # ground gets the link back
        self.assertTrue(self.gs.rotate())
        self.assertEqual((self.sat.key_id, self.gs.ks.active_id), (2, 2))
        self.assertIn("Rejected", self.attack("leaked", TC.hex()))
        self.assertIsNotNone(self.gs.send_ad(services.TC_SET_COLOR, bytes([0, 200, 0])))
        self.assertEqual(self.sat.payload, (0, 200, 0))

    def test_bypass_without_sdls(self):
        self.gs.sync()
        self.attack("bypass")
        time.sleep(0.3)
        self.assertEqual([e.code for e in self.gs.events], [sdls.SEC_ERR_LENGTH, sdls.SEC_ERR_LENGTH])
        self.assertEqual(self.sat.payload, (0, 0, 0))

    def test_flood(self):
        self.gs.sync()
        self.attack("flood", "--n", "200")
        self.assertIsNotNone(self.gs.send_ad(services.TC_SET_COLOR, bytes([0, 90, 255])))
        time.sleep(2.5)
        self.assertEqual(self.sat.payload, (0, 90, 255))
        self.assertLessEqual(len(self.gs.events), 3)
        self.assertEqual(len(self.gs.events) + self.gs.suppressed, self.sat.sec[sdls.SEC_ERR_MAC])
        self.assertGreater(self.gs.suppressed, 100)


if __name__ == "__main__":
    unittest.main()
