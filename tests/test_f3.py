"""
Tests de la fase 3: FARM-1, OTAR (rotacion de claves) e interoperabilidad
con la implementacion C++ del satelite (build/f3_cli, si existe).
"""

import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "ground"))

from cryptography.exceptions import InvalidTag  # noqa: E402

from ccsds import cop1, frames, sdls  # noqa: E402
from ccsds.keystore import KeyStoreF3  # noqa: E402

CLI = os.environ.get("F3_CLI", os.path.join(ROOT, "build", "f3_cli"))
KEK = bytes(range(100, 132))


class TestFarm(unittest.TestCase):
    def test_en_orden(self):
        f = cop1.Farm()
        self.assertEqual([f.on_ad(i) for i in range(3)], [cop1.ACCEPT] * 3)
        self.assertEqual(f.vr, 3)

    def test_hueco_pide_retransmision(self):
        f = cop1.Farm()
        f.on_ad(0)
        self.assertEqual(f.on_ad(2), cop1.DISCARD_AHEAD)
        self.assertTrue(frames.parse_clcw(f.clcw()).retransmit)
        self.assertEqual(f.on_ad(1), cop1.ACCEPT)
        self.assertFalse(frames.parse_clcw(f.clcw()).retransmit)

    def test_duplicado_y_lockout(self):
        f = cop1.Farm()
        f.on_ad(0)
        self.assertEqual(f.on_ad(0), cop1.DISCARD_DUPLICATE)
        self.assertEqual(f.on_ad(100), cop1.LOCKOUT)
        self.assertEqual(f.on_ad(1), cop1.DISCARD_LOCKED)
        self.assertEqual(f.on_bc(cop1.set_vr(5)), cop1.CONTROL_BAD)   # Set V(R) no vale con lockout
        self.assertEqual(f.on_bc(cop1.UNLOCK), cop1.CONTROL_OK)
        self.assertEqual(f.on_bc(cop1.set_vr(5)), cop1.CONTROL_OK)
        self.assertEqual(f.on_ad(5), cop1.ACCEPT)

    def test_vuelta_del_contador(self):
        f = cop1.Farm(vr=255)
        self.assertEqual(f.on_ad(255), cop1.ACCEPT)
        self.assertEqual(f.vr, 0)
        self.assertEqual(f.on_ad(255), cop1.DISCARD_DUPLICATE)


class TestOtar(unittest.TestCase):
    def test_ida_y_vuelta(self):
        tc, tm = os.urandom(32), os.urandom(32)
        block = sdls.otar_wrap(KEK, 2, tc, tm)
        self.assertEqual(len(block), sdls.OTAR_BLOCK_LEN)
        self.assertEqual(sdls.otar_unwrap(KEK, 2, block), (tc, tm))

    def test_id_autenticado(self):
        block = sdls.otar_wrap(KEK, 2, bytes(32), bytes(32))
        with self.assertRaises(InvalidTag):
            sdls.otar_unwrap(KEK, 3, block)   # no se puede reetiquetar como otra ID

    def test_rotar_conserva_anti_replay(self):
        sat = sdls.SecurityAssociation(sdls.SPI_TC, bytes(32))
        gnd = sdls.SecurityAssociation(sdls.SPI_TC, bytes(32))
        old = sdls.build_secure_tc_frame(gnd, b"\x10\x10\xc0\x00\x00\x01\x11\x01", 0, 100)
        sdls.process_secure_tc(sat, old)
        sat.set_key(KEK)
        gnd.set_key(KEK)
        with self.assertRaises(sdls.SdlsError):     # la clave vieja ya no sirve
            sdls.process_secure_tc(sat, old)
        new = sdls.build_secure_tc_frame(gnd, b"\x10\x10\xc0\x00\x00\x01\x11\x01", 1, 101)
        sdls.process_secure_tc(sat, new)

    def test_keystore(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "k.json")
            KeyStoreF3.create(path, KEK, bytes(32), bytes([1]) * 32)
            ks = KeyStoreF3(path)
            ks.set_pending(2, bytes([2]) * 32, bytes([3]) * 32)
            self.assertEqual(KeyStoreF3(path).pending()[0], 2)
            ks.activate_pending()
            ks = KeyStoreF3(path)
            self.assertEqual((ks.active_id, ks.data["retired"], ks.pending()), (2, [1], None))
            self.assertEqual(ks.active()[0], bytes([2]) * 32)


def cli(*args):
    return subprocess.run([CLI, *args], check=True, capture_output=True, text=True).stdout.strip().splitlines()


@unittest.skipUnless(os.path.exists(CLI), "falta build/f3_cli")
class TestInteropF3(unittest.TestCase):
    def test_farm_identico(self):
        ops = ["ad:0", "ad:2", "ad:1", "ad:1", "ad:200", "bc:820005", "bc:00", "bc:820005", "ad:5", "bd", "bc:99"]
        f = cop1.Farm()
        expected = []
        for op in ops:
            if op.startswith("ad:"):
                r = f.on_ad(int(op[3:]))
            elif op == "bd":
                r = f.on_bd()
            else:
                r = f.on_bc(bytes.fromhex(op[3:]))
            expected.append(f"{r} {f.clcw():08x}")
        self.assertEqual(cli("farm", *ops), expected)

    def test_otar_de_python_lo_abre_el_satelite(self):
        tc, tm = os.urandom(32), os.urandom(32)
        block = sdls.otar_wrap(KEK, 7, tc, tm)
        self.assertEqual(cli("otar", KEK.hex(), "7", block.hex()), [f"OK {tc.hex()} {tm.hex()}"])
        self.assertEqual(cli("otar", KEK.hex(), "8", block.hex()), ["ERR"])
        self.assertEqual(cli("otar", bytes(32).hex(), "7", block.hex()), ["ERR"])

    def test_huella_kek(self):
        self.assertEqual(cli("fp", KEK.hex()), [sdls.kek_fingerprint(KEK).hex()])


if __name__ == "__main__":
    unittest.main()
