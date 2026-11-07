"""
Interoperabilidad SDLS: la pila C++ del satelite (mbedTLS) y la de tierra
(Python, cryptography) deben entenderse byte a byte.

Necesita build/sdls_cli (ver tests/native/sdls_cli.cpp). Si no existe, los
tests se saltan; en GitHub Actions se compila automaticamente.
"""

import os
import subprocess
import sys
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "ground"))

from ccsds import frames, sdls, services  # noqa: E402

CLI = os.environ.get("SDLS_CLI", os.path.join(ROOT, "build", "sdls_cli"))
KEY_TC = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
KEY_TM = bytes(reversed(KEY_TC))


def cli(*args) -> list:
    out = subprocess.run([CLI, *args], check=True, capture_output=True, text=True).stdout
    return out.strip().splitlines()


@unittest.skipUnless(os.path.exists(CLI), "falta build/sdls_cli")
class TestInteropSdls(unittest.TestCase):
    def setUp(self):
        self.ground = sdls.SecurityAssociation(sdls.SPI_TC, KEY_TC)
        self.pkt = services.build_tc_packet(services.TC_SET_COLOR, 77, bytes([255, 0, 0]))

    def tc(self, seq, iv, key=None):
        sa = self.ground if key is None else sdls.SecurityAssociation(sdls.SPI_TC, key)
        return sdls.build_secure_tc_frame(sa, self.pkt, seq=seq, iv_counter=iv).hex()

    def test_tc_de_python_lo_acepta_el_satelite(self):
        out = cli("tc", KEY_TC.hex(), "0", self.tc(200, 123456789))
        self.assertEqual(out, [f"OK 200 123456789 {self.pkt.hex()}"])

    def test_satelite_rechaza_replay_y_iv_viejo(self):
        a, b, c = self.tc(1, 10), self.tc(2, 11), self.tc(3, 5)
        out = cli("tc", KEY_TC.hex(), "0", a, a, b, c)
        self.assertEqual([line.split()[0] + (" " + line.split()[1] if line.startswith("SEC") else "")
                          for line in out], ["OK", "SEC 22", "OK", "SEC 22"])

    def test_satelite_rechaza_clave_falsa_y_trama_sin_sdls(self):
        forged = self.tc(1, 10**12, key=bytes(32))
        plain = frames.build_tc_frame(self.pkt, seq=1).hex()
        out = cli("tc", KEY_TC.hex(), "0", forged, plain, self.tc(2, 1))
        self.assertEqual(out[0], "SEC 21")
        self.assertEqual(out[1], "SEC 23")
        self.assertTrue(out[2].startswith("OK"), "la trama falsa no debe mover la ventana")

    def test_satelite_rechaza_manipulacion(self):
        frame = bytearray(bytes.fromhex(self.tc(1, 1)))
        frame[25] ^= 0x80
        crc = frames.crc16(bytes(frame[:-2]))
        frame[-2:] = bytes([crc >> 8, crc & 0xFF])
        self.assertEqual(cli("tc", KEY_TC.hex(), "0", bytes(frame).hex()), ["SEC 21"])

    def test_tm_del_satelite_la_entiende_python(self):
        raw = bytes.fromhex(cli("tm", KEY_TM.hex(), "999", "9", "0107002a", "3", "4", "201")[0])
        self.assertEqual(len(raw), 128)
        ground = sdls.SecurityAssociation(sdls.SPI_TM, KEY_TM)
        tm = sdls.parse_secure_tm_frame(ground, raw)
        self.assertEqual(sdls.iv_to_counter(tm.iv), 999)
        self.assertEqual((tm.frame.mc_count, tm.frame.vc_count, tm.frame.clcw.report_value), (3, 4, 201))
        self.assertEqual(services.decode_tm_packet(tm.frame.packets[0]),
                         "OK: telecomando (paquete #42) ejecutado")

    def test_tm_identica_byte_a_byte(self):
        sat = sdls.SecurityAssociation(sdls.SPI_TM, KEY_TM)
        pkt = frames.build_space_packet(0, 0x010, 9, bytes.fromhex("0107002a"))
        self.assertEqual(cli("tm", KEY_TM.hex(), "999", "9", "0107002a", "3", "4", "201")[0],
                         sdls.build_secure_tm_frame(sat, pkt, 3, 4, 201, iv_counter=999).hex())


if __name__ == "__main__":
    unittest.main()
