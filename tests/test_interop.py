"""
Interoperabilidad: la pila C++ del satelite y la pila Python de tierra
deben entenderse byte a byte.

Necesita el binario build/ccsds_cli (ver tests/native/ccsds_cli.cpp). Si no
existe, los tests se saltan; en GitHub Actions se compila automaticamente.
"""

import os
import subprocess
import sys
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "ground"))

from ccsds import frames, services  # noqa: E402

CLI = os.environ.get("CCSDS_CLI", os.path.join(ROOT, "build", "ccsds_cli"))


def cli(*args) -> str:
    return subprocess.run([CLI, *args], check=True, capture_output=True, text=True).stdout.strip()


@unittest.skipUnless(os.path.exists(CLI), "falta build/ccsds_cli")
class TestInterop(unittest.TestCase):
    def test_crc_igual_en_ambos_lados(self):
        for data in (b"123456789", b"\x00", bytes(range(200))):
            self.assertEqual(int(cli("crc", data.hex()), 16), frames.crc16(data))

    def test_tc_de_python_lo_entiende_el_satelite(self):
        pkt = services.build_tc_packet(services.TC_SET_COLOR, 77, bytes([255, 0, 0]))
        frame = frames.build_tc_frame(pkt, seq=200)
        out = cli("tc", frame.hex()).split()
        self.assertEqual(out[:8], ["OK", "0", str(0x0C5), "0", "200", "1", str(0x010), "77"])
        self.assertEqual(out[8], "0801ff0000")

    def test_satelite_rechaza_tramas_mal_formadas(self):
        pkt = services.build_tc_packet(services.TC_PING, 1)
        good = frames.build_tc_frame(pkt, seq=1)
        corrupt = bytearray(good)
        corrupt[6] ^= 0xFF
        other_sat = frames.build_tc_frame(pkt, seq=1, scid=0x123)
        self.assertEqual(cli("tc", bytes(corrupt).hex()), "ERR 4")      # CRC
        self.assertEqual(cli("tc", other_sat.hex()), "ERR 5")           # SCID
        self.assertEqual(cli("tc", good[:-1].hex()), "ERR 3")           # longitud

    def test_tm_del_satelite_la_entiende_python(self):
        raw = bytes.fromhex(cli("tm", "9", "0107002a", "3", "4", "201"))
        self.assertEqual(len(raw), 128)
        tm = frames.parse_tm_frame(raw)
        self.assertEqual((tm.mc_count, tm.vc_count, tm.clcw.report_value), (3, 4, 201))
        self.assertEqual(tm.packets[0].seq_count, 9)
        self.assertEqual(services.decode_tm_packet(tm.packets[0]),
                         "OK: telecomando (paquete #42) ejecutado")

    def test_tm_identica_byte_a_byte(self):
        pkt = frames.build_space_packet(0, 0x010, 9, bytes.fromhex("0107002a"))
        self.assertEqual(cli("tm", "9", "0107002a", "3", "4", "201"),
                         frames.build_tm_frame(pkt, 3, 4, 201).hex())


if __name__ == "__main__":
    unittest.main()
