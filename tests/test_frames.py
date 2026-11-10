"""Tests of the ground CCSDS stack. Run: py -m unittest discover -s tests"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ground"))

from ccsds import frames, services  # noqa: E402
from ccsds.frames import CcsdsError  # noqa: E402


class TestCrc(unittest.TestCase):
    def test_standard_check_value(self):
        # CRC-16/CCITT-FALSE of "123456789" is 0x29B1
        self.assertEqual(frames.crc16(b"123456789"), 0x29B1)


class TestSpacePacket(unittest.TestCase):
    def test_round_trip(self):
        raw = frames.build_space_packet(1, 0x010, 42, b"\x11\x01\xff\x00\x00")
        self.assertEqual(len(raw), 6 + 5)
        p = frames.parse_space_packet(raw)
        self.assertEqual((p.type, p.apid, p.seq_count, p.seq_flags), (1, 0x010, 42, 0b11))
        self.assertEqual(p.data, b"\x11\x01\xff\x00\x00")

    def test_known_header(self):
        raw = frames.build_space_packet(1, 0x010, 1, b"\x11\x01")
        self.assertEqual(raw[:6].hex(), "1010c0010001")


class TestTcFrame(unittest.TestCase):
    def setUp(self):
        self.pkt = services.build_tc_packet(services.TC_SET_COLOR, 7, bytes([0, 200, 0]))
        self.frame = frames.build_tc_frame(self.pkt, seq=3)

    def test_header(self):
        # version 00, bypass 0, control 0, SCID 0x0C5, VCID 0, length-1, sequence 3
        self.assertEqual(self.frame[:5].hex(), "00c5001103")
        self.assertEqual(len(self.frame), 5 + 11 + 2)

    def test_round_trip(self):
        f = frames.parse_tc_frame(self.frame)
        self.assertEqual((f.scid, f.vcid, f.seq, f.bypass), (0x0C5, 0, 3, False))
        self.assertEqual(f.data, self.pkt)

    def test_crc_catches_one_changed_bit(self):
        bad = bytearray(self.frame)
        bad[8] ^= 0x01
        with self.assertRaises(CcsdsError):
            frames.parse_tc_frame(bytes(bad))


class TestTmFrame(unittest.TestCase):
    def test_full_frame(self):
        pkt = frames.build_space_packet(0, 0x010, 5, bytes([17, 2]))
        raw = frames.build_tm_frame(pkt, mc_count=9, vc_count=9, report_value=4)
        self.assertEqual(len(raw), 128)
        tm = frames.parse_tm_frame(raw)
        self.assertEqual((tm.scid, tm.vcid, tm.mc_count), (0x0C5, 0, 9))
        self.assertEqual(len(tm.packets), 1)  # the idle packet does not count
        self.assertEqual(tm.clcw.report_value, 4)
        self.assertEqual(services.decode_tm_packet(tm.packets[0]), "PONG: the satellite answers")

    def test_hk(self):
        app = bytes.fromhex("0000003c" "000c" "0002" "22" "00c800" "c4" "00030d40")
        pkt = frames.build_space_packet(0, 0x010, 1, bytes([3, 25]) + app)
        tm = frames.parse_tm_frame(frames.build_tm_frame(pkt, 0, 0, 0))
        hk = services.decode_hk(tm.packets[0].data[2:])
        self.assertEqual((hk.uptime_s, hk.tc_accepted, hk.tc_rejected), (60, 12, 2))
        self.assertEqual((hk.last_frame_seq, hk.payload_rgb, hk.rssi_dbm, hk.free_heap),
                         (0x22, (0, 200, 0), -60, 200000))


if __name__ == "__main__":
    unittest.main()
