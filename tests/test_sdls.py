"""SDLS tests (phase 2) of the ground stack. Run: py -m unittest discover -s tests"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ground"))

from ccsds import frames, sdls, services  # noqa: E402
from ccsds.frames import CcsdsError  # noqa: E402
from ccsds.keystore import IvCounter  # noqa: E402
from ccsds.sdls import SdlsError  # noqa: E402

KEY_TC = bytes(range(32))
KEY_TM = bytes(range(32, 64))


def color_packet(seq=1, rgb=(0, 200, 0)):
    return services.build_tc_packet(services.TC_SET_COLOR, seq, bytes(rgb))


class TestAesGcm(unittest.TestCase):
    def test_nist_vector_aes256_gcm(self):
        # NIST GCM test case 13 (AES-256, key, IV and plaintext all zero)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        tag = AESGCM(bytes(32)).encrypt(bytes(12), b"", None)
        self.assertEqual(tag.hex(), "530f8afbc74536b9a963b4f1c4cb738b")


class TestSecureTc(unittest.TestCase):
    def setUp(self):
        self.ground = sdls.SecurityAssociation(sdls.SPI_TC, KEY_TC)
        self.sat = sdls.SecurityAssociation(sdls.SPI_TC, KEY_TC)

    def test_round_trip(self):
        frame = sdls.build_secure_tc_frame(self.ground, color_packet(), seq=4, iv_counter=1000)
        self.assertEqual(len(frame), 5 + 14 + 11 + 16 + 2)
        tc = sdls.process_secure_tc(self.sat, frame)
        self.assertEqual(tc.packet, color_packet())
        self.assertEqual((tc.frame.seq, sdls.iv_to_counter(tc.iv)), (4, 1000))

    def test_packet_is_encrypted(self):
        frame = sdls.build_secure_tc_frame(self.ground, color_packet(), seq=1, iv_counter=1)
        self.assertNotIn(color_packet(), frame)
        self.assertNotIn(bytes([8, 1, 0, 200, 0]), frame)

    def test_replay_rejected(self):
        frame = sdls.build_secure_tc_frame(self.ground, color_packet(), seq=1, iv_counter=5)
        sdls.process_secure_tc(self.sat, frame)
        with self.assertRaises(SdlsError) as cm:
            sdls.process_secure_tc(self.sat, frame)
        self.assertEqual(cm.exception.code, sdls.SEC_ERR_REPLAY)

    def test_old_iv_rejected(self):
        new = sdls.build_secure_tc_frame(self.ground, color_packet(), seq=2, iv_counter=10)
        old = sdls.build_secure_tc_frame(self.ground, color_packet(), seq=1, iv_counter=9)
        sdls.process_secure_tc(self.sat, new)
        with self.assertRaises(SdlsError) as cm:
            sdls.process_secure_tc(self.sat, old)
        self.assertEqual(cm.exception.code, sdls.SEC_ERR_REPLAY)

    def test_tampering_with_new_crc(self):
        frame = bytearray(sdls.build_secure_tc_frame(self.ground, color_packet(), seq=1, iv_counter=1))
        frame[22] ^= 0x01                       # one bit of the ciphertext
        crc = frames.crc16(bytes(frame[:-2]))   # the attacker fixes the CRC
        frame[-2:] = bytes([crc >> 8, crc & 0xFF])
        with self.assertRaises(SdlsError) as cm:
            sdls.process_secure_tc(self.sat, bytes(frame))
        self.assertEqual(cm.exception.code, sdls.SEC_ERR_MAC)

    def test_header_is_authenticated(self):
        # Changing the N(S) in the header (in clear) also breaks the MAC
        frame = bytearray(sdls.build_secure_tc_frame(self.ground, color_packet(), seq=1, iv_counter=1))
        frame[4] = 99
        crc = frames.crc16(bytes(frame[:-2]))
        frame[-2:] = bytes([crc >> 8, crc & 0xFF])
        with self.assertRaises(SdlsError) as cm:
            sdls.process_secure_tc(self.sat, bytes(frame))
        self.assertEqual(cm.exception.code, sdls.SEC_ERR_MAC)

    def test_wrong_key(self):
        attacker = sdls.SecurityAssociation(sdls.SPI_TC, bytes(32))
        frame = sdls.build_secure_tc_frame(attacker, color_packet(), seq=1, iv_counter=10**15)
        with self.assertRaises(SdlsError) as cm:
            sdls.process_secure_tc(self.sat, frame)
        self.assertEqual(cm.exception.code, sdls.SEC_ERR_MAC)
        # And the fake frame did not move the anti-replay window
        ok = sdls.build_secure_tc_frame(self.ground, color_packet(), seq=2, iv_counter=1)
        sdls.process_secure_tc(self.sat, ok)

    def test_phase_1_frame_rejected(self):
        frame = frames.build_tc_frame(color_packet(), seq=1)
        with self.assertRaises(SdlsError) as cm:
            sdls.process_secure_tc(self.sat, frame)
        self.assertEqual(cm.exception.code, sdls.SEC_ERR_LENGTH)

    def test_unknown_spi(self):
        other = sdls.SecurityAssociation(7, KEY_TC)
        frame = sdls.build_secure_tc_frame(other, color_packet(), seq=1, iv_counter=1)
        with self.assertRaises(SdlsError) as cm:
            sdls.process_secure_tc(self.sat, frame)
        self.assertEqual(cm.exception.code, sdls.SEC_ERR_SPI)

    def test_bad_crc_is_link_error(self):
        frame = bytearray(sdls.build_secure_tc_frame(self.ground, color_packet(), seq=1, iv_counter=1))
        frame[22] ^= 0x01
        with self.assertRaises(CcsdsError):
            sdls.process_secure_tc(self.sat, bytes(frame))


class TestSecureTm(unittest.TestCase):
    def setUp(self):
        self.sat = sdls.SecurityAssociation(sdls.SPI_TM, KEY_TM)
        self.ground = sdls.SecurityAssociation(sdls.SPI_TM, KEY_TM)
        self.pkt = frames.build_space_packet(0, frames.APID_SAT, 3, bytes([17, 2]))

    def test_round_trip(self):
        raw = sdls.build_secure_tm_frame(self.sat, self.pkt, 1, 2, 7, iv_counter=50)
        self.assertEqual(len(raw), 128)
        tm = sdls.parse_secure_tm_frame(self.ground, raw)
        self.assertEqual(services.decode_tm_packet(tm.frame.packets[0]), "PONG: the satellite answers")
        self.assertEqual(tm.frame.clcw.report_value, 7)

    def test_tm_replay_rejected(self):
        raw = sdls.build_secure_tm_frame(self.sat, self.pkt, 1, 2, 7, iv_counter=50)
        sdls.parse_secure_tm_frame(self.ground, raw)
        with self.assertRaises(SdlsError):
            sdls.parse_secure_tm_frame(self.ground, raw)

    def test_fake_tm_rejected(self):
        fake = sdls.SecurityAssociation(sdls.SPI_TM, bytes(32))
        raw = sdls.build_secure_tm_frame(fake, self.pkt, 1, 2, 7, iv_counter=50)
        with self.assertRaises(SdlsError):
            sdls.parse_secure_tm_frame(self.ground, raw)

    def test_hk_and_event_fit(self):
        import struct
        hk = struct.pack(services.HK_F2_FORMAT, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, -60, 1000)
        pkt = frames.build_space_packet(0, frames.APID_SAT, 1, bytes(services.TM_HK) + hk)
        raw = sdls.build_secure_tm_frame(self.sat, pkt, 0, 0, 0, iv_counter=1)
        tm = sdls.parse_secure_tm_frame(self.ground, raw)
        h = services.decode_hk_f2(tm.frame.packets[0].data[2:])
        self.assertEqual((h.sec_spi, h.sec_mac, h.sec_replay, h.payload_rgb), (4, 5, 6, (8, 9, 10)))
        ev = struct.pack(services.SEC_EVENT_FORMAT, 22, 9, bytes([192, 168, 1, 5]), 5555, 77)
        self.assertEqual(services.decode_sec_event(ev).source, "192.168.1.5:5555")
        self.assertIn("replay", services.decode_sec_event(ev).reason)


class TestIvCounter(unittest.TestCase):
    def test_always_grows_even_if_state_is_lost(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "state.json")
            c = IvCounter(path)
            a, b = c.next(), c.next()
            self.assertLess(a, b)
            self.assertLess(b, IvCounter(path).next())   # open again
            os.remove(path)
            self.assertLess(b, IvCounter(path).next())   # state lost: the clock is ahead


if __name__ == "__main__":
    unittest.main()
