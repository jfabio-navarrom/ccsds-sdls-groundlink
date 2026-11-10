"""
Policy as code (phase 4): the documented SA database must match what ground
(Python) and satellite (C++) implement. If someone changes a length or a SPI
in the code and does not update the docs, this test fails.

It also tests the logic of tools/check_policy.py without Conftest.
"""

import datetime as dt
import json
import os
import re
import sys
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "ground"))
sys.path.insert(0, os.path.join(ROOT, "tools"))

try:
    import yaml
except ImportError:  # it may not be installed on every PC
    yaml = None

from ccsds import frames, sdls  # noqa: E402

ARCH = os.path.join(ROOT, "docs", "architecture")


def load(name):
    with open(os.path.join(ARCH, name), encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def cpp_const(path, name):
    with open(os.path.join(ROOT, path), encoding="utf-8") as fh:
        m = re.search(rf"const \w+ {name} = (0x[0-9A-Fa-f]+|\d+);", fh.read())
    return int(m.group(1), 0)


@unittest.skipIf(yaml is None, "PyYAML is missing (py -m pip install pyyaml)")
class TestSaDatabase(unittest.TestCase):
    def setUp(self):
        self.db = load("groundlink.sdls.yaml")
        self.sas = {sa["spi"]: sa for sa in self.db["security_associations"]}

    def test_spis(self):
        self.assertEqual(self.sas[sdls.SPI_TC]["protocol"], "TC")
        self.assertEqual(self.sas[sdls.SPI_TM]["protocol"], "TM")
        self.assertEqual(cpp_const("satellite/satellite_f3/sdls.h", "SPI_TC"), sdls.SPI_TC)
        self.assertEqual(cpp_const("satellite/satellite_f3/sdls.h", "SPI_TM"), sdls.SPI_TM)

    def test_crypto_parameters(self):
        for sa in self.sas.values():
            self.assertEqual(sa["service"], "authenticated_encryption")
            self.assertEqual(sa["algorithm"], {"cipher": "AES", "mode": "GCM", "key_bits": sdls.KEY_LEN * 8})
            self.assertEqual(sa["iv_length_octets"], sdls.IV_LEN)
            self.assertEqual(sa["mac_length_octets"], sdls.MAC_LEN)
            self.assertEqual(sa["sequence_number"]["length_octets"], 0)   # ARSN = IV (ADR-009)
        for name, value in (("IV_LEN", sdls.IV_LEN), ("MAC_LEN", sdls.MAC_LEN), ("KEY_LEN", sdls.KEY_LEN)):
            self.assertEqual(cpp_const("satellite/satellite_f3/sdls.h", name), value, name)

    def test_channels(self):
        scid = cpp_const("satellite/satellite_f3/ccsds.h", "SCID")
        self.assertEqual(scid, frames.SCID)
        for vc in self.db["virtual_channels"]:
            self.assertEqual((vc["gvcid"]["scid"], vc["gvcid"]["vcid"]), (frames.SCID, frames.VCID))
        tc = next(vc for vc in self.db["virtual_channels"] if vc["protocol"] == "TC")
        self.assertTrue(tc["cop"])   # FARM-1 is active in phase 3

    def test_no_key_material(self):
        with open(os.path.join(ARCH, "groundlink.sdls.yaml"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIsNone(re.search(r"[0-9a-f]{64}", text))
        for sa in self.sas.values():
            self.assertNotIn("key", sa)

    def test_risk_register_complete(self):
        for a in load("accepted-risks.yaml")["acceptances"]:
            for field in ("policy_id", "targets", "risk", "justification", "compensating_controls",
                          "remediation", "owner", "review_by"):
                self.assertIn(field, a, f"{a.get('policy_id')}: {field} is missing")
            for ref in a["compensating_controls"]:
                if "/" in ref or ref.startswith("."):
                    self.assertTrue(os.path.exists(os.path.join(ROOT, ref)), ref)


class TestCheckPolicy(unittest.TestCase):
    def setUp(self):
        import check_policy
        self.cp = check_policy
        self.out = json.dumps([{"failures": [
            {"msg": "[SDLS-020] SA spi=1 (x): ...", "metadata": {"policy_id": "SDLS-020"}},
            {"msg": "[SDLS-020] SA spi=2 (x): ...", "metadata": {"policy_id": "SDLS-020"}},
        ], "warnings": [{"msg": "[SDLS-022] SA spi=1 (x): ...", "metadata": {"policy_id": "SDLS-022"}}]}])
        self.acc = [{"policy_id": "SDLS-020", "targets": ["spi=1", "spi=2"], "review_by": "2099-01-01"}]

    def test_new_finding(self):
        found = self.cp.parse_conftest(self.out)
        problems = self.cp.compare(found, self.acc, dt.date(2026, 1, 1))
        self.assertEqual(problems, ["NEW FINDING (warn): SDLS-022 spi=1"])

    def test_stale_acceptance_and_overdue_review(self):
        acc = self.acc + [{"policy_id": "MISSION-002", "targets": ["spi=1"], "review_by": "2020-01-01"}]
        found = {("fail", "SDLS-020", "spi=1"), ("fail", "SDLS-020", "spi=2")}
        problems = self.cp.compare(found, acc, dt.date(2026, 1, 1))
        self.assertEqual(len(problems), 2)
        self.assertTrue(problems[0].startswith("STALE ACCEPTANCE: MISSION-002"))
        self.assertTrue(problems[1].startswith("REVIEW OVERDUE: MISSION-002"))


if __name__ == "__main__":
    unittest.main()
