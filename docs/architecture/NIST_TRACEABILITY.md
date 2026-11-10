# NIST SP 800-53 Rev. 5 traceability

For each control: what is implemented, where it is, and what proves it. If a control is partial or missing, this says so.

The SPARTA countermeasures (CM0031, CM0030...) are mapped to 800-53 controls in the framework itself. This table starts from those controls and connects them to the code.

| Control | What it asks for | Implementation in the link | Where | Evidence | Status |
| --- | --- | --- | --- | --- | --- |
| **SC-8, SC-8(1)** Transmission Confidentiality and Integrity | Protect confidentiality and integrity in transit with cryptography | AES-256-GCM on TC (SPI 1) and TM (SPI 2); the frame header is authenticated | `satellite_f3/sdls.cpp`, `ground/ccsds/sdls.py` | `test_sdls`, `test_interop_f2` (C++ ↔ Python byte by byte); `sniff` and `tamper` on board | Implemented |
| **SC-13** Cryptographic Protection | Use approved cryptography | AES-256-GCM with a 128 bit MAC (CCSDS 352.0-B), mbedTLS and `cryptography` | `sdls.h` | NIST GCM vector in `test_sdls`; rules CRYPTO-001/002/004 of the policy scan | Implemented |
| **SC-12** Cryptographic Key Establishment and Management | Generate, distribute, store, rotate and destroy keys | CSPRNG key generation; separate keys per direction; OTAR with KEK; anti-rollback; RAM copies wiped | `tools/gen_keys_f3.py`, `handleKeys()` in `satellite_f3.ino`, `KeyStoreF3` | `test_f3` (OTAR, interop), `test_e2e_f3` (rotation); board: rotation that survives RST | Partial: storage without HSM (R2) and KEK can not be rotated (R5) |
| **SC-23** Session Authenticity | Protect session authenticity: replay, hijack | IV as a persistent anti-replay counter; TM only goes to the authenticated ground | `processTc()`, NVS `tciv` | `attack_f2 replay` on board (also after RST); `test_e2e_f2` | Implemented, with accepted deviation R1 |
| **IA-3** Device Identification and Authentication | Authenticate devices before connecting | The ground station authenticates with the TC key; the IP does not count | `handleTc()` | `inject`, `forge`, `leaked` (after rotation) on board | Implemented (symmetric key) |
| **SI-10** Information Input Validation | Validate all inputs | Lengths, version, CRC, SCID and VCID; Space Packet with exact length; service and application data | `ccsds.cpp`, `executePacket()` | `test_frames`, `test_interop` | Implemented |
| **AU-2, AU-3** Event Logging; Content of Audit Records | Log relevant events with what, when, where and source | Security event (5,4) with reason, N(S), source IP and port, and IV; counters in the HK | `sendSecurityEvent()` | `test_e2e_f2`, `test_e2e_f3`; ground console on board | Implemented (no timestamp on board) |
| **AU-6** Audit Record Review | Review the records | The console shows `[SECURITY]` in real time; `status` sums up the counters | `gs_f3.py` | Board | Partial: not saved to disk |
| **SI-4** System Monitoring | Monitor for attacks and indicators | Counters per rejection type, FARM discards and summarized events in the HK | `sendHk()` | `test_sdls` (HK) | Implemented |
| **SC-5** Denial-of-Service Protection | Limit the effect of denial of service | Token bucket for events; anti-replay window only after the MAC; SDLS before the FARM | `refillEventTokens()`, ADR-011 | `flood` and `forge` on board; `test_e2e_f3` | Partial: the channel is not protected (R4) |
| **SC-28** Protection of Information at Rest | Protect stored information | None: keys in clear in JSON and NVS | none | none | **Not implemented** (R2) |
| **SI-7** Software, Firmware, and Information Integrity | Detect unauthorized firmware changes | None: no secure boot | none | none | **Not implemented** (R6) |
| **CM-6** Configuration Settings | Set and watch the security configuration | The SA database is code and is scanned with the `ccsds-policy-as-code` policies | `docs/architecture/groundlink.sdls.yaml`, `tools/check_policy.py` | `policies` CI job; `test_sa_database` | Implemented |
| **CA-7** Continuous Monitoring | Assess the controls all the time | On every push: tests, interop, and policy scan with the risk register | `.github/workflows/ci.yml` | CI runs on GitHub Actions | Implemented |
| **SA-11** Developer Testing and Evaluation | Developer testing of the controls | Unit tests, interop tests between two independent implementations, and end to end tests with the attacks | `tests/` | CI | Implemented |
| **RA-3** Risk Assessment | Assess and document risk | Threat model with SPARTA, residual risks, and acceptances with a review date | [THREAT_MODEL.md](THREAT_MODEL.md), [accepted-risks.yaml](accepted-risks.yaml) | CI fails if an acceptance expires | Implemented |

**Summary:** 11 controls implemented, 3 partial and 2 not implemented. Every gap has a named residual risk and a proposed fix.
