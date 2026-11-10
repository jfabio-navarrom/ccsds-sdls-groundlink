# CCSDS SDLS Ground Link: project summary

**A secure satellite command and telemetry link, built end to end on one ESP32-C5 board and attacked at every step.**

Author: Fabio Navarro (from GRC to security architecture). Board: Waveshare ESP32-C5-Touch-LCD-2.8. Ground segment: Python on Windows.

## What it is

The ESP32-C5 plays the spacecraft and a Python console plays the ground station. They talk real CCSDS over Wi-Fi/UDP, which takes the place of the RF link (ADR-007):

- TC and TM Space Data Link Protocol frames;
- Space Packets;
- PUS-style services;
- COP-1 (FOP/FARM-1) for reliable commanding, in order.

The link is protected with **SDLS (CCSDS 355.0-B)**:
- **AES-256-GCM** authenticated encryption, with one key per direction (ADR-008);
- **anti-replay** state that survives reboots (ADR-009);
- **in-flight key rotation (OTAR)** under a key encryption key, with anti-rollback (ADR-010);
- **rate-limited security events** in the downlink (ADR-011).

## How I built it: vulnerable first, then defended

Each phase has the defense and also the attack script that proves it. I ran every result below **on the real board**, not only in simulation.

| Attack (SPARTA technique) | Before SDLS | After |
| --- | --- | --- |
| Command injection (IA-0008.01) | Accepted | Rejected and reported to ground |
| Replay of captured commands (EX-0001.01) | Accepted | Rejected, also after a board reset |
| Bit flip with the CRC computed again (IMP-0011) | Accepted | Rejected: the MAC catches it |
| Eavesdropping (EXF-0003) | Commands and telemetry readable | Encrypted |
| Telemetry hijack (DE-0002) | Housekeeping goes to the attacker | Telemetry only goes to the authenticated ground |
| Leaked traffic key | Full control until reflash | `rotate` revokes it in flight |
| Bypass/control frames without SDLS | n/a | Rejected: security runs before FARM-1 |
| Flood of 300 frames (EX-0013) | n/a | 3 events + 1 summary; operations go on |

## Architecture documents

- **Threat model** mapped to SPARTA techniques and countermeasures, with residual risks named and owned: [`THREAT_MODEL.md`](architecture/THREAT_MODEL.md).
- **NIST SP 800-53 Rev. 5 traceability**, control by control, with code location and evidence. The gaps (SC-28, SI-7) are written down, not hidden: [`NIST_TRACEABILITY.md`](architecture/NIST_TRACEABILITY.md).
- **Six ADRs** (007 to 012) with the trade-offs: [`docs/adr/`](adr/).
- **Policy as code:**
  - the Security Association database of the link is versioned YAML, scanned in CI with my [`ccsds-policy-as-code`](https://github.com/jfabio-navarrom/ccsds-policy-as-code) Rego policies;
  - deviations live in a **risk register as code** (`accepted-risks.yaml`), with justification, compensating controls, owner and review date;
  - CI fails on a new finding, a stale exception or an overdue review (ADR-012).

## Engineering evidence

- **Two separate implementations** of the protocol stack (C++ with mbedTLS on board, Python with `cryptography` on ground), tested byte by byte against each other in CI.
- **End to end tests** run every attack against a simulated satellite on every push.
- **A bug that only happened on the hardware.** The ESP32 hardware AES-GCM rejects input of length zero, and because of this the rotated keys were silently not saved. It never happened on the PC. I found it on the board with the serial logs and fixed it. A good reminder of why testing on flight-like hardware matters.

## Next steps

- Explicit ARSN with a narrow window, to close accepted risk R1.
- Keys in an OS key store or HSM on ground, and flash encryption plus secure boot on board (R2, R6).
- Authenticated CLCW (R3) and KEK renewal with ECDH (R5).
