# CCSDS SDLS Ground Link: portfolio summary

**A secure satellite command-and-telemetry link, built end to end on a single ESP32-C5 board and attacked at every step.**

Author: Fabio Navarro (GRC → Security Architecture). Board: Waveshare ESP32-C5-Touch-LCD-2.8. Ground segment: Python on Windows.

## What it is

The ESP32-C5 plays the spacecraft. A Python console plays the ground station. They talk real CCSDS over Wi-Fi/UDP, which stands in for the RF link (ADR-007):

- TC and TM Space Data Link Protocol frames;
- Space Packets;
- PUS-style services;
- COP-1 (FOP/FARM-1) for reliable, in-order commanding.

The link is protected with **SDLS (CCSDS 355.0-B)**:
- **AES-256-GCM** authenticated encryption, with separate keys per direction (ADR-008);
- **anti-replay** state that survives reboots (ADR-009);
- **in-flight key rotation (OTAR)** under a key-encryption key, with anti-rollback (ADR-010);
- **rate-limited security events** in the downlink (ADR-011).

## How it was built: vulnerable first, then defended

Each phase ships both the defence and the attack script that proves it. Every result below was **reproduced on the real board**, not only in simulation.

| Attack (SPARTA technique) | Before SDLS | After |
| --- | --- | --- |
| Command injection (IA-0008.01) | Accepted | Rejected and reported to ground |
| Replay of captured commands (EX-0001.01) | Accepted | Rejected, also after a board reset |
| Bit-flip with recomputed CRC (IMP-0011) | Accepted | Rejected: the MAC catches it |
| Eavesdropping (EXF-0003) | Commands and telemetry readable | Encrypted |
| Telemetry hijack (DE-0002) | Housekeeping redirected to attacker | Telemetry only goes to the authenticated ground |
| Leaked traffic key | Full control until reflash | `rotar` revokes it in flight |
| Bypass/control frames without SDLS | n/a | Rejected: security applies before FARM-1 |
| 300-frame flood (EX-0013) | n/a | 3 events + 1 summary; operations continue |

## Architecture artefacts

- **Threat model** mapped to SPARTA techniques and countermeasures, with residual risks named and owned: [`docs/arquitectura/THREAT_MODEL.md`](arquitectura/THREAT_MODEL.md).
- **NIST SP 800-53 Rev. 5 traceability**, control by control, with code location and evidence. Gaps (SC-28, SI-7) are stated, not hidden: [`TRAZABILIDAD_NIST.md`](arquitectura/TRAZABILIDAD_NIST.md).
- **Six ADRs** (007–012) explaining the trade-offs: [`docs/adr/`](adr/).
- **Policy as code:**
  - the link's Security Association database is versioned YAML, scanned in CI with my [`ccsds-policy-as-code`](https://github.com/jfabio-navarrom/ccsds-policy-as-code) Rego policies;
  - deviations live in a **risk register as code** (`riesgos-aceptados.yaml`), with justification, compensating controls, owner and review date;
  - CI fails on a new finding, a stale exception or an overdue review (ADR-012).

## Engineering evidence

- **Two independent implementations** of the protocol stack (C++ with mbedTLS on board; Python with `cryptography` on ground), tested byte-for-byte against each other in CI.
- **End-to-end tests** run every attack against a simulated satellite on every push.
- **A hardware-only bug found and fixed.** The ESP32's hardware AES-GCM rejects zero-length input, which silently stopped rotated keys from persisting. It never showed up on the PC. It was found on the board through serial logs and fixed with a regression path. A reminder of why flight-representative testing matters.

## What I would do next

- Explicit ARSN with a tight window, to close accepted risk R1.
- Keys in an OS keystore or HSM on ground, and flash encryption plus secure boot on board (R2, R6).
- Authenticated CLCW (R3) and ECDH-based KEK renewal (R5).
