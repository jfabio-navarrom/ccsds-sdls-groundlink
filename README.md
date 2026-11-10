# CCSDS SDLS Ground Link

Securing a ground-to-satellite link end to end with CCSDS and SDLS, using an ESP32-C5 (Waveshare ESP32-C5-Touch-LCD-2.8 board) as the simulated satellite.

[![CI](https://github.com/jfabio-navarrom/ccsds-sdls-groundlink/actions/workflows/ci.yml/badge.svg)](https://github.com/jfabio-navarrom/ccsds-sdls-groundlink/actions/workflows/ci.yml)

> **Status: all 4 phases done.** The link speaks real CCSDS (TC and TM frames, Space Packets, PUS-lite services and housekeeping) and is protected with **SDLS (CCSDS 355.0-B) using AES-256-GCM**. It has persistent anti-replay, security events, **in-flight key rotation (OTAR)**, **COP-1 (FOP/FARM-1)** with retransmission, and flood defense. Phase 4 adds the threat model, NIST traceability and policy as code. The older phases are kept for comparison.

## The "before": without SDLS, anyone can command

![Phase 0 demo: the ground station sets the payload to green and an attacker without keys sets it to red](docs/media/demo-f0-before.gif)

The ground station sets the payload (the screen) to green. Then an attacker script that knows no secret injects a telecommand, and the satellite accepts it: the screen turns red. In phase 2 this same attack must be rejected and logged in the telemetry.

## Before and after SDLS

| Attack | Phase 1 (no SDLS) | Phase 2 (with SDLS) | Control |
| --- | --- | --- | --- |
| TC injection | Accepted | Rejected and reported | AES-GCM MAC |
| Replay of a captured frame | Accepted | Rejected, also after a reset | IV as anti-replay counter, saved in flash |
| One bit changed, CRC computed again | Accepted | Rejected | MAC (the CRC is not authentication) |
| Reading commands and telemetry | Readable | Encrypted | AES-256-GCM |
| Telemetry hijack | HK goes to the attacker | TM only goes to the authenticated ground | Authenticated source, not IP |
| Huge IV to lock out the ground | Not applicable | No effect | Counter only updated after the MAC check |

Each rejection creates a **security event** (PUS service 5,4) with the reason, the source IP and the IV. It arrives encrypted at the ground station. The sender gets no answer.

## Phase 3: running a secure link

| Scenario | Without phase 3 | With phase 3 | Control |
| --- | --- | --- | --- |
| Leaked TC key | The attacker is in control until a reflash | `rotate` and the old key stops working | OTAR with KEK, anti-rollback (ADR-010) |
| Network that loses 40 % of the TCs | Commands lost without notice | All of them arrive, in order | FOP with retransmission (new IV) + FARM-1 |
| Bypass frame (BD/BC) without SDLS | n/a | Rejected and reported | SDLS before the FARM (ADR-011) |
| Flood of 300 fake frames | 300 events that bury the telemetry | 3 events + 1 summary; operations go on | Event limit (token bucket) |
| Satellite reset | n/a | Visible lockout, fixed with `sync` | FARM-1 + CLCW |

## Phase 4: architecture

| Document | What is inside |
| --- | --- |
| [Threat model](docs/architecture/THREAT_MODEL.md) | 13 threats with SPARTA technique, control, countermeasure, evidence on the board and residual risk |
| [NIST SP 800-53 traceability](docs/architecture/NIST_TRACEABILITY.md) | 16 controls: where they are in the code and what proves them (11 implemented, 3 partial, 2 missing) |
| [SA database](docs/architecture/groundlink.sdls.yaml) | The real SDLS configuration as code, checked against the firmware and scanned with [ccsds-policy-as-code](https://github.com/jfabio-navarrom/ccsds-policy-as-code) |
| [Accepted risks](docs/architecture/accepted-risks.yaml) | Accepted deviations with justification, owner and review date; CI fails when they expire |
| [Portfolio summary](docs/PORTFOLIO.md) | One page summary of the project |

## What is in the repo

| Part | File | What it does |
| --- | --- | --- |
| Satellite F3 | `satellite/satellite_f3/` | F2 + `farm.cpp` (FARM-1), OTAR with KEK, keys in NVS, event limit |
| Satellite F2 | `satellite/satellite_f2/` | Firmware with SDLS: `sdls.cpp` (mbedTLS), anti-replay in NVS, security events |
| Satellite F1 | `satellite/satellite_f1/` | CCSDS baseline with no security |
| Ground library | `ground/ccsds/` | `frames.py` (TC/TM, Space Packets), `services.py` (PUS-lite), `sdls.py` (SDLS and OTAR), `cop1.py` (FARM-1), `keystore.py` (keys and IV counter) |
| Ground station | `ground/gs_f3.py`, `gs_f2.py`, `gs_f1.py` | Console for each phase; F3 has FOP, `rotate`, `sync` and `--loss` |
| Attacker | `attacks/attack_f3.py`, `attack_f2.py`, `attack_f1.py` | `flood`, `bypass`, `leaked`; `inject`, `forge`, `replay`, `tamper`, `sniff` |
| Tools | `tools/` | Key generator, simulated satellites in Python, policy check |
| Tests | `tests/` | Test vectors, C++ (mbedTLS) ↔ Python interop byte by byte, and end to end tests of the attacks, in CI |

Step by step guides: [phase 0](GUIDE_PHASE0.md), [phase 1](GUIDE_PHASE1.md), [phase 2](GUIDE_PHASE2.md) and [phase 3](GUIDE_PHASE3.md).

## Roadmap

1. **F0, setup:** UDP link and screen control.
2. **F1, MVP with no security:** CCSDS TC/TM frames, Space Packets and PUS-lite services.
3. **F2, SDLS:** AES-256-GCM, anti-replay and security events in telemetry.
4. **F3, keys and FARM:** in-flight rekeying, FARM-1, and bypass and flood scenarios.
5. **F4, architecture:** SPARTA threat model, NIST SP 800-53 traceability, ADRs and policy as code. ✓ Done.

## Architecture decisions

- [ADR-007: UDP over Wi-Fi in place of the RF link](docs/adr/ADR-007-udp-as-rf-link.md)
- [ADR-008: SDLS with AES-256-GCM and one key per direction](docs/adr/ADR-008-sdls-aes-gcm.md)
- [ADR-009: Anti-replay with the IV, and counters that survive resets](docs/adr/ADR-009-anti-replay-and-iv-management.md)
- [ADR-010: In-flight key rotation (OTAR) with a master key](docs/adr/ADR-010-otar-key-rotation.md)
- [ADR-011: COP-1 below SDLS, and an event limit against flooding](docs/adr/ADR-011-cop1-and-flooding.md)
- [ADR-012: Link security configuration as code, with versioned risk acceptances](docs/adr/ADR-012-policy-as-code.md)

## Ethics

Educational and defensive project. The attack scripts are only used against my own C5, on my own network.
