# ADR-008: SDLS with AES-256-GCM and one key per direction

- **Status:** accepted
- **Date:** 2026-11-07

## Context

In phase 1 the link speaks real CCSDS, but anyone on the network can inject telecommands, replay captured frames, read the telemetry and redirect it to themselves. The CRC only finds transmission errors. I need to authenticate the sender, protect integrity and confidentiality, and the satellite must keep a record of the attempts.

## Decision

Protect TC and TM frames with a subset of SDLS (CCSDS 355.0-B) in authenticated encryption mode:

| | TC frame | TM frame (128 bytes) |
| --- | --- | --- |
| Security Header | SPI (2) + IV (12) after the primary header | same |
| Data | encrypted Space Packet | 86 encrypted bytes (packet + idle) |
| Security Trailer | 16 byte MAC | 16 byte MAC, before the OCF |
| AAD (authenticated, in clear) | TC header + SPI + IV | TM header + SPI + IV |

- Algorithm: **AES-256-GCM**, with mbedTLS on the satellite and `cryptography` on ground.
- **Two security associations (SA):** SPI 1 with the TC key (ground → satellite) and SPI 2 with the TM key (satellite → ground).
- The satellite **never answers** a frame that fails SDLS. It sends a security event (service 5,4) to the authenticated ground station and counts it in the housekeeping.
- Telemetry only goes to the address of the last **authenticated** TC.

## Why

- **GCM** gives confidentiality, integrity and authentication in one operation, with a 128 bit MAC. It is the mode that the SDLS Cryptographic Algorithms Blue Book (CCSDS 352.0-B) recommends, and the ESP32-C5 has hardware support for it.
- **Header in the AAD.** Without this, an attacker could change the SCID, the channel or the N(S) and the MAC would still be valid.
- **One key per direction.** Ground and satellite make their IVs with separate counters. With one shared key they could hit the same IV, and in GCM a repeated IV with the same key leaks the XOR of the plaintexts and allows forged MACs. Separate keys remove this risk by design.
- **Silence to unknown senders.** The attacker gets no oracle (they don't know if the MAC or the replay check failed), and the satellite does not send traffic to a faked IP.

## Options I rejected

- **Authentication only (GMAC/CMAC):** it stops injection and replay, but commands and telemetry stay readable. It could be a configurable mode later.
- **AES-CBC + HMAC:** two primitives and two keys per direction to get what GCM already gives, with more room for implementation mistakes.
- **TLS/DTLS over UDP:** it protects the transport, not the CCSDS frame. It does not exist on a real RF link (see ADR-007).

## Consequences

- Each TC grows by 30 bytes, and the useful TM goes down from 116 to 86 bytes per frame.
- The CLCW (OCF) stays **outside** the protection, like in the standard, so an attacker can change it. FARM-1 in phase 3 deals with it.
- Keys are pre-shared and stored in clear in `secrets.h` and `ground/keys_f2.json`. The ESP32 flash is not encrypted (no flash encryption, no secure boot). In-flight key rotation comes in phase 3.
- Security events have no rate limit: a flood of fake frames creates the same number of events. Phase 3 handles this (flood scenario).
