# ADR-007: UDP over Wi-Fi in place of the RF link

- **Status:** accepted
- **Date:** 2026-11-07

## Context

A real ground-to-satellite link uses radio (S, X or UHF band) with CCSDS channel coding. For this project I only have one ESP32-C5 and a Windows PC, with no SDR or other RF equipment. I need a transport that keeps the security properties of the radio link that matter here.

## Decision

The CCSDS frames travel as UDP datagrams over my home Wi-Fi. Telecommands go to port 10025 on the C5, and answers and telemetry go back to the sender.

## Why

- **Same threat model.** Like in radio, any device on the network can listen, inject and replay frames. UDP does not add authentication or ordering, the same as the RF channel.
- **Security does not depend on the transport.** All protection must come from SDLS, not from the network. I do not count the Wi-Fi password as a link control.
- **It is simple.** Arduino-ESP32 and Python both support UDP out of the box, with no extra libraries.

## Options I rejected

- **USB serial:** it is point to point and physical, so I can not show attacks on the link.
- **TCP:** it adds ordering and retransmission that the RF link does not have. It would hide problems that FARM-1 has to solve.
- **The C5 as its own access point:** it isolates the lab, but the PC loses Internet while connected. I keep it as a fallback if the home network blocks traffic between devices.

## Consequences

- The source IP of a datagram is **never** used to authorize a telecommand. It does not exist in radio, and in UDP it is easy to fake.
- I do not simulate the physical layer, channel coding or CLTUs. This is a documented limitation.
- Wi-Fi can lose packets. That is useful to test FARM-1 in phase 3.
