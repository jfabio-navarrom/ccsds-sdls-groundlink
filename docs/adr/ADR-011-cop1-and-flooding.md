# ADR-011: COP-1 below SDLS, and an event limit against flooding

- **Status:** accepted
- **Date:** 2026-11-09

## Context

The UDP link loses frames (ADR-007). Without a retransmission protocol, a lost telecommand is simply not executed and ground does not know it. CCSDS solves this with COP-1: FOP on ground and FARM-1 on board. Putting COP-1 together with SDLS raises three design questions:

1. In which order do SDLS and FARM run?
2. How do we retransmit if anti-replay rejects repeated IVs?
3. If every security rejection creates an event, an attacker can flood the link.

## Decision

- **Order: SDLS first, then FARM**, for all frame types:
  - AD (sequenced) and BD (bypass) carry services;
  - BC (control) carries Unlock and Set V(R).
  - Bypass skips the FARM, never the security.
- **Retransmission: same N(S) with a new IV.** The FOP protects the frame again on each try. If the original did arrive, the FARM drops the copy as a duplicate (silent drop).
- **FOP with one frame at a time** (window 1): ground does not send the next frame until the CLCW confirms the last one. At most 4 tries of 1.5 s.
- **Lockout:** it is cleared with `sync` (Unlock + Set V(R)), which the operator runs on purpose. Ground does not do it alone.
- **Event limit:** token bucket with bursts of 3 and 1 event per second. Events that do not fit are counted and summarized in one message (service 5,5). Also, the screen is redrawn at most every 150 ms, and nothing is written to the serial port for each rejected frame.

## Why

- **SDLS before FARM.** If the FARM processed frames that are not authenticated, an attacker could put it in lockout or push it out of sync with fake frames. That is a trivial denial of service. With SDLS in front, only who has the key can touch the FARM state. Also, N(S) is in the AAD, so it can not be changed.
- **New IV on each retransmission.** Anti-replay only accepts growing IVs. Sending the same bytes again works if the original was lost. But if it arrived and the confirmation was lost, the copy would be marked as replay and raise a false security alarm. With a new IV, the FARM handles duplicates without noise.
- **Window 1.** With several frames in flight, if one is lost, the next one moves the anti-replay counter forward. The retransmission of the lost frame would then have an older IV and be rejected. One frame at a time avoids this without making anti-replay more complex.
- **Event limit.** Telemetry is a scarce resource (86 useful bytes per frame). Without a limit, 300 fake frames would create 300 TM frames and bury the housekeeping and the real confirmations. With the summary nothing is lost: the exact total is still in the HK.

## Options I rejected

- **FARM before SDLS:** more efficient, but it opens the denial of service described above.
- **Sliding anti-replay window (bitmap):** it would allow several frames in flight, at the cost of more state and complexity. At the speed of a human operator it is not worth it.
- **Clear the lockout automatically:** it hides a symptom that must be looked at, like an unexpected satellite reset or a desync.
- **Drop the extra events without counting them:** the operator would lose the size of the attack.

## Consequences

- **The FARM is not a security control.** N(S) has 8 bits and wraps. This is written in the code so nobody treats it as one.
- **After a reset the satellite starts with V(R) = 0.** The first TC from ground causes a lockout and `sync` is needed. This is expected, and it works as a warning that the satellite was reset.
- **A flood still uses CPU and Wi-Fi.** The limit protects the telemetry and the screen, not the radio channel. In a real system the channel defense would be physical (antenna, spectrum), out of scope here.
- **The CLCW is not covered by the MAC**, as said in ADR-008. A man-in-the-middle could fake the FARM state that ground sees. This is in the phase 4 threat model.
