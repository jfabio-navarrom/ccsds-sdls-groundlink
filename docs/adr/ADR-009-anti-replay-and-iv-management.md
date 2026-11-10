# ADR-009: Anti-replay with the IV, and counters that survive resets

- **Status:** accepted
- **Date:** 2026-11-07

## Context

With AES-GCM the IV has two jobs:

1. It must never repeat with the same key (see ADR-008).
2. It can work as the anti-replay sequence number (ARSN in SDLS).

A replay is a real frame sent again without changes. The MAC is valid, so only a counter can catch it. Three cases make this harder: the ground station is closed and opened again, the satellite resets, and an attacker sends fake frames with a huge IV.

## Decision

- **IV = 4 zero bytes + 64 bit counter.** The IV goes in clear in the Security Header and works as the ARSN. There is no separate sequence field.
- **Satellite, TC reception:** a TC is accepted only if its IV is **strictly higher** than the last accepted one, and this is checked **after** the MAC. The last accepted IV is saved in NVS (flash) on every valid TC.
- **Ground, TC sending:** the counter is `max(last_saved + 1, clock_in_µs)` and it is saved in `ground/state_f2.json`.
- **Satellite, TM sending:** it reserves blocks of 1024 IVs in NVS, and at boot it starts above the last reserved block.
- **Ground, TM reception:** it also rejects TM with an IV that does not grow.

## Why

- **MAC before the counter.** If the counter moved first, an attacker without the key could send an IV of 2^63 and lock out the real ground station forever (denial of service). The `forge` attack tests exactly this.
- **NVS on the satellite.** Without it, after a reset the counter goes back to 0 and the satellite accepts any frame captured before. ESP32 flash lasts about 100,000 cycles per sector and NVS spreads the wear. This is fine for a lab, not for a mission.
- **Clock on ground.** If the state file is deleted, the PC clock is still ahead of the last IV used, so ground does not get blocked like an attacker.
- **IV blocks for TM.** This avoids one flash write per telemetry frame. A reset only "skips" IVs, it never repeats them.

## Options I rejected

- **Sliding window (accept out of order frames within N):** useful with loss and reordering. Here ground sends one frame at a time, so I leave it to FARM-1 in phase 3.
- **Use the frame N(S) as the counter:** it is only 8 bits, wraps every 256 frames, and is not made for this.
- **Reset the counters when the key rotates:** correct with new keys, but rotation comes in phase 3.

## Consequences

- If the PC clock goes back and `state_f2.json` is also lost, ground could be below the last IV of the satellite. Its TCs would be rejected as replay until the clock passes that value (visible in the security events).
- After a reset the satellite does not know the ground address until the first authenticated TC. Rejections before that are counted in the HK, but they do not create events.
- Erasing the C5 flash ("Erase All Flash" in Arduino) deletes the anti-replay state. This is fine in the lab and it is documented.
