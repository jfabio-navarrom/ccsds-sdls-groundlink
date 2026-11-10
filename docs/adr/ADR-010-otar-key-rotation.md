# ADR-010: In-flight key rotation (OTAR) with a master key

- **Status:** accepted
- **Date:** 2026-11-09

## Context

In phase 2 the traffic keys (TC and TM) are compiled into the firmware. If a key leaks (for example because someone pastes it in a chat), the only way to change it is to generate a new one and reflash the board. On a real satellite this is not possible: nobody can go up and change the firmware. I need to change the keys over the link itself, in a safe way.

## Decision

Follow the key hierarchy of SDLS Extended Procedures (CCSDS 355.1-B), simplified:

- **KEK (master key):** installed before launch. It only wraps new keys and never encrypts normal traffic.
- **Traffic keys (TC and TM):** they have an **ID** that only goes up. The first keys have ID 1.
- **Upload (service 24,1):** `[ID][IV 12][TC+TM keys encrypted 64][MAC 16]`, with AES-256-GCM under the KEK and AAD = `"OTAR" + SCID + ID`. The TC that carries it is also protected with the current traffic keys.
- **Activation (service 24,2):** a separate step. From its confirmation on, which already goes out encrypted with the new TM key, ground and satellite use the new keys.
- **Anti-rollback:** the satellite rejects any ID that is not higher than the active one.
- **Destruction:** the satellite clears the copies of the pending keys from RAM. On ground, retired keys are removed from the key store and only their ID is kept.
- **Persistence:** the satellite saves the active keys in NVS together with a KEK fingerprint. If it is reflashed with another KEK, it drops the saved keys and goes back to the ones in `secrets.h`.

## Why

- **Separate KEK and traffic keys** to limit the damage. The key that is used (and exposed) the most is not the one that can install new keys.
- **The ID inside the AAD** stops anyone from relabeling a captured OTAR block as a different ID.
- **Upload and activation as separate steps** let me check that the keys arrived before the switch. If the activation fails, the link keeps working with the old keys.
- **Anti-rollback.** Without it, an attacker with an old leaked key and an old captured OTAR block could take the satellite back to a compromised key.
- **Keep the anti-replay counters when rotating.** The IVs keep growing, so there is no replay window during the change.

## Options I rejected

- **Reflash for every change:** not possible in flight, and it is exactly the problem I want to solve.
- **Derive new keys from the old one (HKDF ratchet):** no KEK needed, but if one key leaks, all the next ones can be computed.
- **Asymmetric key exchange (ECDH):** stronger, because no long-lived secret protects everything. But it is more complex and it is not part of the SDLS baseline. I leave it as a future improvement.
- **AES Key Wrap (RFC 3394):** the classic standard to wrap keys. Using GCM lets me reuse the same primitive and its tested implementation.

## Consequences

- **The KEK becomes the critical secret.** If it leaks, an attacker who can also send authenticated TCs could install their own keys. Changing the KEK does need a reflash.
- The KEK and the active keys are in clear in the ESP32 flash, with no flash encryption and no secure boot. This is an accepted risk of the lab in the phase 4 threat model.
- If the activation confirmation is lost, ground notices it when the next TM arrives encrypted with the new key, and finishes the switch then.
