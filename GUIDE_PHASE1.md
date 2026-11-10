# Step by step guide: phase 1

Goal of this phase: **satellite and ground stop talking with text and start using real CCSDS frames**, the same kind that ESA and NASA use. The satellite also sends telemetry every 5 seconds. And you will see that, even with a "real" protocol, **without SDLS there is still no security**.

Time: 30-45 minutes.

## What changed

| | Phase 0 | Phase 1 |
| --- | --- | --- |
| Telecommand | text: `LED 0 200 0` | 18 byte CCSDS TC frame with CRC |
| Answer | text: `ACK LED` | 128 byte CCSDS TM frame with CLCW |
| Telemetry | none | housekeeping (HK) report every 5 s |
| Screen | color | color + OK / ERR / SEQ counters |
| Ground | one command per run | interactive console `gs_f1.py` |

## Step 1. Upload the new firmware

1. Download and unzip the project over your folder, or run `git pull` if you use Git.
2. In Arduino IDE open `satellite\satellite_f1\satellite_f1.ino`. It is a new folder; the phase 0 one stays as it was.
3. Create the `secrets.h` tab again (⋯ > New Tab) with your Wi-Fi:

```
#define WIFI_SSID "your_wifi_name"
#define WIFI_PASS "your_wifi_password"
```

4. Click **Upload**. On the screen you will see the amber bar, the payload box, and three counters below:
   - **OK**: accepted telecommands
   - **ERR**: rejected telecommands
   - **SEQ**: sequence number of the last accepted frame
5. Check the IP in the Serial Monitor. Usually it is the same as before.

## Step 2. Open the ground console

```powershell
cd <folder where you unzipped the project>
py ground\gs_f1.py --sat 192.168.33.105
```

- The first time, Windows may ask about the firewall: allow **private networks**. If not, the telemetry will not arrive.
- At start, the console sends a `ping` and you should see `PONG: the satellite answers`.

Try these commands:

```
ground> color green
ground> hk
ground> status
ground> quit
```

Each command shows a line `[AIR] TC sent (...)`: these are the exact bytes that travel on the link. **Copy the one for `color green`**, you need it in step 4.

## Step 3. Understand a TC frame

This is the `color green` frame, byte by byte:

| Bytes | Field | Meaning |
| --- | --- | --- |
| `00 c5` | TC header | version 0, no bypass, **SCID 0x0C5** (our satellite) |
| `00 11` | | virtual channel 0, length 0x011 + 1 = 18 bytes |
| `01` | | frame sequence number N(S) = 1 |
| `10 10` | Space Packet | telecommand type, **APID 0x010** (on-board application) |
| `c0 01` | | packet not segmented, packet number 1 |
| `00 04` | | 5 data bytes |
| `08 01` | PUS-lite service | service 8, subservice 1 = "set color" |
| `00 c8 00` | Data | R = 0, G = 200, B = 0 |
| `fa 2b` | FECF | CRC-16 of everything before |

Look at what is **not** there: no signature, no key, nothing that proves who sent it.

## Step 4. The phase 1 attacks

Keep the ground console open in one window and open **another PowerShell window** for the attacker.

**Injection**: the attacker builds a perfect frame, with its CRC, without any secret. The SCID is not secret either: in real life it is public.

```powershell
py attacks\attack_f1.py --sat 192.168.33.105 inject
```

The screen goes red and the **OK** counter goes up. Now wait 15 seconds and type `status` in the ground console: you will see a warning that no telemetry is arriving. The satellite thinks the attacker is the ground station and **sends the housekeeping to the attacker**. Send any command from ground to get it back.

**Replay**: sends again the `color green` frame you copied in step 2.

```powershell
py attacks\attack_f1.py --sat 192.168.33.105 replay 00c50011011010c0010004080100c800fa2b
```

The satellite accepts it again, even if its sequence number is old (see how **SEQ** goes back). It has no way to know it is a copy.

**Corruption**: the same frame with one bit changed.

```powershell
py attacks\attack_f1.py --sat 192.168.33.105 corrupt 00c50011011010c0010004080100c800fa2b
```

This time it is rejected: **ERR** goes up and the bottom bar blinks red. **Conclusion: the CRC protects against transmission errors, not against attackers**, because anyone can compute it. For that we need cryptographic authentication: SDLS, in phase 2.

## Step 5 (optional). Practice without the board

There is a simulated satellite in Python that behaves like the firmware:

```powershell
py tools\fake_satellite_f1.py
```

And in another window:

```powershell
py ground\gs_f1.py --sat 127.0.0.1
```

## Step 6 (optional). Run the tests

```powershell
py -m unittest discover -s tests -v
```

The C++ ↔ Python interop tests are skipped on your PC because they need to compile C++. On GitHub they run by themselves on every change (**Actions** tab of the repo).

## Phase 1 checklist

- [ ] The ground console gets `PONG` and housekeeping
- [ ] The screen shows the OK / ERR / SEQ counters
- [ ] `inject` and `replay` are accepted and `corrupt` is rejected
- [ ] You saw how the attacker hijacks the telemetry
