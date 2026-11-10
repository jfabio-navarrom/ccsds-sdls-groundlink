# Step by step guide: phase 2 (SDLS)

Goal of this phase: **protect the link with SDLS** (CCSDS 355.0-B). Each frame is encrypted and authenticated with AES-256-GCM and has an anti-replay counter. Then you repeat the phase 1 attacks and see how **all of them fail** and arrive at the ground station as security events.

Time: 45-60 minutes.

## What changed

| | Phase 1 | Phase 2 |
| --- | --- | --- |
| Telecommand | 18 byte TC frame, in clear | 48 bytes: + SPI, IV, encrypted data and MAC |
| Telemetry | in clear | encrypted and authenticated (another key) |
| Replay | accepted | rejected: the IV was already used |
| Injection | accepted | rejected: no valid MAC |
| Who gets answers | anyone | only who proves to have the key |
| Screen | amber bar, OK / ERR / SEQ | **green** bar, OK / ERR / **SEC** |

## Step 1. Install the crypto library on the PC

```powershell
py -m pip install cryptography
```

## Step 2. Generate the keys

From the project folder:

```powershell
py tools\gen_keys_f2.py
```

It does two things:
- Saves the ground keys in `ground\keys_f2.json`. This file is **not pushed to GitHub**.
- Prints two lines that start with `#define SDLS_TC_KEY` and `#define SDLS_TM_KEY`. You need them in step 3.

There are two keys because each direction of the link uses its own. The reason is in [ADR-008](docs/adr/ADR-008-sdls-aes-gcm.md).

> Treat the keys like a password. Do not paste them in chats or show them in screenshots.

## Step 3. Upload the new firmware

1. In Arduino IDE open `satellite\satellite_f2\satellite_f2.ino`.
2. Create the `secrets.h` tab (⋯ > New Tab) with your Wi-Fi **and the two lines from step 2**:

```
#define WIFI_SSID "your_wifi_name"
#define WIFI_PASS "your_wifi_password"
#define SDLS_TC_KEY {0x.., 0x.., ...}
#define SDLS_TM_KEY {0x.., 0x.., ...}
```

3. Click **Upload**. If you get `Keys are missing in secrets.h`, you did not paste the two lines.
4. On the screen you will see the top bar in **green** (SDLS active) and the counters:
   - **OK**: authenticated and accepted telecommands
   - **ERR**: broken frames (CRC, length)
   - **SEC**: frames rejected for security
5. In the Serial Monitor you will also see the line `Anti-replay: last accepted TC IV #...`.

## Step 4. Open the ground console

First close any phase 1 console (`quit`), because they use the same port.

```powershell
py ground\gs_f2.py --sat 192.168.33.105
```

Try `color green`, `hk` and `status`. Now the `[AIR]` line says **encrypted TC sent** and it is 48 bytes. **Copy the one for `color green`**: you will use it in the attacks.

## Step 5. Repeat the attacks

Keep the ground console open and use another window for the attacker. In each attack, look at three places:
- the attacker window: it gets no answer;
- the C5 screen: **SEC** goes up and the bottom bar blinks red;
- the ground console: a `[SECURITY] SECURITY EVENT` line arrives with the reason and the attacker IP.

In the commands, replace `<hex>` with the frame you copied.

**1. The phase 1 attack, as it is** (valid frame but without SDLS):
```powershell
py attacks\attack_f2.py --sat 192.168.33.105 inject
```
Reason: `too short for SDLS`. The frame has no security header and no MAC.

**2. Forgery** (well formed SDLS frame, but with a made-up key):
```powershell
py attacks\attack_f2.py --sat 192.168.33.105 forge
```
Reason: `invalid MAC`. It also has a huge IV on purpose. If the satellite updated the counter before checking the MAC, the ground station would be locked out. Send `color blue` from ground after this to check it still works.

**3. Replay** (the `color green` frame you captured):
```powershell
py attacks\attack_f2.py --sat 192.168.33.105 replay <hex>
```
Reason: `replay`. The MAC is correct because the frame is real, but its IV was already used. **This is the attack that worked in phase 1.**

**4. Tampering** (changes one encrypted bit and computes the CRC again):
```powershell
py attacks\attack_f2.py --sat 192.168.33.105 tamper <hex>
```
Reason: `invalid MAC`. In phase 1 the CRC caught `corrupt`. Here the attacker fixes the CRC, but can not fix the MAC without the key.

**5. Sniffing** (sends nothing, only tries to read the frame):
```powershell
py attacks\attack_f2.py sniff <hex>
```
It sees the SCID, the channel and the IV, but the data can not be read. In phase 1 you could see `0801 00c800` ("set color green").

**6. Telemetry hijack does not work anymore.** After the attacks, wait 15 seconds and type `status` on ground: the HK still arrives. The satellite only changes its ground station with an authenticated TC.

## Step 6. Check that anti-replay survives a reset

1. Press the **RST** button on the board, or unplug it and plug it in again.
2. Repeat the `replay <hex>` from step 5.
3. It is still rejected, because the last accepted IV is saved in flash. [ADR-009](docs/adr/ADR-009-anti-replay-and-iv-management.md) explains this.

After the reset, the satellite does not know where the ground station is until you send a command. Type `ping` in the ground console and you will see the events again.

## Step 7 (optional). Practice without the board

```powershell
py tools\fake_satellite_f2.py
py ground\gs_f2.py --sat 127.0.0.1
```

## Step 8 (optional). Tests

```powershell
py -m unittest discover -s tests
```

## Phase 2 checklist

- [ ] The ground console works with the encrypted link
- [ ] `inject`, `forge`, `replay` and `tamper` are rejected and arrive as security events
- [ ] `sniff` can not read the command
- [ ] The HK can not be hijacked anymore
- [ ] Replay is still rejected after a board reset

## If something fails

| Symptom | Likely cause |
| --- | --- |
| `The 'cryptography' library is missing` | You skipped step 1 |
| `I can not find the SDLS keys` | You did not run step 2 from the project folder |
| Ground gets no `PONG` and **SEC** goes up on the screen with each command | The keys in `secrets.h` are not the ones in `keys_f2.json`. Copy the lines again: `py tools\gen_keys_f2.py` prints them again |
| The console gets nothing | Windows firewall: allow Python on private networks |
