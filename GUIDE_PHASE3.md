# Step by step guide: phase 3 (keys, FARM-1 and flooding)

Goal of this phase: the link is not only secure, it is also **usable in operations**:
- change the keys without touching the board;
- no telecommands are lost even if the network fails;
- an attacker can not take down the telemetry by sending garbage.

Time: 60 minutes.

## What changed

| | Phase 2 | Phase 3 |
| --- | --- | --- |
| Keys | fixed in the firmware | can be rotated in flight with `rotate` (OTAR) |
| Leaked key | you must reflash | `rotate` and the old key stops working |
| Lost telecommand | lost without notice | ground sends it again by itself (COP-1) |
| Execution order | no guarantee | in order, no duplicates (FARM-1) |
| 300 fake frames | 300 security events | 3 events + 1 summary |
| Screen | green bar | green bar + **active key ID** on the right |

## Step 1. Generate the phase 3 keys

From the project folder:

```powershell
py tools\gen_keys_f3.py
```

Now it prints **three** lines:
- `SDLS_KEK` is the master key. It is only used to send new keys. It is the most important one.
- `SDLS_TC_KEY` and `SDLS_TM_KEY` are the first traffic keys (ID 1).

The ground keys are saved in `ground\keys_f3.json`, which is not pushed to GitHub.

## Step 2. Upload the firmware

1. In Arduino IDE open `satellite\satellite_f3\satellite_f3.ino`.
2. Create the `secrets.h` tab with your Wi-Fi and the **three** lines from step 1.
3. Click **Upload**. On the right side of the green bar you will see a **1**: the ID of the active key.
4. Write down the IP from the Serial Monitor (last time it was .108).

## Step 3. Open the ground console

```powershell
py ground\gs_f3.py --sat 192.168.33.108
```

At start it does two new things:
- `sync`: unlocks the FARM and aligns the counters. You will see two `TC BC` lines.
- `ping`: each `[AIR]` line now shows the frame type (AD, BD or BC) and its **N(S)**.

Try `color green` and `status`. In `status` there are two new lines: **FARM (CLCW)**, the frame the satellite expects, and **FOP**, the next one ground will send.

## Step 4. COP-1: telecommands that are not lost

Close the console (`quit`) and open it again, simulating a channel that loses 40 % of the frames:

```powershell
py ground\gs_f3.py --sat 192.168.33.108 --loss 0.4
```

Send several colors in a row. You will see lines like these:

```
[CHANNEL] frame N(S)=3 lost on the way (simulated)
[FOP] No confirmation for N(S)=3: sending again (try 2, new IV)
```

Every color arrives in the end, and in order. Look at **new IV**: the retransmission can not reuse the IV, because anti-replay would reject it. The reason is in [ADR-011](docs/adr/ADR-011-cop1-and-flooding.md).

Close the console and open it again without `--loss` for the next steps.

## Step 5. Satellite reset and lockout

1. With the console open, press **RST** on the board and wait until it connects.
2. Send `color blue`. You will see `The satellite FARM is in LOCKOUT`: the satellite was reset, it expects frame 0, and ground was at another number.
3. Type `sync` and repeat `color blue`. Now it works.

The lockout is not a bug: it is an alarm that something strange happened to the satellite. That is why the operator clears it, not the machine.

## Step 6. Leaked key and rotation (the phase 2 case)

Imagine the TC key has leaked. Open `ground\keys_f3.json` and copy the `"tc"` value inside `"active"`. **Do not paste it in any chat.**

**Before rotating**, the attacker uses the leaked key from another window:

```powershell
py attacks\attack_f3.py --sat 192.168.33.108 leaked <tc_key>
```

The screen goes **red**: with the key, the attacker is in control. It uses a BD (bypass) frame so it does not need to guess the N(S). Also, the telemetry now goes to the attacker, even if they can not read it without the TM key. Send `ping` from ground to get it back.

**Rotate the keys** from the ground console:

```
ground> rotate
```

You will see three lines:
- `[OTAR] Uploading keys ID 2, wrapped with the KEK`
- `Keys received on board. Activating them`
- `Rotation done: key ID 2 is active`

On the screen, the **1** changes to **2**.

**Repeat the attack** with the same leaked key: now it says `Rejected` and an `invalid MAC` event arrives at ground.

**Check that the rotation survives a reset:** press **RST**, then on ground run `sync` and `ping`. Key 2 is still active, because it is saved in flash.

## Step 7. Bypass without security

```powershell
py attacks\attack_f3.py --sat 192.168.33.108 bypass
```

The attacker tries the two "special" frame types: BD (skips the FARM) and BC (commands the FARM). **Two security events** arrive: bypass skips the sequence control, never SDLS.

## Step 8. Flooding

```powershell
py attacks\attack_f3.py --sat 192.168.33.108 flood --n 300
```

While it runs, send `color green` from ground. You should see:
- on ground, **only a few** events and then `FLOOD: N more security events, summarized in this message`;
- your `color green` arrives (maybe with a retransmission);
- in `status`, the total rejections and the **summarized events**: the count is not lost.

Without the limit, the satellite would have sent 300 telemetry frames and the ground station would have drowned.

## Step 9 (optional). No board, and tests

```powershell
py tools\fake_satellite_f3.py
py ground\gs_f3.py --sat 127.0.0.1 --loss 0.3
py -m unittest discover -s tests
```

## Phase 3 checklist

- [ ] With `--loss 0.4` all colors arrive, in order
- [ ] After a board reset, the lockout is cleared with `sync`
- [ ] The leaked key works before `rotate` and fails after it
- [ ] The screen shows ID 2 and keeps it after a reset
- [ ] `bypass` and `flood` do not affect operations, and `flood` is summarized

## If something fails

| Symptom | Likely cause |
| --- | --- |
| `Keys are missing in secrets.h` when compiling | The three lines from step 1 are missing (the KEK is new) |
| The console stays at `Could not sync the FARM` | The keys in `secrets.h` are not the ones in `keys_f3.json`, or the IP changed |
| `rotate` says `key ID is not higher than the active one` | You generated `keys_f3.json` again but the board has a rotated key. Reflash with the new lines |
| Lockout all the time | Type `sync`. If it happens again without a board reset, check if another ground console is open |
