# Step by step guide: phase 0

Goal of this phase: **you send a telecommand from your PC and the C5 screen changes color.** Then you check that an "attacker" can do the same, because there is no security yet. This is the "before" of the demo.

Time: 1 or 2 hours the first time. You don't need to know C: you only copy, configure and run.

## What you need

- The **Waveshare ESP32-C5-Touch-LCD-2.8** board and a USB-C **data** cable. Some cables only charge; if the PC does not see the board, try another cable.
- Your Windows PC, on the **same Wi-Fi** that the C5 will join.
- The `ccsds-sdls-groundlink` folder on your PC, for example in `C:\projects\ccsds-sdls-groundlink`.

## Step 1. Install Arduino IDE 2

1. Download it from https://www.arduino.cc/en/software and install it with the default options.
2. Open it.

## Step 2. Add the Espressif boards

1. Open **File > Preferences**.
2. In **"Additional boards manager URLs"** paste:
   `https://espressif.github.io/arduino-esp32/package_esp32_index.json`
3. Click OK.
4. Open **Tools > Board > Boards Manager**, search `esp32` and install **"esp32 by Espressif Systems"**, version **3.3.0 or newer** (older ones do not have the C5).

## Step 3. Open the sketch and set your Wi-Fi

1. In Arduino IDE: **File > Open** and choose `satellite\satellite_f0\satellite_f0.ino`.
2. In Windows Explorer, inside `satellite\satellite_f0\`, copy `secrets.example.h` and rename the copy to **`secrets.h`**.
   - Careful: Windows sometimes hides file extensions and the file ends up as `secrets.h.txt`. Turn on **View > Show > File name extensions** to check.
3. Close and open the sketch again. You will see a `secrets.h` tab. Write the name and password of your Wi-Fi between the quotes.

`secrets.h` is never pushed to GitHub: it is in `.gitignore`.

## Step 4. Connect the board

1. Connect the board to the PC with USB.
2. **Tools > Board > esp32 > ESP32C5 Dev Module**. Settings that Waveshare recommends for this board: **Flash Size: 16MB**, **PSRAM: Enabled** and **Partition Scheme: 16M Flash (3MB APP/9.9MB FATFS)**.
3. **Tools > Port** and choose the COM port that shows up (for example `COM5`).
   - If no COM port shows up: try another cable. If it still does not show up, check which USB chip your board has (CP210x or CH343) and install its driver.

## Step 5. Upload the firmware

1. Click the **→ (Upload)** arrow.
2. If you get `Failed to connect`, hold the **BOOT** button on the board when the upload starts and release it when you see the percentage.
3. When it finishes, the screen turns on: **amber bar on top** (mode with no security), center box **dark blue** while it connects to Wi-Fi, and **black** when it is ready.

## Step 6. Find the satellite IP

1. Open **Tools > Serial Monitor** and set the speed to **115200**.
2. Press the **RESET** (or EN) button on the board. You should see:

```
[SAT] Simulated satellite - phase 0 (NO security)
[SAT] Connecting to the Wi-Fi....
[SAT] Connected. MY IP IS: 192.168.1.50
[SAT] Listening for telecommands on UDP 10025
```

3. **Write down that IP**. You need it in the next steps.
   - If the monitor stays empty: set **Tools > USB CDC On Boot > Enabled**, upload the sketch again and repeat.
   - If it stays on `Connecting...` forever: check the password in `secrets.h`.

## Step 7. Install Python

1. Download it from https://www.python.org/downloads/ (version 3.12 or newer).
2. In the installer, **tick "Add python.exe to PATH"** before you click Install.
3. Open **PowerShell** and check it works with `py --version`. On Windows always use `py` to run the scripts; `python` can open the Microsoft Store instead.

The scripts of this phase do not need anything else.

## Step 8. Be the ground station

In PowerShell, go to the project folder and run these commands, with your IP:

```powershell
cd C:\projects\ccsds-sdls-groundlink
py ground\ground_f0.py --sat 192.168.1.50 ping
py ground\ground_f0.py --sat 192.168.1.50 led blue
py ground\ground_f0.py --sat 192.168.1.50 led off
```

You should see `PONG` and `ACK LED`. The center box of the screen changes color and the bottom bar blinks white with each telecommand. The Serial Monitor shows each telecommand received.

- If Windows asks about the firewall, allow access on **private networks**.
- If there is no answer: check that the PC and the C5 are on the same Wi-Fi. Some routers isolate devices on the guest network from each other.

## Step 9. Be the attacker (the "before")

```powershell
py attacks\attack_f0.py --sat 192.168.1.50 inject
py attacks\attack_f0.py --sat 192.168.1.50 replay --times 3
```

- `inject`: the screen goes **red**. A program that is not the ground station took control of the payload.
- `replay`: sends a "captured" telecommand again, and the satellite accepts it every time.

Look at the Serial Monitor: the satellite has no way to know who is talking to it. It only sees an IP, which is easy to fake, and on a real radio link it would not even have that. **This is the problem SDLS solves in phase 2.**

## Phase 0 checklist

- [ ] The screen changes color with `ground_f0.py`
- [ ] `attack_f0.py inject` turns the screen red
- [ ] Screenshot or short video of the attack working (used in the README as the "before")
- [ ] Repo created on GitHub with these files
