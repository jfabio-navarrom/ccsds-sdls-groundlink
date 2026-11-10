"""
Scans the SA database of the link with the ccsds-policy-as-code policies
(Conftest/OPA) and compares the result with the accepted risks register.

    py tools\\check_policy.py --policies ..\\ccsds-policy-as-code\\policy

Fails (exit code 1) if there are new findings, acceptances that do not apply
anymore, or acceptances past their review date. Needs 'conftest' in the PATH
and PyYAML.
"""

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SA_DB = os.path.join(ROOT, "docs", "architecture", "groundlink.sdls.yaml")
ACCEPTED = os.path.join(ROOT, "docs", "architecture", "accepted-risks.yaml")


def target_of(msg: str) -> str:
    m = re.search(r"SA spi=(\d+)", msg)
    if m:
        return f"spi={m.group(1)}"
    m = re.search(r"VC ([\w-]+)", msg)
    return f"vc={m.group(1)}" if m else "?"


def parse_conftest(output: str) -> set:
    """Returns {(level, policy_id, target)} from 'conftest -o json'."""
    found = set()
    for result in json.loads(output):
        for level, key in (("fail", "failures"), ("warn", "warnings")):
            for f in result.get(key) or []:
                found.add((level, f["metadata"]["policy_id"], target_of(f["msg"])))
    return found


def compare(found: set, accepted: list, today: dt.date) -> list:
    """List of problems (empty = all good)."""
    problems = []
    covered = set()
    for a in accepted:
        for tgt in a["targets"]:
            covered.add((a["policy_id"], tgt))
            if not any(pid == a["policy_id"] and t == tgt for _, pid, t in found):
                problems.append(f"STALE ACCEPTANCE: {a['policy_id']} {tgt} is not found anymore; remove it from the register")
        review = a["review_by"]
        review = review if isinstance(review, dt.date) else dt.date.fromisoformat(str(review))
        if review < today:
            problems.append(f"REVIEW OVERDUE: {a['policy_id']} had to be reviewed before {review}")
    for level, pid, tgt in sorted(found):
        if (pid, tgt) not in covered:
            problems.append(f"NEW FINDING ({level}): {pid} {tgt}")
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--policies", required=True, help="policy/ folder of ccsds-policy-as-code")
    ap.add_argument("--conftest", default="conftest")
    args = ap.parse_args(argv)

    import yaml
    with open(ACCEPTED, encoding="utf-8") as fh:
        accepted = yaml.safe_load(fh)["acceptances"]
    proc = subprocess.run([args.conftest, "test", SA_DB, "-p", args.policies, "--all-namespaces", "-o", "json"],
                          capture_output=True, text=True)
    if proc.returncode not in (0, 1):
        print(proc.stderr)
        return 2
    found = parse_conftest(proc.stdout)
    print(f"Scan findings: {len(found)}")
    for level, pid, tgt in sorted(found):
        print(f"  {level:4} {pid:12} {tgt}")
    problems = compare(found, accepted, dt.date.today())
    if problems:
        print("\nPROBLEMS:")
        for p in problems:
            print("  " + p)
        return 1
    print("\nAll findings are accepted, justified and inside their review date.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
