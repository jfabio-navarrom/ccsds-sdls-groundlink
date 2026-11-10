"""
Escanea la base de datos de SA del enlace con las politicas de
ccsds-policy-as-code (Conftest/OPA) y la compara con el registro de riesgos
aceptados.

    py tools\\check_policy.py --politicas ..\\ccsds-policy-as-code\\policy

Falla (codigo 1) si hay hallazgos nuevos, aceptaciones que ya no aplican o
aceptaciones con la revision vencida. Necesita 'conftest' en el PATH y PyYAML.
"""

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SA_DB = os.path.join(ROOT, "docs", "arquitectura", "groundlink.sdls.yaml")
ACCEPTED = os.path.join(ROOT, "docs", "arquitectura", "riesgos-aceptados.yaml")


def target_of(msg: str) -> str:
    m = re.search(r"SA spi=(\d+)", msg)
    if m:
        return f"spi={m.group(1)}"
    m = re.search(r"VC ([\w-]+)", msg)
    return f"vc={m.group(1)}" if m else "?"


def parse_conftest(output: str) -> set:
    """Devuelve {(nivel, policy_id, objetivo)} a partir de 'conftest -o json'."""
    found = set()
    for result in json.loads(output):
        for level, key in (("fail", "failures"), ("warn", "warnings")):
            for f in result.get(key) or []:
                found.add((level, f["metadata"]["policy_id"], target_of(f["msg"])))
    return found


def compare(found: set, accepted: list, today: dt.date) -> list:
    """Lista de problemas (vacia = todo en orden)."""
    problems = []
    covered = set()
    for a in accepted:
        for tgt in a["objetivo"]:
            covered.add((a["policy_id"], tgt))
            if not any(pid == a["policy_id"] and t == tgt for _, pid, t in found):
                problems.append(f"ACEPTACION CADUCADA: {a['policy_id']} {tgt} ya no aparece; borrala del registro")
        review = a["revisar_antes"]
        review = review if isinstance(review, dt.date) else dt.date.fromisoformat(str(review))
        if review < today:
            problems.append(f"REVISION VENCIDA: {a['policy_id']} debia revisarse antes de {review}")
    for level, pid, tgt in sorted(found):
        if (pid, tgt) not in covered:
            problems.append(f"HALLAZGO NUEVO ({level}): {pid} {tgt}")
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--politicas", required=True, help="carpeta policy/ de ccsds-policy-as-code")
    ap.add_argument("--conftest", default="conftest")
    args = ap.parse_args(argv)

    import yaml
    with open(ACCEPTED, encoding="utf-8") as fh:
        accepted = yaml.safe_load(fh)["aceptaciones"]
    proc = subprocess.run([args.conftest, "test", SA_DB, "-p", args.politicas, "--all-namespaces", "-o", "json"],
                          capture_output=True, text=True)
    if proc.returncode not in (0, 1):
        print(proc.stderr)
        return 2
    found = parse_conftest(proc.stdout)
    print(f"Hallazgos del escaneo: {len(found)}")
    for level, pid, tgt in sorted(found):
        print(f"  {level:4} {pid:12} {tgt}")
    problems = compare(found, accepted, dt.date.today())
    if problems:
        print("\nPROBLEMAS:")
        for p in problems:
            print("  " + p)
        return 1
    print("\nTodos los hallazgos estan aceptados, justificados y dentro de su fecha de revision.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
