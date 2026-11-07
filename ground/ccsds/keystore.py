"""
Claves SDLS y contador de IV de la estacion de tierra (fase 2).

- Las claves viven en ground/keys_f2.json, que crea tools/gen_keys_f2.py
  y que NUNCA se sube a GitHub (.gitignore).
- El contador de IV de los TC tiene que crecer siempre, aunque cierres la
  consola o borres el estado: si repitiera un IV, el satelite rechazaria
  el TC como replay (y, peor, en GCM repetir IV con la misma clave filtra
  informacion). Por eso usamos max(ultimo_guardado + 1, reloj en microsegundos):
  aunque se pierda el archivo de estado, el reloj ya va por delante.
"""

import json
import os
import time

GROUND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
KEYS_PATH = os.path.join(GROUND_DIR, "keys_f2.json")
STATE_PATH = os.path.join(GROUND_DIR, "state_f2.json")


class KeysMissing(Exception):
    pass


def load_keys(path: str = KEYS_PATH) -> tuple:
    """Devuelve (clave_tc, clave_tm) como bytes."""
    if not os.path.exists(path):
        raise KeysMissing(
            "No encuentro las claves SDLS (ground/keys_f2.json). Generalas con:\n"
            "    py tools\\gen_keys_f2.py\n"
            "y copia en secrets.h del satelite las dos lineas que imprime.")
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return bytes.fromhex(data["tc_key"]), bytes.fromhex(data["tm_key"])


class IvCounter:
    """Contador monotono para el IV de los TC, guardado en disco."""

    def __init__(self, path: str = STATE_PATH):
        self.path = path
        self.last = 0
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    self.last = int(json.load(fh).get("tc_iv", 0))
            except (ValueError, OSError):
                self.last = 0

    def next(self) -> int:
        self.last = max(self.last + 1, time.time_ns() // 1000)
        try:
            with open(self.path, "w", encoding="utf-8") as fh:
                json.dump({"tc_iv": self.last}, fh)
        except OSError:
            pass
        return self.last
