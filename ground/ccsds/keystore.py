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


# ------------------------------- Fase 3 ---------------------------------

KEYS_F3_PATH = os.path.join(GROUND_DIR, "keys_f3.json")
STATE_F3_PATH = os.path.join(GROUND_DIR, "state_f3.json")


class KeyStoreF3:
    """
    Claves de la fase 3, en ground/keys_f3.json (NUNCA se sube a GitHub):
      kek       clave maestra: solo envuelve claves nuevas (OTAR)
      active    {id, tc, tm}: claves de trafico en uso
      pending   {id, tc, tm} o null: subidas pero todavia no activadas
      retired   IDs ya retirados (las claves en si se borran)
    """

    def __init__(self, path: str = KEYS_F3_PATH):
        self.path = path
        if not os.path.exists(path):
            raise KeysMissing(
                "No encuentro las claves de la fase 3 (ground/keys_f3.json). Generalas con:\n"
                "    py tools\\gen_keys_f3.py\n"
                "y copia en secrets.h del satelite las tres lineas que imprime.")
        with open(path, encoding="utf-8") as fh:
            self.data = json.load(fh)

    @staticmethod
    def create(path: str, kek: bytes, tc: bytes, tm: bytes) -> None:
        data = {"kek": kek.hex(), "active": {"id": 1, "tc": tc.hex(), "tm": tm.hex()},
                "pending": None, "retired": []}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)

    def save(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=2)
        os.replace(tmp, self.path)

    @property
    def kek(self) -> bytes:
        return bytes.fromhex(self.data["kek"])

    @property
    def active_id(self) -> int:
        return self.data["active"]["id"]

    def active(self) -> tuple:
        a = self.data["active"]
        return bytes.fromhex(a["tc"]), bytes.fromhex(a["tm"])

    def pending(self):
        p = self.data.get("pending")
        if not p:
            return None
        return p["id"], bytes.fromhex(p["tc"]), bytes.fromhex(p["tm"])

    def set_pending(self, key_id: int, tc: bytes, tm: bytes) -> None:
        self.data["pending"] = {"id": key_id, "tc": tc.hex(), "tm": tm.hex()}
        self.save()

    def activate_pending(self) -> int:
        p = self.data["pending"]
        self.data["retired"].append(self.data["active"]["id"])
        self.data["active"] = p
        self.data["pending"] = None
        self.save()
        return p["id"]
