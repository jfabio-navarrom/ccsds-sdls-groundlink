"""
Genera las dos claves SDLS de la fase 2 (AES-256): una para los TC
(tierra -> satelite, SPI 1) y otra para la TM (satelite -> tierra, SPI 2).

- Guarda las claves de tierra en ground/keys_f2.json (no se sube a GitHub).
- Imprime las dos lineas que tienes que pegar en secrets.h del satelite.

Uso:
    py tools\\gen_keys_f2.py            (no sobrescribe si ya existen)
    py tools\\gen_keys_f2.py --nuevas   (genera otras y sustituye las anteriores)
"""

import argparse
import json
import os
import secrets
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ground"))

from ccsds.keystore import KEYS_PATH  # noqa: E402


def c_array(key: bytes) -> str:
    return "{" + ", ".join(f"0x{b:02x}" for b in key) + "}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Genera las claves SDLS de la fase 2")
    ap.add_argument("--nuevas", action="store_true", help="sustituir las claves existentes")
    args = ap.parse_args(argv)

    if os.path.exists(KEYS_PATH) and not args.nuevas:
        with open(KEYS_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        print("Ya tenias claves en ground/keys_f2.json; no las cambio (usa --nuevas para cambiarlas).")
    else:
        data = {"tc_key": secrets.token_bytes(32).hex(), "tm_key": secrets.token_bytes(32).hex()}
        with open(KEYS_PATH, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        print("Claves nuevas guardadas en ground/keys_f2.json (este archivo NO se sube a GitHub).")

    print()
    print("Copia estas dos lineas en la pestana secrets.h del satelite (satellite_f2),")
    print("debajo de WIFI_PASS:")
    print()
    print(f"#define SDLS_TC_KEY {c_array(bytes.fromhex(data['tc_key']))}")
    print(f"#define SDLS_TM_KEY {c_array(bytes.fromhex(data['tm_key']))}")
    print()
    print("Trata estas claves como una contrasena: no las pegues en chats ni capturas.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
