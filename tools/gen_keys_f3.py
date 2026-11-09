"""
Genera las claves de la fase 3:
  - KEK (clave maestra): solo sirve para enviar claves nuevas en vuelo (OTAR)
  - clave TC y clave TM iniciales (ID 1)

- Guarda las claves de tierra en ground/keys_f3.json (no se sube a GitHub).
- Imprime las tres lineas que tienes que pegar en secrets.h del satelite.

Despues de esto, para cambiar las claves de trafico NO hace falta volver a
generar nada ni reflashear: usa el comando 'rotar' de la consola de tierra.

Uso:
    py tools\\gen_keys_f3.py            (no sobrescribe si ya existen)
    py tools\\gen_keys_f3.py --nuevas   (empieza de cero: hay que reflashear)
"""

import argparse
import os
import secrets
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ground"))

from ccsds.keystore import KEYS_F3_PATH, KeyStoreF3  # noqa: E402


def c_array(key: bytes) -> str:
    return "{" + ", ".join(f"0x{b:02x}" for b in key) + "}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Genera las claves de la fase 3")
    ap.add_argument("--nuevas", action="store_true", help="sustituir las claves existentes")
    args = ap.parse_args(argv)

    if os.path.exists(KEYS_F3_PATH) and not args.nuevas:
        print("Ya tenias claves en ground/keys_f3.json; no las cambio (usa --nuevas para empezar de cero).")
    else:
        KeyStoreF3.create(KEYS_F3_PATH, secrets.token_bytes(32), secrets.token_bytes(32), secrets.token_bytes(32))
        print("Claves nuevas guardadas en ground/keys_f3.json (este archivo NO se sube a GitHub).")
    ks = KeyStoreF3(KEYS_F3_PATH)
    if ks.active_id != 1:
        print(f"OJO: la clave activa ya es la ID {ks.active_id} (rotada en vuelo). Las lineas de abajo son")
        print("la KEK y las claves ACTUALES; si reflasheas, el satelite volvera a empezar con ellas.")
    tc, tm = ks.active()
    print()
    print("Copia estas tres lineas en la pestana secrets.h del satelite (satellite_f3),")
    print("debajo de WIFI_PASS:")
    print()
    print(f"#define SDLS_KEK {c_array(ks.kek)}")
    print(f"#define SDLS_TC_KEY {c_array(tc)}")
    print(f"#define SDLS_TM_KEY {c_array(tm)}")
    print()
    print("Trata estas claves como una contrasena: no las pegues en chats ni capturas.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
