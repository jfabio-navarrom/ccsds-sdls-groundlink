"""
Estacion de tierra - fase 0 (SIN seguridad).

Envia telecomandos por UDP al "satelite" (ESP32-C5) y muestra su respuesta.
Solo usa la libreria estandar de Python: no hace falta instalar nada.

Uso (en PowerShell, dentro de la carpeta del proyecto):
    python ground/ground_f0.py --sat 192.168.1.50 ping
    python ground/ground_f0.py --sat 192.168.1.50 led verde
    python ground/ground_f0.py --sat 192.168.1.50 led apagado
"""

import argparse
import socket
import sys

TC_PORT = 10025

# Colores que la estacion de tierra puede poner en la pantalla (la carga util).
# El rojo intenso queda reservado para el atacante en la demo.
COLORES = {
    "verde": (0, 200, 0),
    "azul": (0, 90, 255),
    "amarillo": (255, 200, 0),
    "blanco": (255, 255, 255),
    "apagado": (0, 0, 0),
}


def enviar_tc(ip: str, texto: str, port: int = TC_PORT, timeout: float = 2.0):
    """Envia un telecomando y espera la respuesta. Devuelve el texto o None."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(texto.encode("ascii"), (ip, port))
        try:
            datos, _ = s.recvfrom(256)
            return datos.decode("ascii", errors="replace")
        except (socket.timeout, ConnectionResetError):
            # En Windows, si nadie escucha en ese puerto, llega un
            # ConnectionResetError en vez de un timeout
            return None


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Estacion de tierra (fase 0)")
    p.add_argument("--sat", required=True, help="IP del C5 (la ves en el Monitor Serie)")
    p.add_argument("--port", type=int, default=TC_PORT, help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("ping", help="comprobar que el satelite responde")
    led = sub.add_parser("led", help="cambiar el color de la pantalla (carga util)")
    led.add_argument("color", choices=sorted(COLORES))
    args = p.parse_args(argv)

    if args.cmd == "ping":
        tc = "PING"
    else:
        r, g, b = COLORES[args.color]
        tc = f"LED {r} {g} {b}"

    print(f"[TIERRA] Enviando TC -> {args.sat}:{args.port}  \"{tc}\"")
    respuesta = enviar_tc(args.sat, tc, port=args.port)
    if respuesta is None:
        print("[TIERRA] Sin respuesta en 2 s. Revisa la IP, que el C5 este encendido "
              "y que ambos esten en la misma Wi-Fi.")
        return 1
    print(f"[TIERRA] Respuesta del satelite: {respuesta}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
