# Guía paso a paso: fase 1

Objetivo de la fase: **el satélite y la tierra dejan de hablar con texto y pasan a usar tramas CCSDS reales**, las mismas que usan ESA y NASA. Además, el satélite envía telemetría cada 5 segundos. Y vas a comprobar que, aunque el protocolo sea "de verdad", **sin SDLS sigue sin haber seguridad**.

Tiempo estimado: 30-45 minutos.

## Qué ha cambiado

| | Fase 0 | Fase 1 |
| --- | --- | --- |
| Telecomando | texto: `LED 0 200 0` | trama TC CCSDS de 18 bytes con CRC |
| Respuesta | texto: `ACK LED` | trama TM CCSDS de 128 bytes con CLCW |
| Telemetría | no hay | informe de housekeeping (HK) cada 5 s |
| Pantalla | color | color + contadores OK / ERR / SEQ |
| Tierra | un comando por ejecución | consola interactiva `gs_f1.py` |

## Paso 1. Subir el firmware nuevo

1. Descarga y descomprime el proyecto encima de tu carpeta, o haz `git pull` si ya usas Git.
2. En Arduino IDE abre `satellite\satellite_f1\satellite_f1.ino`. Es una carpeta nueva; la de la fase 0 se queda como estaba.
3. Crea otra vez la pestaña `secrets.h` (⋯ > Nueva pestaña) con tu Wi-Fi:

```
#define WIFI_SSID "nombre_de_tu_wifi"
#define WIFI_PASS "contrasena_de_tu_wifi"
```

4. Pulsa **Subir**. En la pantalla verás la franja ámbar, el recuadro de la carga útil y debajo tres contadores:
   - **OK**: telecomandos aceptados
   - **ERR**: telecomandos rechazados
   - **SEQ**: número de secuencia de la última trama aceptada
5. En el Monitor Serie comprueba la IP. Suele ser la misma de antes.

## Paso 2. Abrir la consola de tierra

```powershell
cd <carpeta donde descomprimiste el proyecto>
py ground\gs_f1.py --sat 192.168.33.105
```

- La primera vez, Windows puede preguntar por el firewall: permite **redes privadas**. Si no, la telemetría no llegará.
- Al arrancar, la consola envía un `ping` y deberías ver `PONG: el satelite responde`.

Prueba estos comandos:

```
tierra> color verde
tierra> hk
tierra> estado
tierra> salir
```

Cada comando muestra una línea `[AIRE] TC enviado (...)`: son los bytes exactos que viajan por el enlace. **Copia la de `color verde`**, porque la usarás en el paso 4.

## Paso 3. Entender una trama TC

Esta es la trama de `color verde`, byte a byte:

| Bytes | Campo | Significado |
| --- | --- | --- |
| `00 c5` | Cabecera TC | versión 0, sin bypass, **SCID 0x0C5** (nuestro satélite) |
| `00 11` | | canal virtual 0, longitud 0x011 + 1 = 18 bytes |
| `01` | | número de secuencia de trama N(S) = 1 |
| `10 10` | Space Packet | tipo telecomando, **APID 0x010** (aplicación de a bordo) |
| `c0 01` | | paquete no segmentado, número de paquete 1 |
| `00 04` | | 5 bytes de datos |
| `08 01` | Servicio PUS-lite | servicio 8, subservicio 1 = "poner color" |
| `00 c8 00` | Datos | R = 0, G = 200, B = 0 |
| `fa 2b` | FECF | CRC-16 de todo lo anterior |

Fíjate en lo que **no** hay: ninguna firma, ninguna clave, nada que demuestre quién la envió.

## Paso 4. Los ataques de la fase 1

Deja la consola de tierra abierta en una ventana y abre **otra ventana de PowerShell** para el atacante.

**Inyección**: el atacante fabrica una trama perfecta, con su CRC, sin conocer ningún secreto. El SCID tampoco es secreto: en la realidad se publica.

```powershell
py attacks\attack_f1.py --sat 192.168.33.105 inject
```

La pantalla se pone roja y el contador **OK** sube. Ahora espera 15 segundos y escribe `estado` en la consola de tierra: verás un aviso de que no llega telemetría. El satélite ha tomado al atacante por la estación de tierra y **le manda a él el housekeeping**. Envía cualquier comando desde tierra para recuperarlo.

**Replay**: reenvía la trama de `color verde` que copiaste en el paso 2.

```powershell
py attacks\attack_f1.py --sat 192.168.33.105 replay 00c50011011010c0010004080100c800fa2b
```

El satélite la acepta otra vez, aunque su número de secuencia es viejo (mira cómo **SEQ** vuelve atrás). No tiene forma de saber que es una copia.

**Corrupción**: la misma trama con un bit cambiado.

```powershell
py attacks\attack_f1.py --sat 192.168.33.105 corrupt 00c50011011010c0010004080100c800fa2b
```

Ahora sí la rechaza: sube **ERR** y la franja de abajo parpadea en rojo. **Conclusión: el CRC protege contra errores de transmisión, no contra atacantes**, porque cualquiera puede calcularlo. Para eso hace falta autenticación criptográfica: SDLS, en la fase 2.

## Paso 5 (opcional). Practicar sin la placa

Hay un satélite simulado en Python que se comporta igual que el firmware:

```powershell
py tools\fake_satellite_f1.py
```

Y en otra ventana:

```powershell
py ground\gs_f1.py --sat 127.0.0.1
```

## Paso 6 (opcional). Ejecutar los tests

```powershell
py -m unittest discover -s tests -v
```

Los tests de interoperabilidad C++ ↔ Python se saltan en tu PC porque necesitan compilar C++. En GitHub se ejecutan solos en cada cambio (pestaña **Actions** del repo).

## Hito de la fase 1

- [ ] La consola de tierra recibe `PONG` y housekeeping
- [ ] La pantalla muestra los contadores OK / ERR / SEQ
- [ ] `inject` y `replay` son aceptados y `corrupt` es rechazado
- [ ] Has visto cómo el atacante secuestra la telemetría
