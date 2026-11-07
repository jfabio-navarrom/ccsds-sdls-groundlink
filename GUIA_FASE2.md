# Guía paso a paso: fase 2 (SDLS)

Objetivo de la fase: **proteger el enlace con SDLS** (CCSDS 355.0-B). Cada trama irá cifrada y autenticada con AES-256-GCM y llevará un contador anti-replay. Luego repetirás los ataques de la fase 1 y verás cómo **fallan todos** y llegan como eventos de seguridad a la estación de tierra.

Tiempo estimado: 45-60 minutos.

## Qué ha cambiado

| | Fase 1 | Fase 2 |
| --- | --- | --- |
| Telecomando | trama TC de 18 bytes, en claro | 48 bytes: + SPI, IV, datos cifrados y MAC |
| Telemetría | en claro | cifrada y autenticada (otra clave) |
| Replay | aceptado | rechazado: el IV ya se usó |
| Inyección | aceptada | rechazada: no hay MAC válida |
| A quién responde | a cualquiera | solo a quien demuestra tener la clave |
| Pantalla | franja ámbar, OK / ERR / SEQ | franja **verde**, OK / ERR / **SEC** |

## Paso 1. Instalar la librería de cifrado en el PC

```powershell
py -m pip install cryptography
```

## Paso 2. Generar las claves

Desde la carpeta del proyecto:

```powershell
py tools\gen_keys_f2.py
```

Hace dos cosas:
- Guarda las claves de tierra en `ground\keys_f2.json`. Este archivo **no se sube a GitHub**.
- Imprime dos líneas que empiezan por `#define SDLS_TC_KEY` y `#define SDLS_TM_KEY`. Las necesitas en el paso 3.

Hay dos claves porque cada sentido del enlace usa la suya. El porqué está en [ADR-008](docs/adr/ADR-008-sdls-aes-gcm.md).

> Trata las claves como una contraseña. No las pegues en el chat ni salgan en capturas.

## Paso 3. Subir el firmware nuevo

1. En Arduino IDE abre `satellite\satellite_f2\satellite_f2.ino`.
2. Crea la pestaña `secrets.h` (⋯ > Nueva pestaña) con tu Wi-Fi **y las dos líneas del paso 2**:

```
#define WIFI_SSID "nombre_de_tu_wifi"
#define WIFI_PASS "contrasena_de_tu_wifi"
#define SDLS_TC_KEY {0x.., 0x.., ...}
#define SDLS_TM_KEY {0x.., 0x.., ...}
```

3. Pulsa **Subir**. Si sale `Faltan las claves en secrets.h`, es que no pegaste las dos líneas.
4. En la pantalla verás la franja de arriba **verde** (SDLS activo) y los contadores:
   - **OK**: telecomandos autenticados y aceptados
   - **ERR**: tramas rotas (CRC, longitud)
   - **SEC**: tramas rechazadas por seguridad
5. En el Monitor Serie verás también la línea `Anti-replay: ultimo IV de TC aceptado #...`.

## Paso 4. Abrir la consola de tierra

Cierra antes cualquier consola de la fase 1 (`salir`), porque usan el mismo puerto.

```powershell
py ground\gs_f2.py --sat 192.168.33.105
```

Prueba `color verde`, `hk` y `estado`. Ahora la línea de `[AIRE]` dice **TC cifrado enviado** y mide 48 bytes. **Copia la de `color verde`**: la usarás en los ataques.

## Paso 5. Repetir los ataques

Deja la consola de tierra abierta y usa otra ventana para el atacante. En cada ataque, fíjate en tres sitios:
- la ventana del atacante: no recibe respuesta;
- la pantalla del C5: sube **SEC** y la franja de abajo parpadea en rojo;
- la consola de tierra: llega una línea `[SEGURIDAD] EVENTO DE SEGURIDAD` con el motivo y la IP del atacante.

En los comandos, cambia `<hex>` por la trama que copiaste.

**1. El ataque de la fase 1, tal cual** (trama válida pero sin SDLS):
```powershell
py attacks\attack_f2.py --sat 192.168.33.105 inject
```
Motivo: `demasiado corta para SDLS`. La trama no lleva ni cabecera ni MAC.

**2. Falsificación** (trama SDLS bien formada, pero con una clave inventada):
```powershell
py attacks\attack_f2.py --sat 192.168.33.105 forge
```
Motivo: `MAC invalida`. Además, lleva un IV enorme a propósito. Si el satélite actualizara el contador antes de comprobar la MAC, la tierra quedaría bloqueada. Envía después `color azul` desde tierra para comprobar que sigue funcionando.

**3. Replay** (la trama de `color verde` que capturaste):
```powershell
py attacks\attack_f2.py --sat 192.168.33.105 replay <hex>
```
Motivo: `repeticion (replay)`. La MAC es correcta porque la trama es legítima, pero su IV ya se usó. **Este es el ataque que funcionaba en la fase 1.**

**4. Manipulación** (cambia un bit cifrado y recalcula el CRC):
```powershell
py attacks\attack_f2.py --sat 192.168.33.105 tamper <hex>
```
Motivo: `MAC invalida`. En la fase 1, `corrupt` lo detectaba el CRC. Aquí el atacante arregla el CRC, pero no puede arreglar la MAC sin la clave.

**5. Espionaje** (no envía nada, solo intenta leer la trama):
```powershell
py attacks\attack_f2.py espiar <hex>
```
Ve el SCID, el canal y el IV, pero los datos son ilegibles. En la fase 1 se veía `0801 00c800` («poner color verde»).

**6. El secuestro de telemetría ya no funciona.** Después de los ataques, espera 15 segundos y escribe `estado` en tierra: el HK sigue llegando. El satélite solo cambia de estación de tierra con un TC autenticado.

## Paso 6. Comprobar que el anti-replay sobrevive a un reinicio

1. Pulsa el botón **RST** de la placa, o desconéctala y vuelve a conectarla.
2. Repite el `replay <hex>` del paso 5.
3. Sigue rechazado, porque el último IV aceptado está guardado en la flash. Esto lo explica [ADR-009](docs/adr/ADR-009-anti-replay-y-gestion-de-iv.md).

Tras el reinicio, el satélite no sabe dónde está la tierra hasta que le mandas un comando. Escribe `ping` en la consola de tierra y verás de nuevo los eventos.

## Paso 7 (opcional). Practicar sin la placa

```powershell
py tools\fake_satellite_f2.py
py ground\gs_f2.py --sat 127.0.0.1
```

## Paso 8 (opcional). Tests

```powershell
py -m unittest discover -s tests
```

## Hito de la fase 2

- [ ] La consola de tierra funciona con el enlace cifrado
- [ ] `inject`, `forge`, `replay` y `tamper` son rechazados y llegan como eventos de seguridad
- [ ] `espiar` no puede leer el comando
- [ ] El HK ya no se puede secuestrar
- [ ] El replay sigue rechazado después de reiniciar la placa

## Si algo falla

| Síntoma | Causa probable |
| --- | --- |
| `Falta la libreria 'cryptography'` | No hiciste el paso 1 |
| `No encuentro las claves SDLS` | No hiciste el paso 2 desde la carpeta del proyecto |
| La tierra no recibe `PONG` y en la pantalla sube **SEC** con cada comando | Las claves de `secrets.h` no son las de `keys_f2.json`. Vuelve a copiar las líneas: `py tools\gen_keys_f2.py` las imprime otra vez |
| La consola no recibe nada | Firewall de Windows: permite Python en redes privadas |
