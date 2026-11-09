# Guía paso a paso: fase 3 (claves, FARM-1 e inundación)

Objetivo de la fase: que el enlace no solo sea seguro, sino también **operable**:
- cambiar las claves sin tocar la placa;
- que no se pierdan telecomandos aunque la red falle;
- que un atacante no pueda tumbar la telemetría a base de basura.

Tiempo estimado: 60 minutos.

## Qué ha cambiado

| | Fase 2 | Fase 3 |
| --- | --- | --- |
| Claves | fijas en el firmware | rotables en vuelo con `rotar` (OTAR) |
| Clave filtrada | hay que reflashear | `rotar` y la clave vieja deja de servir |
| Telecomando perdido | se pierde sin aviso | la tierra lo retransmite sola (COP-1) |
| Orden de ejecución | sin garantía | en orden, sin duplicados (FARM-1) |
| 300 tramas falsas | 300 eventos de seguridad | 3 eventos + 1 resumen |
| Pantalla | franja verde | franja verde + **ID de clave activa** a la derecha |

## Paso 1. Generar las claves de la fase 3

Desde la carpeta del proyecto:

```powershell
py tools\gen_keys_f3.py
```

Ahora imprime **tres** líneas:
- `SDLS_KEK` es la clave maestra. Solo sirve para enviar claves nuevas. Es la más importante.
- `SDLS_TC_KEY` y `SDLS_TM_KEY` son las claves de tráfico iniciales (ID 1).

Las claves de tierra se guardan en `ground\keys_f3.json`, que no se sube a GitHub.

## Paso 2. Subir el firmware

1. En Arduino IDE abre `satellite\satellite_f3\satellite_f3.ino`.
2. Crea la pestaña `secrets.h` con tu Wi-Fi y las **tres** líneas del paso 1.
3. Pulsa **Subir**. Arriba a la derecha de la franja verde verás un **1**: el ID de la clave activa.
4. Apunta la IP del Monitor Serie (la última vez era la .108).

## Paso 3. Abrir la consola de tierra

```powershell
py ground\gs_f3.py --sat 192.168.33.108
```

Al arrancar hace dos cosas nuevas:
- `sync`: desbloquea el FARM y alinea los contadores. Verás dos líneas `TC BC`.
- `ping`: cada línea `[AIRE]` muestra ahora el tipo de trama (AD, BD o BC) y su **N(S)**.

Prueba `color verde` y `estado`. En `estado` hay dos líneas nuevas: **FARM (CLCW)**, la trama que espera el satélite, y **FOP**, la siguiente que enviará la tierra.

## Paso 4. COP-1: telecomandos que no se pierden

Cierra la consola (`salir`) y ábrela simulando un canal que pierde el 40 % de las tramas:

```powershell
py ground\gs_f3.py --sat 192.168.33.108 --perdida 0.4
```

Envía varios colores seguidos. Verás líneas como estas:

```
[CANAL] trama N(S)=3 perdida por el camino (simulado)
[FOP] Sin confirmacion de N(S)=3: retransmito (intento 2, IV nuevo)
```

Cada color acaba llegando, y en orden. Fíjate en **IV nuevo**: la retransmisión no puede reutilizar el IV, porque el anti-replay la rechazaría. El porqué está en [ADR-011](docs/adr/ADR-011-cop1-e-inundacion.md).

Cierra y vuelve a abrir la consola sin `--perdida` para los pasos siguientes.

## Paso 5. Reinicio del satélite y lockout

1. Con la consola abierta, pulsa **RST** en la placa y espera a que se conecte.
2. Envía `color azul`. Verás `El FARM del satelite esta BLOQUEADO (lockout)`: el satélite se reinició, espera la trama 0 y la tierra iba por otra.
3. Escribe `sync` y repite `color azul`. Ahora funciona.

El lockout no es un fallo: es una alarma de que algo raro ha pasado con el satélite. Por eso el desbloqueo lo hace el operador, no la máquina.

## Paso 6. Clave filtrada y rotación (el caso de la fase 2)

Supón que la clave TC se ha filtrado. Ábrela en `ground\keys_f3.json` y copia el valor de `"tc"` dentro de `"active"`. **No lo pegues en el chat.**

**Antes de rotar**, el atacante usa la clave filtrada desde otra ventana:

```powershell
py attacks\attack_f3.py --sat 192.168.33.108 filtrada <clave_tc>
```

La pantalla se pone **roja**: con la clave, el atacante manda. Usa una trama BD (bypass) para no tener que adivinar la N(S). Además, ahora la telemetría va al atacante, aunque no pueda leerla porque no tiene la clave TM. Envía `ping` desde tierra para recuperarla.

**Rota las claves** desde la consola de tierra:

```
tierra> rotar
```

Verás tres líneas:
- `[OTAR] Subo las claves ID 2, envueltas con la KEK`
- `Claves recibidas a bordo. Las activo`
- `Rotacion completada: clave ID 2 activa`

En la pantalla, el **1** pasa a **2**.

**Repite el ataque** con la misma clave filtrada: ahora sale `Rechazada` y llega un evento `MAC invalida` a tierra.

**Comprueba que la rotación sobrevive a un reinicio:** pulsa **RST** y luego, en tierra, `sync` y `ping`. Sigue la clave 2, porque está guardada en la flash.

## Paso 7. Bypass sin seguridad

```powershell
py attacks\attack_f3.py --sat 192.168.33.108 bypass
```

El atacante prueba los dos tipos de trama «especiales»: BD (se salta el FARM) y BC (manda al FARM). Llegan **dos eventos de seguridad**: el bypass se salta el control de secuencia, nunca SDLS.

## Paso 8. Inundación

```powershell
py attacks\attack_f3.py --sat 192.168.33.108 flood --n 300
```

Mientras dura, envía `color verde` desde tierra. Deberías ver:
- en tierra, **solo unos pocos** eventos y luego `INUNDACION: N eventos de seguridad mas, resumidos en este aviso`;
- tu `color verde` llega (quizá con alguna retransmisión);
- en `estado`, los rechazos totales y los **eventos resumidos**: no se pierde la cuenta.

Sin el límite, el satélite habría enviado 300 tramas de telemetría y la estación de tierra se habría ahogado.

## Paso 9 (opcional). Sin placa y tests

```powershell
py tools\fake_satellite_f3.py
py ground\gs_f3.py --sat 127.0.0.1 --perdida 0.3
py -m unittest discover -s tests
```

## Hito de la fase 3

- [ ] Con `--perdida 0.4` todos los colores llegan, en orden
- [ ] Tras reiniciar la placa, el lockout se resuelve con `sync`
- [ ] La clave filtrada funciona antes de `rotar` y falla después
- [ ] La pantalla muestra el ID 2 y lo conserva tras reiniciar
- [ ] `bypass` y `flood` no afectan a la operación, y `flood` queda resumido

## Si algo falla

| Síntoma | Causa probable |
| --- | --- |
| `Faltan claves en secrets.h` al compilar | Faltan las tres líneas del paso 1 (la KEK es nueva) |
| La consola se queda en `No se pudo sincronizar el FARM` | Las claves de `secrets.h` no son las de `keys_f3.json`, o la IP ha cambiado |
| `rotar` dice `ID de clave no es mayor que el activo` | Has regenerado `keys_f3.json` pero la placa tiene una clave rotada. Reflashea con las líneas nuevas |
| Lockout constante | Escribe `sync`. Si vuelve a pasar sin reiniciar la placa, revisa si hay otra consola de tierra abierta |
