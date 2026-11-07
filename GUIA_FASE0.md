# Guía paso a paso: fase 0

Objetivo de la fase: **desde tu PC mandas un telecomando y la pantalla del C5 cambia de color.** Después compruebas que un "atacante" puede hacer lo mismo, porque todavía no hay seguridad. Ese es el "antes" de la demo.

Tiempo estimado: 1 o 2 horas la primera vez. No hace falta saber C: solo vas a copiar, configurar y ejecutar.

## Qué necesitas

- Tu placa **Waveshare ESP32-C5-Touch-LCD-2.8** y un cable USB-C **de datos**. Algunos cables solo cargan; si el PC no detecta la placa, prueba con otro cable.
- Tu PC con Windows, conectado a la **misma Wi-Fi** a la que se conectará el C5.
- La carpeta `ccsds-sdls-groundlink` copiada en tu PC, por ejemplo en `C:\proyectos\ccsds-sdls-groundlink`.

## Paso 1. Instalar Arduino IDE 2

1. Descárgalo de https://www.arduino.cc/en/software e instálalo con las opciones por defecto.
2. Ábrelo. Si quieres el menú en español: **File > Preferences > Language**.

## Paso 2. Añadir las placas de Espressif

1. Abre **Archivo > Preferencias** (File > Preferences).
2. En **"URLs adicionales de gestor de placas"** pega:
   `https://espressif.github.io/arduino-esp32/package_esp32_index.json`
3. Pulsa OK.
4. Abre **Herramientas > Placa > Gestor de placas**, busca `esp32` e instala **"esp32 by Espressif Systems"**, versión **3.3.0 o superior** (las anteriores no tienen el C5).

## Paso 3. Abrir el sketch y poner tu Wi-Fi

1. En Arduino IDE: **Archivo > Abrir** y elige `satellite\satellite_f0\satellite_f0.ino`.
2. En el Explorador de Windows, dentro de `satellite\satellite_f0\`, copia `secrets.example.h` y renombra la copia a **`secrets.h`**.
   - Ojo: Windows a veces oculta las extensiones y el archivo acaba llamándose `secrets.h.txt`. Activa **Vista > Mostrar > Extensiones de nombre de archivo** para comprobarlo.
3. Cierra y vuelve a abrir el sketch. Verás una pestaña `secrets.h`. Escribe ahí el nombre y la contraseña de tu Wi-Fi entre las comillas.

`secrets.h` nunca se sube a GitHub: está en `.gitignore`.

## Paso 4. Conectar la placa

1. Conecta la placa al PC por USB.
2. **Herramientas > Placa > esp32 > ESP32C5 Dev Module**. Ajustes que recomienda Waveshare para esta placa: **Flash Size: 16MB**, **PSRAM: Enabled** y **Partition Scheme: 16M Flash (3MB APP/9.9MB FATFS)**.
3. **Herramientas > Puerto** y elige el COM que aparece (por ejemplo `COM5`).
   - Si no aparece ningún COM: prueba otro cable. Si sigue sin aparecer, mira qué chip USB lleva tu placa (CP210x o CH343) e instala su driver.

## Paso 5. Subir el firmware

1. Pulsa la flecha **→ (Subir)**.
2. Si sale `Failed to connect`, mantén pulsado el botón **BOOT** de la placa mientras empieza la subida y suéltalo cuando veas el porcentaje.
3. Cuando termine, la pantalla se enciende: **franja ámbar arriba** (modo sin seguridad), recuadro central **azul oscuro** mientras conecta a la Wi-Fi y **negro** cuando está listo.

## Paso 6. Ver la IP del satélite

1. Abre **Herramientas > Monitor Serie** y pon la velocidad en **115200**.
2. Pulsa el botón **RESET** (o EN) de la placa. Deberías ver:

```
[SAT] Satelite simulado - fase 0 (SIN seguridad)
[SAT] Conectando a la Wi-Fi....
[SAT] Conectado. MI IP ES: 192.168.1.50
[SAT] Escuchando telecomandos en UDP 10025
```

3. **Apunta esa IP**; la usarás en los siguientes pasos.
   - Si el monitor sale vacío: activa **Herramientas > USB CDC On Boot > Enabled**, vuelve a subir el sketch y repite.
   - Si se queda en `Conectando...` para siempre: revisa la contraseña en `secrets.h`.

## Paso 7. Instalar Python

1. Descárgalo de https://www.python.org/downloads/ (versión 3.12 o superior).
2. En el instalador, **marca la casilla "Add python.exe to PATH"** antes de pulsar Install.
3. Abre **PowerShell** y comprueba que funciona con `py --version`. En Windows usa siempre `py` para lanzar los scripts; `python` puede abrir la Microsoft Store en su lugar.

Los scripts de esta fase no necesitan instalar nada más.

## Paso 8. Ser la estación de tierra

En PowerShell, entra en la carpeta del proyecto y lanza los comandos, cambiando la IP por la tuya:

```powershell
cd C:\proyectos\ccsds-sdls-groundlink
py ground\ground_f0.py --sat 192.168.1.50 ping
py ground\ground_f0.py --sat 192.168.1.50 led azul
py ground\ground_f0.py --sat 192.168.1.50 led apagado
```

Deberías ver `PONG` y `ACK LED`, el recuadro central de la pantalla cambia de color y la franja de abajo parpadea en blanco con cada telecomando. En el Monitor Serie aparece cada telecomando recibido.

- Si Windows pregunta por el firewall, permite el acceso en **redes privadas**.
- Si no hay respuesta: comprueba que el PC y el C5 están en la misma Wi-Fi. Algunos routers aíslan a los dispositivos de la red de invitados entre sí.

## Paso 9. Ser el atacante (el "antes")

```powershell
py attacks\attack_f0.py --sat 192.168.1.50 inject
py attacks\attack_f0.py --sat 192.168.1.50 replay --veces 3
```

- `inject`: la pantalla se pone **roja**. Un programa que no es la estación de tierra ha tomado el control de la carga útil.
- `replay`: reenvía un telecomando "capturado" y el satélite lo acepta cada vez.

Mira el Monitor Serie: el satélite no tiene forma de saber quién le habla. Solo ve una IP, que es fácil de falsificar, y en un enlace radio real ni siquiera tendría eso. **Este es el problema que resuelve SDLS en la fase 2.**

## Hito de la fase 0

- [ ] La pantalla cambia de color con `ground_f0.py`
- [ ] `attack_f0.py inject` pone la pantalla en rojo
- [ ] Captura de pantalla o vídeo corto del ataque funcionando (lo usaremos en el README como el "antes")
- [ ] Repo creado en GitHub con estos archivos
