# ADR-008: SDLS con AES-256-GCM y una clave por sentido

- **Estado:** aceptada
- **Fecha:** 2026-11-07

## Contexto

En la fase 1 el enlace habla CCSDS real, pero cualquiera de la red puede inyectar telecomandos, reproducir tramas capturadas, leer la telemetría y desviarla hacia sí mismo. El CRC solo detecta errores de transmisión. Hace falta autenticar el origen, proteger la integridad y la confidencialidad, y que el satélite deje constancia de los intentos.

## Decisión

Proteger las tramas TC y TM con un subconjunto de SDLS (CCSDS 355.0-B) en modo de cifrado autenticado:

| | Trama TC | Trama TM (128 bytes) |
| --- | --- | --- |
| Security Header | SPI (2) + IV (12) tras la cabecera primaria | igual |
| Datos | Space Packet cifrado | 86 bytes cifrados (paquete + relleno) |
| Security Trailer | MAC de 16 bytes | MAC de 16 bytes, antes del OCF |
| AAD (autenticado, en claro) | cabecera TC + SPI + IV | cabecera TM + SPI + IV |

- Algoritmo: **AES-256-GCM**, mbedTLS en el satélite y `cryptography` en tierra.
- **Dos asociaciones de seguridad (SA):** SPI 1 con la clave TC (tierra → satélite) y SPI 2 con la clave TM (satélite → tierra).
- El satélite **no responde nunca** a una trama que no supera SDLS. Envía un evento de seguridad (servicio 5,4) a la estación de tierra autenticada y lo cuenta en el housekeeping.
- La telemetría solo se envía a la dirección del último TC **autenticado**.

## Por qué

- **GCM** da confidencialidad, integridad y autenticación en una sola operación, con una MAC de 128 bits. Es el modo que recomienda la SDLS Cryptographic Algorithms Blue Book (CCSDS 352.0-B) y el ESP32-C5 lo acelera por hardware.
- **Cabecera en el AAD:** sin esto, un atacante podría cambiar el SCID, el canal o el N(S) sin romper la MAC.
- **Una clave por sentido:** tierra y satélite generan sus IV con contadores independientes. Con una sola clave podrían coincidir en un IV, y repetir IV con la misma clave en GCM revela el XOR de los textos en claro y permite falsificar MACs. La separación de claves elimina ese riesgo por diseño.
- **Silencio ante desconocidos:** no dar oráculo al atacante (no sabe si falló la MAC o el replay) y no amplificar tráfico hacia una IP falsificada.

## Alternativas descartadas

- **Solo autenticación (GMAC/CMAC):** cierra la inyección y el replay, pero deja la telemetría y los comandos legibles. Se podrá mostrar como modo configurable más adelante.
- **AES-CBC + HMAC:** dos primitivas y dos claves por sentido para obtener lo mismo que GCM, con más margen para errores de implementación.
- **TLS/DTLS sobre UDP:** protege el transporte, no la trama CCSDS. No existe en un enlace RF real (ver ADR-007).

## Consecuencias

- Cada TC crece 30 bytes y la TM útil baja de 116 a 86 bytes por trama.
- El CLCW (OCF) queda **fuera** de la protección, como en el estándar: un atacante puede alterarlo. Se tratará con FARM-1 en la fase 3.
- Las claves son precompartidas y están en `secrets.h` y `ground/keys_f2.json`, en claro. La flash del ESP32 no está cifrada (no hay flash encryption ni secure boot). Rotación de claves en vuelo: fase 3.
- Los eventos de seguridad no tienen límite de frecuencia: una inundación de tramas falsas genera la misma cantidad de eventos. Se tratará en la fase 3 (escenario de inundación).
