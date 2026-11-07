# CCSDS SDLS Ground Link

Asegurando un enlace tierra-satélite de extremo a extremo con CCSDS y SDLS, usando un ESP32-C5 (placa Waveshare ESP32-C5-Touch-LCD-2.8) como satélite simulado.

[![CI](https://github.com/jfabio-navarrom/ccsds-sdls-groundlink/actions/workflows/ci.yml/badge.svg)](https://github.com/jfabio-navarrom/ccsds-sdls-groundlink/actions/workflows/ci.yml)

> **Estado: fase 1 de 4.** El enlace ya habla CCSDS de verdad (tramas TC y TM, Space Packets, servicios PUS-lite y telemetría de housekeeping), pero todavía **no tiene seguridad, a propósito**: es la línea base vulnerable que la fase 2 protegerá con SDLS (CCSDS 355.0-B).

## El "antes": sin SDLS, cualquiera manda

![Demo fase 0: la estación de tierra pone la carga útil en verde y un atacante sin claves la pone en rojo](docs/media/demo-f0-antes.gif)

La estación de tierra pone la carga útil (la pantalla) en verde. Después, un script atacante que no conoce ningún secreto inyecta un telecomando y el satélite lo acepta: la pantalla pasa a rojo. En la fase 2, este mismo ataque debe ser rechazado y quedar registrado en la telemetría.

## Qué hay ahora (fase 1)

| Pieza | Archivo | Qué hace |
| --- | --- | --- |
| Satélite | `satellite/satellite_f1/` | Firmware del C5: valida tramas TC (CCSDS 232.0-B, CRC-16), ejecuta servicios PUS-lite y responde con tramas TM de 128 bytes (CCSDS 132.0-B) con CLCW. Envía housekeeping cada 5 s |
| Estación de tierra | `ground/gs_f1.py` | Consola interactiva: `ping`, `color`, `hk`, `estado` |
| Librería CCSDS | `ground/ccsds/` | Tramas TC/TM, Space Packets (CCSDS 133.0-B) y servicios en Python |
| Atacante | `attacks/attack_f1.py` | `inject`, `replay` y `corrupt`: muestra que el CRC no es autenticación |
| Simulador | `tools/fake_satellite_f1.py` | Satélite en Python para probar sin la placa |
| Tests | `tests/` | Vectores CCSDS e interoperabilidad C++ ↔ Python, en CI con GitHub Actions |

Cómo ponerlo en marcha: [GUIA_FASE1.md](GUIA_FASE1.md). La fase 0 (texto plano por UDP) sigue en `satellite/satellite_f0/` y [GUIA_FASE0.md](GUIA_FASE0.md).

### Lo que demuestra la fase 1

| Ataque | Resultado sin SDLS | Por qué |
| --- | --- | --- |
| Inyección de TC | Aceptado | El CRC lo calcula cualquiera y el SCID es público |
| Replay de una trama capturada | Aceptado | No hay contador anti-replay autenticado |
| Trama con un bit cambiado | Rechazada | El CRC detecta errores, no atacantes |
| Secuestro de telemetría | El HK va al atacante | El satélite responde a quien mandó el último TC válido |

## Hoja de ruta

1. **F0, preparación:** enlace UDP y control de la pantalla.
2. **F1, MVP sin seguridad:** tramas TC/TM CCSDS, Space Packets y servicios PUS-lite. ← aquí
3. **F2, SDLS:** AES-256-GCM, anti-replay y eventos de seguridad en telemetría.
4. **F3, claves y FARM:** rekeying en vuelo, FARM-1 y escenarios de bypass e inundación.
5. **F4, arquitectura:** threat model SPARTA, traza NIST SP 800-53, ADRs y policy-as-code.

## Decisiones de arquitectura

- [ADR-007: UDP sobre Wi-Fi como sustituto del enlace RF](docs/adr/ADR-007-udp-como-enlace-rf.md)

## Ética

Proyecto educativo y defensivo. Los scripts de ataque solo se usan contra el propio C5, en la red propia.
