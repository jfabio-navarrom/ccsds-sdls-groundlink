# CCSDS SDLS Ground Link

Asegurando un enlace tierra-satélite de extremo a extremo con CCSDS y SDLS, usando un ESP32-C5 (placa Waveshare ESP32-C5-Touch-LCD-2.8) como satélite simulado.

> **Estado: fase 0 de 4.** El enlace funciona por UDP y todavía **no tiene seguridad, a propósito**: es la línea base vulnerable que la fase 2 protegerá con SDLS (CCSDS 355.0-B).

## Qué hay ahora

| Pieza | Archivo | Qué hace |
| --- | --- | --- |
| Satélite | `satellite/satellite_f0/satellite_f0.ino` | El C5 recibe telecomandos por UDP y pinta su pantalla del color pedido (la "carga útil") |
| Estación de tierra | `ground/ground_f0.py` | Envía `PING` y comandos de color |
| Atacante | `attacks/attack_f0.py` | Inyecta y reproduce telecomandos sin conocer ningún secreto |

Cómo ponerlo en marcha: [GUIA_FASE0.md](GUIA_FASE0.md).

## Hoja de ruta

1. **F0, preparación:** enlace UDP y control de la pantalla. ← aquí
2. **F1, MVP sin seguridad:** tramas TC/TM CCSDS, Space Packets y servicios PUS-lite.
3. **F2, SDLS:** AES-256-GCM, anti-replay y eventos de seguridad en telemetría.
4. **F3, claves y FARM:** rekeying en vuelo, FARM-1 y escenarios de bypass e inundación.
5. **F4, arquitectura:** threat model SPARTA, traza NIST SP 800-53, ADRs y policy-as-code.

## Decisiones de arquitectura

- [ADR-007: UDP sobre Wi-Fi como sustituto del enlace RF](docs/adr/ADR-007-udp-como-enlace-rf.md)

## Ética

Proyecto educativo y defensivo. Los scripts de ataque solo se usan contra el propio C5, en la red propia.
