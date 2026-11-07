# ADR-007: UDP sobre Wi-Fi como sustituto del enlace RF

- **Estado:** aceptada
- **Fecha:** 2026-11-07

## Contexto

Un enlace tierra-satélite real usa radio (bandas S, X, UHF) con codificación de canal CCSDS. El proyecto solo dispone de un ESP32-C5 y un PC con Windows, sin radios SDR ni equipo de RF adicional. Hace falta un medio de transporte que conserve las propiedades de seguridad relevantes del enlace radio.

## Decisión

Las tramas CCSDS viajan como datagramas UDP sobre la Wi-Fi doméstica: telecomandos al puerto 10025 del C5, y respuestas y telemetría de vuelta al emisor.

## Por qué

- **Mismo modelo de amenaza:** como en radio, cualquier equipo de la red puede escuchar, inyectar y reproducir tramas. UDP no añade autenticación ni orden garantizado, igual que el canal RF.
- **Sin dependencia del transporte para la seguridad:** toda la protección debe venir de SDLS, no de la red. La contraseña de la Wi-Fi no se considera un control del enlace.
- **Simplicidad:** UDP lo soportan de forma nativa Arduino-ESP32 y Python sin librerías extra.

## Alternativas descartadas

- **USB serie:** es punto a punto y físico, así que no permite demostrar ataques en el enlace.
- **TCP:** añade orden y retransmisión que el enlace RF no tiene, y ocultaría problemas que FARM-1 debe resolver.
- **Punto de acceso propio del C5:** aísla el laboratorio, pero el PC pierde Internet mientras está conectado. Queda como opción si la red doméstica no permite tráfico entre dispositivos.

## Consecuencias

- La IP de origen del datagrama **no** se usa nunca para autorizar un telecomando, porque en radio no existe y en UDP se falsifica fácilmente.
- No se simulan la capa física, la codificación de canal ni las CLTU; se documenta como limitación.
- La Wi-Fi puede perder paquetes: es útil para probar FARM-1 en la fase 3.
