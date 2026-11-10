# Trazabilidad NIST SP 800-53 Rev. 5

Para cada control: qué se ha implementado, dónde está y qué lo demuestra. Si un control está parcial o falta, se dice.

Las contramedidas de SPARTA (CM0031, CM0030…) se asocian en el propio marco a controles 800-53. Esta tabla parte de esos controles y los aterriza en el código.

| Control | Qué pide | Implementación en el enlace | Dónde | Evidencia | Estado |
| --- | --- | --- | --- | --- | --- |
| **SC-8, SC-8(1)** Transmission Confidentiality and Integrity | Proteger confidencialidad e integridad en tránsito con criptografía | AES-256-GCM en TC (SPI 1) y TM (SPI 2); la cabecera de trama va autenticada | `satellite_f3/sdls.cpp`, `ground/ccsds/sdls.py` | `test_sdls`, `test_interop_f2` (C++ ↔ Python byte a byte); `espiar` y `tamper` en placa | Implementado |
| **SC-13** Cryptographic Protection | Usar criptografía aprobada | AES-256-GCM con MAC de 128 bits (CCSDS 352.0-B), mbedTLS y `cryptography` | `sdls.h` | Vector NIST GCM en `test_sdls`; reglas CRYPTO-001/002/004 del escaneo de políticas | Implementado |
| **SC-12** Cryptographic Key Establishment and Management | Generar, distribuir, almacenar, rotar y destruir claves | Generación con CSPRNG; claves separadas por sentido; OTAR con KEK; anti-rollback; borrado de las copias en RAM | `tools/gen_keys_f3.py`, `handleKeys()` en `satellite_f3.ino`, `KeyStoreF3` | `test_f3` (OTAR, interop), `test_e2e_f3` (rotación); placa: rotación que sobrevive a RST | Parcial: almacenamiento sin HSM (R2) y KEK no rotable (R5) |
| **SC-23** Session Authenticity | Proteger la autenticidad de la sesión: replay, secuestro | IV como contador anti-replay persistente; la TM solo va a la tierra autenticada | `processTc()`, NVS `tciv` | `attack_f2 replay` en placa (también tras RST); `test_e2e_f2` | Implementado, con desviación aceptada R1 |
| **IA-3** Device Identification and Authentication | Autenticar los dispositivos antes de conectar | La estación de tierra se autentica con la clave TC; la IP no cuenta | `handleTc()` | `inject`, `forge`, `filtrada` (tras rotar) en placa | Implementado (clave simétrica) |
| **SI-10** Information Input Validation | Validar todas las entradas | Longitudes, versión, CRC, SCID y VCID; Space Packet con longitud exacta; servicio y datos de aplicación | `ccsds.cpp`, `executePacket()` | `test_frames`, `test_interop` | Implementado |
| **AU-2, AU-3** Event Logging; Content of Audit Records | Registrar los eventos relevantes con qué, cuándo, dónde y origen | Evento de seguridad (5,4) con motivo, N(S), IP y puerto de origen, e IV; contadores en el HK | `sendSecurityEvent()` | `test_e2e_f2`, `test_e2e_f3`; consola de tierra en placa | Implementado (sin marca de tiempo a bordo) |
| **AU-6** Audit Record Review | Revisar los registros | La consola muestra `[SEGURIDAD]` en tiempo real; `estado` resume los contadores | `gs_f3.py` | Placa | Parcial: no se guardan en disco |
| **SI-4** System Monitoring | Monitorizar ataques e indicadores | Contadores por tipo de rechazo, descartes del FARM y eventos resumidos en el HK | `sendHk()` | `test_sdls` (HK) | Implementado |
| **SC-5** Denial-of-Service Protection | Limitar el efecto de la denegación de servicio | Cubo de fichas para eventos; ventana anti-replay solo tras la MAC; SDLS antes del FARM | `refillEventTokens()`, ADR-011 | `flood` y `forge` en placa; `test_e2e_f3` | Parcial: el canal no se protege (R4) |
| **SC-28** Protection of Information at Rest | Proteger la información almacenada | Ninguno: claves en claro en JSON y NVS | — | — | **No implementado** (R2) |
| **SI-7** Software, Firmware, and Information Integrity | Detectar cambios no autorizados en el firmware | Ninguno: sin secure boot | — | — | **No implementado** (R6) |
| **CM-6** Configuration Settings | Fijar y vigilar la configuración de seguridad | La base de datos de SA es código y se escanea con las políticas de `ccsds-policy-as-code` | `docs/arquitectura/groundlink.sdls.yaml`, `tools/check_policy.py` | Job `politicas` del CI; `test_sa_database` | Implementado |
| **CA-7** Continuous Monitoring | Evaluar los controles de forma continua | En cada push: tests, interoperabilidad y escaneo de políticas con registro de riesgos | `.github/workflows/ci.yml` | Ejecuciones del CI en GitHub Actions | Implementado |
| **SA-11** Developer Testing and Evaluation | Pruebas del desarrollador sobre los controles | Tests unitarios, de interoperabilidad entre dos implementaciones independientes y de extremo a extremo con los ataques | `tests/` | CI | Implementado |
| **RA-3** Risk Assessment | Evaluar y documentar el riesgo | Threat model con SPARTA, riesgos residuales y aceptaciones con fecha de revisión | [THREAT_MODEL.md](THREAT_MODEL.md), [riesgos-aceptados.yaml](riesgos-aceptados.yaml) | El CI falla si una aceptación vence | Implementado |

**Resumen:** 11 controles implementados, 3 parciales y 2 no implementados. Todos los huecos tienen un riesgo residual con nombre y una remediación propuesta.
